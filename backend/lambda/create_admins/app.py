import os
import json
import uuid
import boto3
import bcrypt
import re
from datetime import datetime
from jsonschema import Draft7Validator, FormatChecker
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError



dynamodb = boto3.resource("dynamodb")

ADMINS_TABLE = os.environ.get("ADMINS_TABLE")
admins_table = dynamodb.Table(ADMINS_TABLE)

# ---------------------------------------------------
# CORS
# ---------------------------------------------------
def get_cors_headers():
    origin = 'http://localhost:3000'
    return {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
        "Access-Control-Allow-Methods": "POST,OPTIONS",
        "Access-Control-Allow-Credentials": "true"
    }

# ---------------------------------------------------
# JSON Schema
# ---------------------------------------------------
admins_schema = {
    "type": "object",
    "required": ["first_name", "last_name", "email", "password"],
    "properties": {
        "first_name": {"type": "string"},
        "last_name": {"type": "string"},
        "email": {"type": "string", "format": "email"},
        "password": {"type": "string"}
    }
}

# ---------------------------------------------------
# Validate JSON
# ---------------------------------------------------
def validate_json(body):

    validator = Draft7Validator(
        admins_schema,
        format_checker=FormatChecker()
    )

    errors = [
        f"{'/'.join([str(x) for x in e.path]) or 'root'}: {e.message}"
        for e in validator.iter_errors(body)
    ]

    # Empty field check
    errors += check_empty_fields(body)

    if errors:
        return False, errors

    return True, None


def check_empty_fields(obj, path=""):
    errors = []

    if isinstance(obj, dict):
        for k, v in obj.items():
            sub_path = f"{path}/{k}" if path else k
            errors += check_empty_fields(v, sub_path)

    elif isinstance(obj, list):
        if not obj:
            errors.append(f"{path} cannot be empty")
        else:
            for i, item in enumerate(obj):
                sub_path = f"{path}[{i}]"
                errors += check_empty_fields(item, sub_path)

    else:
        if obj is None or (isinstance(obj, str) and not obj.strip()):
            errors.append(f"{path} cannot be empty")

    return errors

# ---------------------------------------------------
# Validate Password Strength
# ---------------------------------------------------
def validate_password_strength(password):
    """
    Validate password meets security requirements:
    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    - At least one special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>)"
    
    return True, None

# ---------------------------------------------------
# Build Admin Item
# ---------------------------------------------------
def build_admin_item(body):
    now = datetime.utcnow().isoformat() + "Z"

    hashed_password = bcrypt.hashpw(
        body["password"].encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    return {
        "adminId": str(uuid.uuid4()),
        "first_name": body["first_name"].strip(),
        "last_name": body["last_name"].strip(),
        "email": body["email"].lower().strip(),
        "password_hash": hashed_password,
        "last_login": None,
        "createdAt": now,
        "updatedAt": now
    }

# ---------------------------------------------------
# Lambda Handler
# ---------------------------------------------------
def handler(event, context):
    cors = get_cors_headers()

    # Preflight
    if event.get("httpMethod") == "OPTIONS":
        return {
            "statusCode": 200,
            "headers": cors,
            "body": json.dumps({"message": "Preflight OK"})
        }

    try:
        # -----------------------------------------
        # Parse Body
        # -----------------------------------------
        if not event.get("body"):
            return {
                "statusCode": 400,
                "headers": cors,
                "body": json.dumps({"message": "Request body required"})
            }

        try:
            body = json.loads(event["body"])
        except json.JSONDecodeError:
            return {
                "statusCode": 400,
                "headers": cors,
                "body": json.dumps({"message": "Invalid JSON"})
            }
        
        # -----------------------------------------
        # PASSWORD UPDATE USING assistantId
        # -----------------------------------------
        amdin_id = body.get("adminId")
        new_password = body.get("new_password")

        if amdin_id:
            if not new_password:
                return {
                    "statusCode": 400,
                    "headers": cors,
                    "body": json.dumps({"message": "new_password is required"})
                }

            # Validate password strength
            is_valid_password, password_error = validate_password_strength(new_password)
            if not is_valid_password:
                return {
                    "statusCode": 400,
                    "headers": cors,
                    "body": json.dumps({"message": password_error})
                }

            admins_table = get_cross_account_table()

            # Check assistant exists
            response = admins_table.get_item(
                Key={"assistantId": assistant_id}
            )

            if "Item" not in response:
                return {
                    "statusCode": 404,
                    "headers": cors,
                    "body": json.dumps({"message": "Assistant not found"})
                }

            # Hash new password
            new_hash = bcrypt.hashpw(
                new_password.encode("utf-8"),
                bcrypt.gensalt()
            ).decode("utf-8")

            # Update password
            admins_table.update_item(
                Key={"assistantId": assistant_id},
                UpdateExpression="SET password_hash = :p, updatedAt = :u",
                ExpressionAttributeValues={
                    ":p": new_hash,
                    ":u": datetime.utcnow().isoformat() + "Z"
                }
            )

            return {
                "statusCode": 200,
                "headers": cors,
                "body": json.dumps({
                    "message": "Password updated successfully"
                })
            }


        # -----------------------------------------
        # Validate Schema
        # -----------------------------------------
        is_valid, errors = validate_json(body)
        if not is_valid:
            return {
                "statusCode": 400,
                "headers": cors,
                "body": json.dumps({"errors": errors})
            }

        # -----------------------------------------
        # Validate Password Strength
        # -----------------------------------------
        is_valid_password, password_error = validate_password_strength(body["password"])
        if not is_valid_password:
            return {
                "statusCode": 400,
                "headers": cors,
                "body": json.dumps({"message": password_error})
            }

        # -----------------------------------------
        # Get Cross Account Table
        # -----------------------------------------

        email = body["email"].lower().strip()

        # -----------------------------------------
        # Check Email Uniqueness (GSI)
        # -----------------------------------------
        existing = admins_table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq(email)
        )

        if existing.get("Items"):
            return {
                "statusCode": 400,
                "headers": cors,
                "body": json.dumps({"message": "Admins with this email already exists"})
            }

        # -----------------------------------------
        # Create Admin
        # -----------------------------------------
        admin_item = build_admin_item(body)

        admins_table.put_item(
            Item=admin_item
        )

        return {
            "statusCode": 201,
            "headers": cors,
            "body": json.dumps({
                "message": "Admin created successfully",
                "adminId": admin_item["adminId"]
            })
        }

    except ClientError as e:
        return {
            "statusCode": 500,
            "headers": cors,
            "body": json.dumps({
                "message": "AWS error",
                "error": str(e)
            })
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "headers": cors,
            "body": json.dumps({
                "message": "Internal server error",
                "error": str(e)
            })
        }




# {
#   "httpMethod": "POST",
#   "body": "{\n  \"first_name\": \"Surekha\",\n  \"last_name\": \"S\",\n  \"email\": \"surekha@gmail.com\",\n  \"password\": \"Surekha@22\"\n}"
# }