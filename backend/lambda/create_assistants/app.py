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

# ---------------------------------------------------
# CORS
# ---------------------------------------------------
def get_cors_headers():
    origin = "https://www.admin.jobsyme.com"
    return {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
        "Access-Control-Allow-Methods": "POST,OPTIONS",
        "Access-Control-Allow-Credentials": "true"
    }

# ---------------------------------------------------
# JSON Schema
# ---------------------------------------------------
assistant_schema = {
    "type": "object",
    "required": ["first_name", "last_name", "email", "password"],
    "properties": {
        "first_name": {"type": "string"},
        "last_name": {"type": "string"},
        "email": {"type": "string", "format": "email"},
        "password": {"type": "string"},
        "assgined_candidates": {
            "type": "array",
            "items": {"type": "string"}
        }
    }
}

# ---------------------------------------------------
# Validate JSON
# ---------------------------------------------------
def validate_json(body):
    validator = Draft7Validator(assistant_schema, format_checker=FormatChecker())
    errors = [
        f"{'/'.join([str(x) for x in e.path]) or 'root'}: {e.message}"
        for e in validator.iter_errors(body)
    ]
    if errors:
        return False, errors
    return True, None

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
# Assume Cross Account Role
# ---------------------------------------------------
def get_cross_account_table():
    role_arn = os.environ["ASSISTANT_DYNAMO_ROLE_ARN"]
    table_name = os.environ["ASSISTANTS_TABLE"]

    sts = boto3.client("sts")

    response = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName="AdminCreateAssistantSession"
    )

    credentials = response["Credentials"]

    dynamodb = boto3.resource(
        "dynamodb",
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )

    return dynamodb.Table(table_name)

# ---------------------------------------------------
# Build Assistant Item
# ---------------------------------------------------
def build_assistant_item(body):
    now = datetime.utcnow().isoformat() + "Z"

    hashed_password = bcrypt.hashpw(
        body["password"].encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    return {
        "assistantId": str(uuid.uuid4()),
        "first_name": body["first_name"].strip(),
        "last_name": body["last_name"].strip(),
        "email": body["email"].lower().strip(),
        "password_hash": hashed_password,
        "assigned_candidates": [],
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
        # Admin Authentication (Authorizer)
        # -----------------------------------------
        admin_id = event.get("requestContext", {}).get("authorizer", {}).get("principalId")

        if not admin_id:
            return {
                "statusCode": 401,
                "headers": cors,
                "body": json.dumps({"message": "Unauthorized"})
            }

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
        assistants_table = get_cross_account_table()

        email = body["email"].lower().strip()

        # -----------------------------------------
        # Check Email Uniqueness (GSI)
        # -----------------------------------------
        existing = assistants_table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq(email)
        )

        if existing.get("Items"):
            return {
                "statusCode": 400,
                "headers": cors,
                "body": json.dumps({"message": "Assistant with this email already exists"})
            }

        # -----------------------------------------
        # Create Assistant
        # -----------------------------------------
        assistant_item = build_assistant_item(body)

        assistants_table.put_item(
            Item=assistant_item
        )

        return {
            "statusCode": 201,
            "headers": cors,
            "body": json.dumps({
                "message": "Assistant created successfully",
                "assistantId": assistant_item["assistantId"]
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