import os
import json
import boto3
import jwt
from decimal import Decimal
from botocore.exceptions import ClientError

# ---------------------------------------------------
# GLOBALS
# ---------------------------------------------------
secrets_client = boto3.client("secretsmanager")
sts_client = boto3.client("sts")

JWT_SECRET_CACHE = None


# ---------------------------------------------------
# CORS
# ---------------------------------------------------
def get_cors_headers():
    origin = 'http://localhost:3000'
    return {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
        "Access-Control-Allow-Methods": "GET,OPTIONS",
        "Access-Control-Allow-Credentials": "true"
    }


# ---------------------------------------------------
# GET JWT SECRET (CACHED)
# ---------------------------------------------------
def get_jwt_secret():
    global JWT_SECRET_CACHE

    if JWT_SECRET_CACHE:
        return JWT_SECRET_CACHE

    secret_name = os.environ["JWT_SECRET_NAME"]

    response = secrets_client.get_secret_value(
        SecretId=secret_name
    )

    secret_data = json.loads(response["SecretString"])

    JWT_SECRET_CACHE = secret_data["jwt_secret"]

    return JWT_SECRET_CACHE


# ---------------------------------------------------
# VERIFY ADMIN TOKEN
# ---------------------------------------------------
def verify_admin_token(event):

    headers = event.get("headers", {})
    auth_header = headers.get("Authorization") or headers.get("authorization")

    if not auth_header or not auth_header.startswith("Bearer "):
        return None, "Missing or invalid Authorization header"

    token = auth_header.split(" ")[1]

    try:
        jwt_secret = get_jwt_secret()

        decoded = jwt.decode(
            token,
            jwt_secret,
            algorithms=["HS256"]
        )

        if decoded.get("user_type") != "admin":
            return None, "Unauthorized user"

        return decoded, None

    except jwt.ExpiredSignatureError:
        return None, "Token expired"

    except jwt.InvalidTokenError:
        return None, "Invalid token"


# ---------------------------------------------------
# ASSUME CROSS ACCOUNT ROLE
# ---------------------------------------------------
def get_cross_account_table():
    # Get Role ARN from environment variable.
    # This is the IAM role in another AWS account that we want to assume
    # in order to access its DynamoDB table.
    role_arn = os.environ["ASSISTANT_DYNAMO_ROLE_ARN"]
    table_name = os.environ["ASSISTANTS_TABLE"]

    # Create an STS (Security Token Service) client.
    # STS is used to assume roles and get temporary credentials.
    sts = boto3.client("sts")

    # Assume the IAM role in the target account.
    # This returns temporary security credentials that allow us
    # to access resources in that other AWS account.
    response = sts.assume_role(
        RoleArn=role_arn,  # IAM Role to assume (target account role)
        RoleSessionName="AdminCreateAssistantSession"    # A name for this temporary session
    )

    # Extract temporary credentials returned by STS
    credentials = response["Credentials"]
    # Create a DynamoDB resource using the temporary credentials.
    # These credentials now have the permissions of the assumed role.
    dynamodb = boto3.resource(
        "dynamodb",
        aws_access_key_id=credentials["AccessKeyId"],  # Temporary Access Key
        aws_secret_access_key=credentials["SecretAccessKey"],   # Temporary Secret Key
        aws_session_token=credentials["SessionToken"], # Temporary Session Token
    )
    
    # Return the DynamoDB table object from the target account.
    # Now we can perform operations like put_item, get_item, query, scan, etc.
    return dynamodb.Table(table_name)


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
        # ADMIN AUTHENTICATION
        # -----------------------------------------
        admin_data, error = verify_admin_token(event)

        if error:
            return {
                "statusCode": 401,
                "headers": cors,
                "body": json.dumps({"message": error})
            }

        admin_id = admin_data["adminId"]

        # -----------------------------------------
        # GET CROSS ACCOUNT TABLE
        # -----------------------------------------
        assistants_table = get_cross_account_table()

        assistants = []

        # ------------------------
        # SCAN TABLE (ALL ITEMS, NO LIMIT)
        # ------------------------
        scan_response = assistants_table.scan() 
        assistants.extend(scan_response.get("Items", []))

        while "LastEvaluatedKey" in scan_response:
            scan_response = assistants_table.scan(
                ExclusiveStartKey=scan_response["LastEvaluatedKey"]
            )
            assistants.extend(scan_response.get("Items", []))

        final_response = format_assistants(assistants)

        return {
            "statusCode": 200,
            "headers": cors,
            "body": json.dumps({
                "message": "Assistants fetched successfully",
                "count": len(final_response),
                "assistants": convert_decimal(final_response)
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


# ---------------------------------------------------
# FORMAT ASSISTANTS
# ---------------------------------------------------
def format_assistants(assistants):

    response = []

    for assistant in assistants:

        response.append({
            "assistantId": assistant["assistantId"],
            "first_name": assistant["first_name"],
            "last_name": assistant["last_name"],
            "email": assistant["email"],
            "assigned_candidates": assistant.get("assigned_candidates", []),
            "last_login": assistant.get("last_login"),
            "createdAt": assistant.get("createdAt"),
            "updatedAt": assistant.get("updatedAt")
        })
    return response


# ---------------------------------------------------
# DECIMAL CONVERTER
# ---------------------------------------------------
def convert_decimal(obj):

    if isinstance(obj, list):
        return [convert_decimal(i) for i in obj]

    elif isinstance(obj, dict):
        return {k: convert_decimal(v) for k, v in obj.items()}

    elif isinstance(obj, Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)

    return obj