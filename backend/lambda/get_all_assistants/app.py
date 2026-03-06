import os
import json
import uuid
import boto3
import bcrypt
import re
from datetime import datetime
from decimal import Decimal
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
# Assume Cross Account Role
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
        # Get Cross Account Table
        # -----------------------------------------
        assistants_table = get_cross_account_table()

        assistants = []

        scan_response = assistants_table.scan(
            Limit=200
        )

        assistants.extend(scan_response.get("Items", []))

        # Pagination handle
        while "LastEvaluatedKey" in scan_response:
            scan_response = assistants_table.scan(
                ExclusiveStartKey=scan_response["LastEvaluatedKey"],
                Limit=100
            )
            assistants.extend(scan_response.get("Items", []))

        final_response = get_all_assistansts(assistants)
        return {
            "statusCode": 200,
            "headers": cors,
            "body": json.dumps({
                "message": "Assistants fetched successfully",
                "count": len(assistants),
                "assistants": convert(final_response)
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


def get_all_assistansts(assistants):
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


def convert(obj):
        if isinstance(obj, list):
            return [convert(i) for i in obj]
        elif isinstance(obj, dict):
            return {k: convert(v) for k, v in obj.items()}
        elif isinstance(obj, Decimal):
            return int(obj) if obj % 1 == 0 else float(obj)
        return obj
