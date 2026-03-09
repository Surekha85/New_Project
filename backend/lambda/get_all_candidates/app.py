import os
import json
import boto3
from decimal import Decimal
from datetime import datetime, timezone
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
def get_cross_account_table(role_env, table_env):

    role_arn = os.environ[role_env]
    table_name = os.environ[table_env]

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
# Get Active Subscriber Candidate IDs
# ---------------------------------------------------
def get_active_candidate_ids(payments_table):

    now = datetime.now(timezone.utc)

    candidate_ids = []

    response = payments_table.scan()

    while True:

        items = response.get("Items", [])

        for item in items:

            subscription = item.get("subscription", {})

            status = subscription.get("status")
            end_date = subscription.get("subscription_period_end")

            if status == "active" and end_date:

                end_datetime = datetime.strptime(
                    end_date,
                    "%Y-%m-%dT%H:%M:%SZ"
                ).replace(tzinfo=timezone.utc)

                if end_datetime >= now:

                    candidate_id = item.get("jaa_candidate_id")

                    if candidate_id:
                        candidate_ids.append(candidate_id)

        if "LastEvaluatedKey" not in response:
            break

        response = payments_table.scan(
            ExclusiveStartKey=response["LastEvaluatedKey"]
        )

    return candidate_ids


# ---------------------------------------------------
# Lambda Handler
# ---------------------------------------------------
def handler(event, context):

    cors = get_cors_headers()

    if event.get("httpMethod") == "OPTIONS":
        return {
            "statusCode": 200,
            "headers": cors,
            "body": json.dumps({"message": "Preflight OK"})
        }

    try:

        # -----------------------------------------
        # Admin Authentication
        # -----------------------------------------
        admin_id = event.get("requestContext", {}).get(
            "authorizer", {}).get("principalId")

        if not admin_id:
            return {
                "statusCode": 401,
                "headers": cors,
                "body": json.dumps({"message": "Unauthorized"})
            }

        # -----------------------------------------
        # Tables
        # -----------------------------------------
        payments_table = get_cross_account_table(
            "CANDIDATE_DYNAMO_ROLE_ARN",
            "PAYMENTS_TABLE"
        )

        candidate_table = get_cross_account_table(
            "CANDIDATE_DYNAMO_ROLE_ARN",
            "CANDIDATES_TABLE"
        )

        # -----------------------------------------
        # Get Active Subscriber Candidate IDs
        # -----------------------------------------
        active_candidate_ids = get_active_candidate_ids(payments_table)

        if not active_candidate_ids:
            return {
                "statusCode": 200,
                "headers": cors,
                "body": json.dumps({
                    "message": "No active subscribers found",
                    "candidates": []
                })
            }

        # -----------------------------------------
        # Fetch Candidates
        # -----------------------------------------
        candidates = []

        for cid in active_candidate_ids:

            response = candidate_table.get_item(
                Key={"jaa_candidate_id": cid}
            )

            item = response.get("Item")

            if item:
                candidates.append(item)

        final_response = get_all_candidates(candidates)

        return {
            "statusCode": 200,
            "headers": cors,
            "body": json.dumps({
                "message": "Fetch Candidates successfully",
                "candidates": json.dumps(convert(final_response))
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
# Format Candidate Response
# ---------------------------------------------------
def get_all_candidates(candidates):
    response = []
    for item in candidates:
        candidate = {
            "jaa_candidate_id": item.get("jaa_candidate_id"),
            "user_id": item.get("user_id"),
            "first_name": item.get("first_name"),
            "last_name": item.get("last_name"),
            "email": item.get("email"),
            "phone": item.get("phone"),
            "github": item.get("github"),
            "linkedin": item.get("linkedin"),
            "resumeUrl": item.get("resumeUrl"),
            "assistantAssignedTo": item.get("assistantAssignedTo"),
            "address": {
                "street": item.get("address", {}).get("street"),
                "city": item.get("address", {}).get("city"),
                "state": item.get("address", {}).get("state"),
                "country": item.get("address", {}).get("country"),
                "zip": item.get("address", {}).get("zip")
            },
            "careerDetails": {
                "highestEducation": item.get("careerDetails", {}).get("highestEducation"),
                "yearsExperience": item.get("careerDetails", {}).get("yearsExperience"),
                "skills": item.get("careerDetails", {}).get("skills"),
                "preferredJobType": item.get("careerDetails", {}).get("preferredJobType"),
                "dateAvailable": item.get("careerDetails", {}).get("dateAvailable"),
                "workAuthorized": item.get("careerDetails", {}).get("workAuthorized"),
                "visaRequired": item.get("careerDetails", {}).get("visaRequired"),
                "validDriverLicense": item.get("careerDetails", {}).get("validDriverLicense"),
                "willingToRelocate": item.get("careerDetails", {}).get("willingToRelocate"),
                "vaccinationStatus": item.get("careerDetails", {}).get("vaccinationStatus")
            },
            "jobPreferences": {
                "preferredJobTitles": item.get("jobPreferences", {}).get("preferredJobTitles"),
                "preferredJobType": item.get("jobPreferences", {}).get("preferredJobType"),
                "blockedCompanies": item.get("jobPreferences", {}).get("blockedCompanies"),
                "salaryExpectation": item.get("jobPreferences", {}).get("salaryExpectation"),
                "timeZone": item.get("jobPreferences", {}).get("timeZone")
            },
            "demographic": {
                "gender": item.get("demographic", {}).get("gender"),
                "pronouns": item.get("demographic", {}).get("pronouns"),
                "ethnicIdentity": item.get("demographic", {}).get("ethnicIdentity"),
                "sexualOrientation": item.get("demographic", {}).get("sexualOrientation"),
                "veteranStatus": item.get("demographic", {}).get("veteranStatus"),
                "disabilityStatus": item.get("demographic", {}).get("disabilityStatus")
            },
            "dedicatedGmailAccount": {
                "email": item.get("dedicatedGmailAccount", {}).get("email"),
                "password": item.get("dedicatedGmailAccount", {}).get("password")
            },
            "createdAt": item.get("createdAt"),
            "updatedAt": item.get("updatedAt")
        }
        response.append(candidate)
    return response


# ---------------------------------------------------
# Decimal Convert
# ---------------------------------------------------
def convert(obj):

    if isinstance(obj, list):
        return [convert(i) for i in obj]

    elif isinstance(obj, dict):
        return {k: convert(v) for k, v in obj.items()}

    elif isinstance(obj, Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)

    return obj








# {
#   "httpMethod": "POST",
#   "requestContext": {
#     "authorizer": {
#       "principalId": "admin_001"
#     }
#   }
# }