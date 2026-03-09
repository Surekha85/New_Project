import os
import json
import boto3
import jwt
from decimal import Decimal
from datetime import datetime, timezone
from botocore.exceptions import ClientError

# ---------------------------------------------------
# GLOBALS
# ---------------------------------------------------
secrets_client = boto3.client("secretsmanager")
JWT_SECRET_CACHE = None


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

    if not auth_header:
        return None, "Authorization header missing"

    parts = auth_header.split()

    if len(parts) != 2 or parts[0] != "Bearer":
        return None, "Invalid Authorization format"

    token = parts[1]

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
# Assume Cross Account Role
# ---------------------------------------------------
def get_cross_account_table(role_env, table_env):

    role_arn = os.environ[role_env]
    table_name = os.environ[table_env]

    sts = boto3.client("sts")

    response = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName="AdminGetCandidatesSession"
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
# GET ACTIVE CANDIDATE IDS (SCAN)
# ---------------------------------------------------
def get_active_candidate_ids(payments_table):

    now = datetime.now(timezone.utc)

    candidate_ids = []

    response = payments_table.scan(
        ProjectionExpression="jaa_candidate_id, subscription"
    )

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

                    cid = item.get("jaa_candidate_id")

                    if cid:
                        candidate_ids.append(cid)

        if "LastEvaluatedKey" not in response:
            break

        response = payments_table.scan(
            ProjectionExpression="jaa_candidate_id, subscription",
            ExclusiveStartKey=response["LastEvaluatedKey"]
        )

    return candidate_ids


# ---------------------------------------------------
# BATCH GET CANDIDATES
# ---------------------------------------------------
def batch_get_candidates(candidate_table, candidate_ids):

    dynamodb = boto3.client("dynamodb")

    table_name = candidate_table.name

    candidates = []

    for i in range(0, len(candidate_ids), 100):

        chunk = candidate_ids[i:i+100]

        keys = [
            {"jaa_candidate_id": {"S": cid}}
            for cid in chunk
        ]

        response = dynamodb.batch_get_item(
            RequestItems={
                table_name: {
                    "Keys": keys
                }
            }
        )

        items = response["Responses"].get(table_name, [])

        for item in items:

            normal_item = {}

            for k, v in item.items():
                normal_item[k] = list(v.values())[0]

            candidates.append(normal_item)

    return candidates


# ---------------------------------------------------
# LAMBDA HANDLER
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

        # -------------------------
        # VERIFY ADMIN TOKEN
        # -------------------------
        admin_data, error = verify_admin_token(event)

        if error:
            return {
                "statusCode": 401,
                "headers": cors,
                "body": json.dumps({"message": error})
            }

        # -------------------------
        # TABLES
        # -------------------------
        payments_table = get_cross_account_table(
            "CANDIDATE_DYNAMO_ROLE_ARN",
            "PAYMENTS_TABLE"
        )

        candidate_table = get_cross_account_table(
            "CANDIDATE_DYNAMO_ROLE_ARN",
            "CANDIDATES_TABLE"
        )

        # -------------------------
        # GET ACTIVE CANDIDATES
        # -------------------------
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

        # -------------------------
        # FETCH CANDIDATES
        # -------------------------
        candidates = batch_get_candidates(
            candidate_table,
            active_candidate_ids
        )

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
# FORMAT RESPONSE
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