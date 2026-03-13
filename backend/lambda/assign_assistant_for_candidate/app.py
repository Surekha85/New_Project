import os
import json
import boto3
import jwt
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError

# ---------------------------------------------------
# GLOBAL CLIENTS
# ---------------------------------------------------
secrets_client = boto3.client("secretsmanager")
sts_client = boto3.client("sts")
dynamodb = boto3.resource("dynamodb")

JWT_SECRET_CACHE = None
ASSUME_ROLE_CACHE = None
ASSUME_ROLE_EXPIRY = None


# ---------------------------------------------------
# CORS
# ---------------------------------------------------
def get_cors_headers():
    origin = "https://www.admin.jobsyme.com"
    return {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
        "Access-Control-Allow-Methods": "POST,GET,OPTIONS",
        "Access-Control-Allow-Credentials": "true"
    }


# ---------------------------------------------------
# GET JWT SECRET
# ---------------------------------------------------
def get_jwt_secret():

    global JWT_SECRET_CACHE

    if JWT_SECRET_CACHE:
        return JWT_SECRET_CACHE

    secret_name = os.environ["JWT_SECRET_NAME"]

    response = secrets_client.get_secret_value(
        SecretId=secret_name
    )

    secret = json.loads(response["SecretString"])

    JWT_SECRET_CACHE = secret["jwt_secret"]

    return JWT_SECRET_CACHE


# ---------------------------------------------------
# VERIFY ADMIN TOKEN
# ---------------------------------------------------
def verify_admin_token(event):

    headers = event.get("headers", {})
    auth_header = headers.get("Authorization") or headers.get("authorization")

    if not auth_header or not auth_header.startswith("Bearer "):
        return None, "Missing Authorization header"

    token = auth_header.split(" ")[1]

    try:

        decoded = jwt.decode(
            token,
            get_jwt_secret(),
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
def assume_role(role_arn):

    global ASSUME_ROLE_CACHE
    global ASSUME_ROLE_EXPIRY

    credentials = None

    if ASSUME_ROLE_CACHE and ASSUME_ROLE_EXPIRY:

        now = datetime.now(timezone.utc)

        if now < (ASSUME_ROLE_EXPIRY - timedelta(minutes=2)):
            credentials = ASSUME_ROLE_CACHE

    if not credentials:

        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="AdminAssignAssistantSession"
        )

        credentials = response["Credentials"]

        ASSUME_ROLE_CACHE = credentials
        ASSUME_ROLE_EXPIRY = credentials["Expiration"]

    dynamodb_cross = boto3.resource(
        "dynamodb",
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"]
    )

    return dynamodb_cross


# ---------------------------------------------------
# ASSIGN CANDIDATE
# ---------------------------------------------------
def assign_candidate_to_assistant(assistant_id, candidate_id):

    # assume roles
    assistant_db = assume_role(os.environ["ASSISTANT_DYNAMO_ROLE_ARN"])
    candidate_db = assume_role(os.environ["CANDIDATE_DYNAMO_ROLE_ARN"])

    assistants_table = assistant_db.Table(os.environ["ASSISTANTS_TABLE"])
    candidates_table = candidate_db.Table(os.environ["CANDIDATES_TABLE"])

    # ------------------------------------------------
    # GET CANDIDATE
    # ------------------------------------------------
    candidate_response = candidates_table.get_item(
        Key={"candidateId": candidate_id}
    )

    if "Item" not in candidate_response:
        return {"message": "Candidate not found"}

    candidate_item = candidate_response["Item"]

    # check already assigned
    if candidate_item.get("assistantAssignedTo"):
        return {"message": "Candidate already assigned to an assistant"}

    # ------------------------------------------------
    # GET ASSISTANT
    # ------------------------------------------------
    assistant_response = assistants_table.get_item(
        Key={"assistant_id": assistant_id}
    )

    if "Item" not in assistant_response:
        return {"message": "Assistant not found"}

    assistant_item = assistant_response["Item"]

    assigned_list = assistant_item.get("assigned_candidates", [])

    if candidate_id in assigned_list:
        return {"message": "Candidate already assigned to this assistant"}

    now_time = datetime.utcnow().isoformat()

    # ------------------------------------------------
    # UPDATE CANDIDATE
    # ------------------------------------------------
    candidates_table.update_item(

        Key={"candidateId": candidate_id},

        UpdateExpression="""
        SET assistantAssignedTo = :aid,
        updatedAt = :time
        """,

        ExpressionAttributeValues={
            ":aid": assistant_id,
            ":time": now_time
        }
    )

    # ------------------------------------------------
    # UPDATE ASSISTANT
    # ------------------------------------------------
    assistants_table.update_item(

        Key={"assistant_id": assistant_id},

        UpdateExpression="""
        SET assigned_candidates =
        list_append(if_not_exists(assigned_candidates, :empty), :cid),
        updatedAt = :time
        """,

        ExpressionAttributeValues={
            ":cid": [candidate_id],
            ":empty": [],
            ":time": now_time
        }
    )

    return {
        "message": "Candidate assigned successfully",
        "assistantId": assistant_id,
        "candidateId": candidate_id
    }


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

        # AUTH
        admin_data, error = verify_admin_token(event)

        if error:

            return {
                "statusCode": 401,
                "headers": cors,
                "body": json.dumps({"message": error})
            }

        # BODY
        body = json.loads(event.get("body", "{}"))

        assistant_id = body.get("assistantId")
        candidate_id = body.get("candidateId")

        if not assistant_id or not candidate_id:

            return {
                "statusCode": 400,
                "headers": cors,
                "body": json.dumps({
                    "message": "assistantId and candidateId are required"
                })
            }

        result = assign_candidate_to_assistant(
            assistant_id,
            candidate_id
        )

        return {
            "statusCode": 200,
            "headers": cors,
            "body": json.dumps(result)
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