import os
import json
import boto3
from boto3.dynamodb.conditions import Key
from datetime import datetime, timedelta
from decimal import Decimal


def decimal_default(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError


# -----------------------------------------
# Assume Cross Account Role
# -----------------------------------------
def get_cross_account_resource(role_arn):

    sts = boto3.client("sts")

    response = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName="AdminGetCandidateProfileSession"
    )

    credentials = response["Credentials"]

    dynamodb = boto3.resource(
        "dynamodb",
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"]
    )

    return dynamodb


# -----------------------------------------
# Query Helper
# -----------------------------------------
def query_by_date(table, index_name, candidate_id, start_date, end_date, date_field):

    response = table.query(
        IndexName=index_name,
        KeyConditionExpression=
        Key("jaa_candidate_id").eq(candidate_id) &
        Key(date_field).between(start_date, end_date)
    )

    return response.get("Items", [])


# -----------------------------------------
# Lambda Handler
# -----------------------------------------
def handler(event, context):

    try:

        candidate_id = event["pathParameters"]["candidateId"]

        params = event.get("queryStringParameters") or {}

        start_date = params.get("start_date")

        if not start_date:
            return {
                "statusCode": 400,
                "body": json.dumps({"message": "start_date required"})
            }

        start = datetime.strptime(start_date, "%Y-%m-%d")
        end = start + timedelta(days=6)

        end_date = end.strftime("%Y-%m-%d")

        # ENV variables
        candidate_role = os.environ["CANDIDATE_DYNAMO_ROLE_ARN"]
        assistant_role = os.environ["ASSISTANT_DYNAMO_ROLE_ARN"]

        candidates_table_name = os.environ["CANDIDATES_TABLE"]
        job_apps_table_name = os.environ["JOB_APPLICATIONS_TABLE"]
        portfolio_table_name = os.environ["PORTFOLIO_TABLE"]
        github_table_name = os.environ["GITHUB_ACTIVITIES_TABLE"]
        linkedin_table_name = os.environ["LINKEDIN_ACTIVITIES_TABLE"]

        # Cross account connections
        candidate_db = get_cross_account_resource(candidate_role)
        assistant_db = get_cross_account_resource(assistant_role)

        candidates_table = candidate_db.Table(candidates_table_name)
        job_apps_table = candidate_db.Table(job_apps_table_name)
        portfolio_table = candidate_db.Table(portfolio_table_name)

        github_table = assistant_db.Table(github_table_name)
        linkedin_table = assistant_db.Table(linkedin_table_name)

        # ---------------------------
        # Candidate Profile
        # ---------------------------
        profile = candidates_table.get_item(
            Key={"jaa_candidate_id": candidate_id}
        ).get("Item", {})

        # ---------------------------
        # Portfolio
        # ---------------------------
        portfolio = portfolio_table.query(
            KeyConditionExpression=Key("jaa_candidate_id").eq(candidate_id)
        ).get("Items", [])

        # ---------------------------
        # Job Applications (GSI)
        # ---------------------------
        job_apps = query_by_date(
            job_apps_table,
            "candidate_date_index",
            candidate_id,
            start_date,
            end_date,
            "application_date"
        )

        # ---------------------------
        # GitHub Activities
        # ---------------------------
        github = query_by_date(
            github_table,
            "CandidateIndex",
            candidate_id,
            start_date,
            end_date,
            "commit_date"
        )

        # ---------------------------
        # LinkedIn Activities
        # ---------------------------
        linkedin = query_by_date(
            linkedin_table,
            "CreatedAtIndex",
            candidate_id,
            start_date,
            end_date,
            "create_date"
        )

        # Final response
        result = {
            "candidate_id": candidate_id,
            "week_start_date": start_date,
            "week_end_date": end_date,
            "profile": profile,
            "portfolio": portfolio,
            "job_applications": job_apps,
            "github_activities": github,
            "linkedin_activities": linkedin
        }

        return {
            "statusCode": 200,
            "body": json.dumps(result, default=decimal_default)
        }

    except Exception as e:

        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }