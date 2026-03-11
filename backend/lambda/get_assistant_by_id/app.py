import os
import json
import jwt
import boto3
import logging

from datetime import datetime, timedelta
from decimal import Decimal
from fastapi import FastAPI, Path, Query, Request, HTTPException, Depends
from fastapi.responses import JSONResponse
from boto3.dynamodb.conditions import Key
from mangum import Mangum


# ============================================================
# Logging
# ============================================================

logger = logging.getLogger()
logger.setLevel(logging.INFO)


# ============================================================
# FastAPI App
# ============================================================

app = FastAPI()


# ============================================================
# AWS Clients
# ============================================================

secrets_client = boto3.client("secretsmanager")
sts_client = boto3.client("sts")
dynamodb = boto3.resource("dynamodb")


# ============================================================
# DynamoDB Tables
# ============================================================

job_table = dynamodb.Table(os.environ["JOB_APPLICATIONS_TABLE"])
linkedin_table = dynamodb.Table(os.environ["LINKEDIN_ACTIVITIES_TABLE"])
github_table = dynamodb.Table(os.environ["GITHUB_ACTIVITIES_TABLE"])
portfolio_table = dynamodb.Table(os.environ["PORTFOLIO_TABLE"])

JWT_SECRET_CACHE = None


# ============================================================
# Decimal Converter
# ============================================================

def convert_decimal(obj):

    if isinstance(obj, list):
        return [convert_decimal(i) for i in obj]

    if isinstance(obj, dict):
        return {k: convert_decimal(v) for k, v in obj.items()}

    if isinstance(obj, Decimal):
        return int(obj)

    return obj


# ============================================================
# JWT Secret
# ============================================================

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


# ============================================================
# Verify Admin Token
# ============================================================

def verify_admin(request: Request):

    auth_header = request.headers.get("Authorization")

    if not auth_header:
        raise HTTPException(status_code=401, detail="Authorization header missing")

    token = auth_header.split(" ")[1]

    try:

        decoded = jwt.decode(
            token,
            get_jwt_secret(),
            algorithms=["HS256"]
        )

        if decoded.get("user_type") != "admin":
            raise HTTPException(status_code=403, detail="Unauthorized")

        return decoded

    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


# ============================================================
# Cross Account Assistant Table
# ============================================================

def get_assistant_table():

    role_arn = os.environ["ASSISTANT_DYNAMO_ROLE_ARN"]
    table_name = os.environ["ASSISTANTS_TABLE"]

    assumed_role = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName="assistant-session"
    )

    credentials = assumed_role["Credentials"]

    dynamodb_cross = boto3.resource(
        "dynamodb",
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"]
    )

    return dynamodb_cross.Table(table_name)


# ============================================================
# Get Candidates for Assistant
# ============================================================

def get_assigned_candidates(assistant_id):

    assistant_table = get_assistant_table()

    response = assistant_table.get_item(
        Key={"assistantId": assistant_id},
        ProjectionExpression="assigned_candidates"
    )

    assistant = response.get("Item")

    # if not assistant:
    #     raise HTTPException(status_code=404, detail="Assistant not found")

    # return assistant.get("assigned_candidates", [])
    return ['cand1', 'cand2', 'cand3']


# ============================================================
# Week Range
# ============================================================

def get_week_range(date):

    start = datetime.strptime(date, "%Y-%m-%d")
    end = start + timedelta(days=6)

    return date, end.strftime("%Y-%m-%d")


# ============================================================
# 1️⃣ Job Applications
# ============================================================

@app.get("/admin/assistants/{assistant_id}/job-applications")
def get_job_applications(
        assistant_id: str = Path(...),
        date: str = Query(...),
        admin=Depends(verify_admin)
):

    week_start, week_end = get_week_range(date)

    candidates = get_assigned_candidates(assistant_id)

    result = []

    for candidate_id in candidates:

        response = job_table.query(
            IndexName="candidate_date_index",
            KeyConditionExpression=
            Key("jaa_candidate_id").eq(candidate_id) &
            Key("application_date").between(week_start, week_end)
        )

        jobs = []

        for j in response.get("Items", []):

            jobs.append({
                "job_id": j.get("job_id"),
                "company_name": j.get("company_name"),
                "job_title": j.get("job_title"),
                "application_date": j.get("application_date")
            })

        result.append({
            "candidate_id": candidate_id,
            "job_applications": jobs
        })

    return JSONResponse(content=convert_decimal(result))


# ============================================================
# 2️⃣ LinkedIn Activities
# ============================================================

@app.get("/admin/assistants/{assistant_id}/linkedin-activities")
def get_linkedin_activities(
        assistant_id: str = Path(...),
        date: str = Query(...),
        admin=Depends(verify_admin)
):

    week_start, week_end = get_week_range(date)

    candidates = get_assigned_candidates(assistant_id)

    result = []

    for candidate_id in candidates:

        response = linkedin_table.query(
            IndexName="CreatedAtIndex",
            KeyConditionExpression=
            Key("jaa_candidate_id").eq(candidate_id) &
            Key("create_date").between(week_start, week_end)
        )

        activities = []

        for l in response.get("Items", []):

            activities.append({
                "task_id": l.get("task_id"),
                "task_type": l.get("task_type"),
                "title": l.get("title"),
                "status": l.get("status"),
                "create_date": l.get("create_date")
            })

        result.append({
            "candidate_id": candidate_id,
            "linkedin_activities": activities
        })

    return JSONResponse(content=convert_decimal(result))


# ============================================================
# 3️⃣ GitHub Activities
# ============================================================

@app.get("/admin/assistants/{assistant_id}/github-activities")
def get_github_activities(
        assistant_id: str = Path(...),
        date: str = Query(...),
        admin=Depends(verify_admin)
):

    week_start, week_end = get_week_range(date)

    candidates = get_assigned_candidates(assistant_id)

    result = []

    for candidate_id in candidates:

        response = github_table.query(
            IndexName="CandidateIndex",
            KeyConditionExpression=Key("jaa_candidate_id").eq(candidate_id)
        )

        projects = []

        for item in response.get("Items", []):

            if item.get("entity_type") != "PROJECT":
                continue

            project_id = item.get("project_id")

            commits_resp = github_table.query(
                KeyConditionExpression=
                Key("project_id").eq(project_id) &
                Key("commit_date").between(week_start, week_end)
            )

            commits = []

            for c in commits_resp.get("Items", []):

                if c.get("entity_type") != "COMMIT":
                    continue

                commits.append({
                    "commit_id": c.get("id"),
                    "message": c.get("message"),
                    "author": c.get("author"),
                    "commit_date": c.get("commit_date")
                })

            projects.append({
                "project_id": project_id,
                "project_name": item.get("project_name"),
                "repo_url": item.get("repo_url"),
                "commits": commits
            })

        result.append({
            "candidate_id": candidate_id,
            "github_projects": projects
        })

    return JSONResponse(content=convert_decimal(result))


# ============================================================
# 4️⃣ Portfolio
# ============================================================

@app.get("/admin/assistants/{assistant_id}/portfolio")
def get_portfolio(
        assistant_id: str = Path(...),
        admin=Depends(verify_admin)
):

    candidates = get_assigned_candidates(assistant_id)

    result = []

    for candidate_id in candidates:

        response = portfolio_table.get_item(
            Key={"jaa_candidate_id": candidate_id}
        )

        item = response.get("Item")

        portfolio = None

        if item:

            portfolio = {
                "portfolio_id": item.get("portfolio_id"),
                "status": item.get("status"),
                "deployment_url": item.get("vercel_deployment_url"),
                "deployment_status": item.get("deployment_status")
            }

        result.append({
            "candidate_id": candidate_id,
            "portfolio": portfolio
        })

    return JSONResponse(content=convert_decimal(result))


# ============================================================
# Lambda Handler
# ============================================================

handler = Mangum(app)