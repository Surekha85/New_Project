import os
import json
import jwt
import boto3
import logging

from decimal import Decimal
from datetime import datetime, timedelta

from fastapi import FastAPI, Path, Query, Request, HTTPException, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from boto3.dynamodb.conditions import Key
from mangum import Mangum
from cryptography.fernet import Fernet


fernet = Fernet(SECRET_KEY.encode())

def decrypt_password(encrypted_password):
    return fernet.decrypt(encrypted_password.encode()).decode()


# ---------------------------------------------------
# Logging
# ---------------------------------------------------

logger = logging.getLogger()
logger.setLevel(logging.INFO)


# ---------------------------------------------------
# FastAPI App
# ---------------------------------------------------

app = FastAPI()

# ✅ CORS MIDDLEWARE (CRITICAL FIX)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ GLOBAL OPTIONS HANDLER (CRITICAL FIX)
@app.options("/{full_path:path}")
def options_handler(full_path: str):
    return JSONResponse(
        status_code=200,
        content={"message": "OK"},
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
        }
    )

# ---------------------------------------------------
# AWS Clients
# ---------------------------------------------------

sts_client = boto3.client("sts")
secrets_client = boto3.client("secretsmanager")


# ---------------------------------------------------
# Caches
# ====================================================
STS_CACHE = {}  # role_arn -> {"dynamodb": ..., "expires_at": datetime}
JWT_SECRET_CACHE = {"secret": None, "expires_at": None}
JWT_CACHE_TTL = timedelta(minutes=10)  # refresh JWT secret every 10 mins

# ====================================================
# CORS Headers
# ====================================================
def get_cors_headers():
    return {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Allow-Methods": "GET, OPTIONS"
    }

# ====================================================
# STS Assume Role (with expiry)
# ====================================================
def assume_role(role_arn):
    now = datetime.utcnow()
    cache_entry = STS_CACHE.get(role_arn)

    if cache_entry and cache_entry["expires_at"] > now:
        return cache_entry["dynamodb"]

    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="AdminPortalSession"
        )
        credentials = response["Credentials"]
        dynamodb = boto3.resource(
            "dynamodb",
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"]
        )

        STS_CACHE[role_arn] = {
            "dynamodb": dynamodb,
            "expires_at": credentials["Expiration"] - timedelta(minutes=5)  # refresh 5 min before expiry
        }
        return dynamodb
    except Exception as e:
        logger.exception(f"Failed to assume role {role_arn}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


# ---------------------------------------------------
# DynamoDB Tables
# ---------------------------------------------------

candidate_role = os.environ["CANDIDATE_DYNAMO_ROLE_ARN"]

dynamodb = assume_role(candidate_role)

candidates_table = dynamodb.Table(os.environ["CANDIDATES_TABLE"])
job_applications_table = dynamodb.Table(os.environ["JOB_APPLICATIONS_TABLE"])
github_activities_table = dynamodb.Table(os.environ["GITHUB_ACTIVITIES_TABLE"])
linkedin_activities_table = dynamodb.Table(os.environ["LINKEDIN_ACTIVITIES_TABLE"])
portfolio_table = dynamodb.Table(os.environ["PORTFOLIO_TABLE"])


# ---------------------------------------------------
# JWT SECRET (Cached)
# ---------------------------------------------------

def get_jwt_secret():
    now = datetime.utcnow()
    if JWT_SECRET_CACHE["secret"] and JWT_SECRET_CACHE["expires_at"] > now:
        return JWT_SECRET_CACHE["secret"]

    secret_name = os.environ["JWT_SECRET_NAME"]
    try:
        response = secrets_client.get_secret_value(SecretId=secret_name)
        secret_data = json.loads(response["SecretString"])
        JWT_SECRET_CACHE["secret"] = secret_data["jwt_secret"]
        JWT_SECRET_CACHE["expires_at"] = now + JWT_CACHE_TTL
        return JWT_SECRET_CACHE["secret"]
    except Exception as e:
        logger.exception(f"Failed to retrieve JWT secret {secret_name}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

# ====================================================
# Verify Admin Token
# ---------------------------------------------------

def verify_admin_token(request: Request):

    auth_header = request.headers.get("authorization")

    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid Authorization header"
        )

    token = auth_header.split(" ")[1]

    try:

        jwt_secret = get_jwt_secret()

        decoded = jwt.decode(
            token,
            jwt_secret,
            algorithms=["HS256"]
        )

        if decoded.get("user_type") != "admin":
            raise HTTPException(
                status_code=403,
                detail="Unauthorized user"
            )

        return decoded

    except jwt.ExpiredSignatureError:

        raise HTTPException(
            status_code=401,
            detail="Token expired"
        )

    except jwt.InvalidTokenError:

        raise HTTPException(
            status_code=401,
            detail="Invalid token"
        )


# ---------------------------------------------------
# Week Range Helper
# ---------------------------------------------------

def get_week_range(date):

    try:
        start = datetime.strptime(date, "%Y-%m-%d")
        end = start + timedelta(days=6)

        return date, end.strftime("%Y-%m-%d")

    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid date format. Use YYYY-MM-DD"
        )


# ---------------------------------------------------
# Decimal Converter
# ---------------------------------------------------

def convert(obj):

    if isinstance(obj, list):
        return [convert(i) for i in obj]

    if isinstance(obj, dict):
        return {k: convert(v) for k, v in obj.items()}

    if isinstance(obj, Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)

    return obj



@app.get("/admin/candidates/{candidate_id}")
def get_candidate_profile(candidate_id: str, request: Request):

    cors = get_cors_headers()

    try:

        response = candidates_table.get_item(
            Key={"jaa_candidate_id": candidate_id}
        )

        item = response.get("Item")
        logging.info(f"Fetched candidate: {item}")

        if item.get("dedicatedGmailAccount", {}).get("password"):
            encrypted = item["dedicatedGmailAccount"]["password"]
            item["dedicatedGmailAccount"]["password"] = decrypt_password(encrypted)

        candidate_response = {
            "jaa_candidate_id": item.get("jaa_candidate_id"),
            "user_id": item.get("user_id"),
            "first_name": item.get("first_name"),
            "last_name": item.get("last_name"),
            "email": item.get("email"),
            "phone": item.get("phone"),
            "github": item.get("github"),
            "linkedin": item.get("linkedin"),
            "resumeUrl": item.get("resumeUrl"),
            "resumeFileExtension": item.get("resumeFileExtension"),
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

        return JSONResponse(
            status_code=200,
            content=convert(candidate_response),
            headers=cors
        )

    except HTTPException as e:

        return JSONResponse(
            status_code=e.status_code,
            content={"message": e.detail},
            headers=cors
        )



# ===================================================
# 1️⃣ Job Applications
# ===================================================

@app.get("/admin/candidates/{candidate_id}/job-applications")
def get_job_applications(
        request: Request,
        candidate_id: str = Path(...),
        date: str = Query(...),
        user=Depends(verify_admin_token)
):

    cors = get_cors_headers()

    week_start, week_end = get_week_range(date)

    try:

        response = job_applications_table.query(
            IndexName="candidate_date_index",
            KeyConditionExpression=
            Key("jaa_candidate_id").eq(candidate_id) &
            Key("application_date").between(week_start, week_end)
        )

        items = response.get("Items", [])

        applications = []

        for item in items:

            applications.append({
                "candidate_id": item.get("jaa_candidate_id"),
                "job_id": item.get("job_id"),
                "job_title": item.get("job_title"),
                "company_name": item.get("company_name"),
                "application_date": item.get("application_date"),
                "application_link": item.get("application_link"),
                "applied_via": item.get("applied_via"),
                "approval_status": item.get("approval_status"),
                "ats_score": item.get("ats_score"),
                "ai_detection_score": item.get("ai_detection_score"),
                "resume_s3_url": item.get("resume_s3_url"),
                "employment_type": item.get("employment_type"),
                "experience": item.get("experience"),
                "created_at": item.get("created_at"),
                "updated_at": item.get("updated_at")
            })

        response_body = {
            "candidate_id": candidate_id,
            "week_start_date": week_start,
            "week_end_date": week_end,
            "total_applications": len(applications),
            "applications": applications
        }

        return JSONResponse(
            status_code=200,
            content=convert(response_body),
            headers=cors
        )

    except Exception as e:

        logger.exception("Job applications error")

        return JSONResponse(
            status_code=500,
            content={"message": str(e)},
            headers=cors
        )


# ===================================================
# 2️⃣ GitHub Activities
# ===================================================

@app.get("/admin/candidates/{candidate_id}/github-activities")
def get_github_weekly(
        request: Request,
        candidate_id: str,
        date: str = Query(...),
        user=Depends(verify_admin_token)
):

    cors = get_cors_headers()

    week_start, week_end = get_week_range(date)

    try:

        projects_response = github_activities_table.query(
            IndexName="CandidateIndex",
            KeyConditionExpression=
            Key("jaa_candidate_id").eq(candidate_id)
        )

        projects = [
            p for p in projects_response.get("Items", [])
            if p.get("entity_type") == "PROJECT"
        ]

        projects_data = []

        for project in projects:

            project_id = project["project_id"]

            commits_response = github_activities_table.query(
                KeyConditionExpression=
                Key("project_id").eq(project_id) &
                Key("commit_date").between(week_start, week_end)
            )

            commits = [
                {
                    "id": c.get("id"),
                    "message": c.get("message"),
                    "author": c.get("author"),
                    "commit_date": c.get("commit_date"),
                    "files_changed": c.get("files_changed"),
                    "commit_url": c.get("commit_url")
                }
                for c in commits_response.get("Items", [])
                if c.get("entity_type") == "COMMIT"
            ]

            projects_data.append({
                "project_id": project_id,
                "project_name": project.get("project_name"),
                "repo_url": project.get("repo_url"),
                "status": project.get("status"),
                "repo_visibility": project.get("repo_visibility"),
                "start_date": project.get("start_date"),
                "estimation_date": project.get("estimation_date"),
                "repo_created_at": project.get("repo_created_at"),
                "commits": commits
            })

        response_body = {
            "candidate_id": candidate_id,
            "week_start_date": week_start,
            "week_end_date": week_end,
            "total_projects": len(projects_data),
            "projects": projects_data
        }

        return JSONResponse(
            status_code=200,
            content=convert(response_body),
            headers=cors
        )

    except Exception as e:

        logger.exception("GitHub activities error")

        return JSONResponse(
            status_code=500,
            content={"message": str(e)},
            headers=cors
        )


# ===================================================
# 3️⃣ LinkedIn Activities
# ===================================================

@app.get("/admin/candidates/{candidate_id}/linkedin-activities")
def get_linkedin_weekly(
        request: Request,
        candidate_id: str,
        date: str = Query(...),
        user=Depends(verify_admin_token)
):

    cors = get_cors_headers()

    week_start, week_end = get_week_range(date)

    try:

        response = linkedin_activities_table.query(
            IndexName="CreatedAtIndex",
            KeyConditionExpression=
            Key("jaa_candidate_id").eq(candidate_id) &
            Key("create_date").between(week_start, week_end)
        )

        items = response.get("Items", [])

        activities = []

        for item in items:

            activities.append({
                "task_id": item.get("task_id"),
                "task_type": item.get("task_type"),
                "title": item.get("title"),
                "status": item.get("status"),
                "due_date": item.get("due_date"),
                "linkedin_profile_url": item.get("linkedin_profile_url"),
                "recipient_name": item.get("recipient_name"),
                "recipient_title": item.get("recipient_title"),
                "created_date": item.get("create_date"),
                "created_by": item.get("created_by"),
                "created_at": item.get("created_at"),
                "updated_at": item.get("updated_at"),
                "completed_at": item.get("completed_at")
            })

        response_body = {
            "candidate_id": candidate_id,
            "week_start_date": week_start,
            "week_end_date": week_end,
            "total_activities": len(activities),
            "activities": activities
        }

        return JSONResponse(
            status_code=200,
            content=convert(response_body),
            headers=cors
        )

    except Exception as e:

        logger.exception("LinkedIn activities error")

        return JSONResponse(
            status_code=500,
            content={"message": str(e)},
            headers=cors
        )


# ===================================================
# 4️⃣ Portfolio
# ===================================================

@app.get("/admin/candidates/{candidate_id}/portfolio")
def get_portfolio(
        request: Request,
        candidate_id: str,
        user=Depends(verify_admin_token)
):

    cors = get_cors_headers()

    try:

        response = portfolio_table.get_item(
            Key={"jaa_candidate_id": candidate_id}
        )

        portfolio = response.get("Item")

        if not portfolio:

            return JSONResponse(
                status_code=404,
                content={"message": "Portfolio not found"},
                headers=cors
            )

        portfolio_data = {
            "candidate_id": portfolio.get("jaa_candidate_id"),
            "portfolio_id": portfolio.get("portfolio_id"),
            "status": portfolio.get("status"),
            "github": {
                "repo_url": portfolio.get("github_repo_url"),
                "repo_name": portfolio.get("github_repo_name")
            },
            "vercel": {
                "project_name": portfolio.get("vercel_project_name"),
                "project_id": portfolio.get("vercel_project_id"),
                "deployment_url": portfolio.get("vercel_deployment_url"),
                "deployment_status": portfolio.get("deployment_status")
            },
            "change_requests": portfolio.get("change_requests", []),
            "created_by": portfolio.get("created_by"),
            "created_at": portfolio.get("created_at"),
            "updated_at": portfolio.get("updated_at")
        }

        return JSONResponse(
            status_code=200,
            content=convert(portfolio_data),
            headers=cors
        )

    except Exception as e:

        logger.exception("Portfolio error")

        return JSONResponse(
            status_code=500,
            content={"message": str(e)},
            headers=cors
        )


# ---------------------------------------------------
# Lambda Adapter
# ---------------------------------------------------

handler = Mangum(app)




{
  "httpMethod": "GET",
  "resource": "/admin/candidates/{candidateId}/github-activities",
  "path": "/admin/candidates/cand1/github-activities",
  "pathParameters": {
    "candidate_id": "cand1"
  },
  "queryStringParameters": {
    "date": "2026-02-10"
  },
  "headers": {
    "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbklkIjoiNTBlM2E0ZWEtZTBiZi00NmQ2LWIxYWMtNTIyYTE0MDVhNDc3IiwiZW1haWwiOiJqb2huQGV4YW1wbGUuY29tIiwidXNlcl90eXBlIjoiYWRtaW4iLCJmaXJzdF9uYW1lIjoiSm9obiIsImxhc3RfbmFtZSI6IkRvZSIsImlhdCI6MTc3MzYzNzU3OCwiZXhwIjoxNzczNzIzOTc4fQ.x_f7m6fCc8LBN6dl8F-nKyE2A4D2NVbQ9dNuEd_qxac"
  },
  "requestContext": {
  }
}

