import os
import json
import jwt
import boto3
import logging

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from fastapi import FastAPI, Path, Query, Request, HTTPException, Depends
from fastapi.responses import JSONResponse
from boto3.dynamodb.conditions import Key
from mangum import Mangum


# ============================================================
# Logging
# ============================================================

logger=logging.getLogger()
logger.setLevel(logging.INFO)


# ============================================================
# FastAPI
# ============================================================

app=FastAPI()


# ============================================================
# AWS Clients
# ============================================================

secrets_client=boto3.client("secretsmanager")
sts_client=boto3.client("sts")
dynamodb=boto3.resource("dynamodb")


# ============================================================
# Tables
# ============================================================

job_table=dynamodb.Table(os.environ["JOB_APPLICATIONS_TABLE"])
linkedin_table=dynamodb.Table(os.environ["LINKEDIN_ACTIVITIES_TABLE"])
github_table=dynamodb.Table(os.environ["GITHUB_ACTIVITIES_TABLE"])
portfolio_table=dynamodb.Table(os.environ["PORTFOLIO_TABLE"])


# ============================================================
# Cache
# ============================================================

JWT_SECRET_CACHE=None
ASSISTANT_TABLE_CACHE=None
ROLE_EXPIRY=None


# ============================================================
# Decimal Converter
# ============================================================

def convert_decimal(obj):

    if isinstance(obj,list):
        return [convert_decimal(i) for i in obj]

    if isinstance(obj,dict):
        return {k:convert_decimal(v) for k,v in obj.items()}

    if isinstance(obj,Decimal):
        return float(obj)

    return obj


# ============================================================
# JWT Secret
# ============================================================

def get_jwt_secret():

    global JWT_SECRET_CACHE

    if JWT_SECRET_CACHE:
        return JWT_SECRET_CACHE

    secret_name=os.environ["JWT_SECRET_NAME"]

    response=secrets_client.get_secret_value(
        SecretId=secret_name
    )

    secret=json.loads(response["SecretString"])

    JWT_SECRET_CACHE=secret["jwt_secret"]

    return JWT_SECRET_CACHE


# ============================================================
# Verify Admin
# ============================================================

def verify_admin(request:Request):

    auth_header=request.headers.get("Authorization")

    if not auth_header:
        raise HTTPException(401,"Authorization header missing")

    parts=auth_header.split(" ")

    if len(parts)!=2 or parts[0]!="Bearer":
        raise HTTPException(401,"Invalid Authorization header")

    token=parts[1]

    try:

        decoded=jwt.decode(
            token,
            get_jwt_secret(),
            algorithms=["HS256"]
        )

        if decoded.get("user_type")!="admin":
            raise HTTPException(403,"Unauthorized")

        return decoded

    except jwt.ExpiredSignatureError:
        raise HTTPException(401,"Token expired")

    except jwt.InvalidTokenError:
        raise HTTPException(401,"Invalid token")


# ============================================================
# Cross Account Assistant Table (Cached)
# ============================================================

def get_assistant_table():

    global ASSISTANT_TABLE_CACHE
    global ROLE_EXPIRY

    if ASSISTANT_TABLE_CACHE and ROLE_EXPIRY:

        if datetime.now(timezone.utc)<ROLE_EXPIRY:
            return ASSISTANT_TABLE_CACHE

    role_arn=os.environ["ASSISTANT_DYNAMO_ROLE_ARN"]
    table_name=os.environ["ASSISTANTS_TABLE"]

    assumed_role=sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName="assistant-session"
    )

    credentials=assumed_role["Credentials"]

    ROLE_EXPIRY=credentials["Expiration"]

    dynamodb_cross=boto3.resource(
        "dynamodb",
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"]
    )

    ASSISTANT_TABLE_CACHE=dynamodb_cross.Table(table_name)

    return ASSISTANT_TABLE_CACHE


# ============================================================
# Get Assigned Candidates
# ============================================================

def get_assigned_candidates(assistant_id):

    table=get_assistant_table()

    response=table.get_item(
        Key={"assistantId":assistant_id},
        ProjectionExpression="assigned_candidates"
    )

    assistant=response.get("Item")

    if not assistant:
        return []
    logger.info(f"Assistant {assistant_id} assigned candidates: {assistant.get('assigned_candidates',[])}")
    return assistant.get("assigned_candidates",[])


# ============================================================
# Week Range
# ============================================================

def get_week_range(date):

    start=datetime.strptime(date,"%Y-%m-%d")

    end=start+timedelta(days=6)

    return (
        start.strftime("%Y-%m-%d"),
        end.strftime("%Y-%m-%d")
    )


# ============================================================
# Pagination Helper
# ============================================================

def query_all(table,**kwargs):

    response=table.query(**kwargs)

    items=response.get("Items",[])

    while "LastEvaluatedKey" in response:

        response=table.query(
            ExclusiveStartKey=response["LastEvaluatedKey"],
            **kwargs
        )

        items.extend(response.get("Items",[]))

    return items


# ============================================================
# Job Applications
# ============================================================

@app.get("/admin/assistants/{assistant_id}/job-applications")
def get_job_applications(
    assistant_id:str=Path(...),
    date:str=Query(...),
    admin=Depends(verify_admin)
):

    week_start,week_end=get_week_range(date)

    candidates=get_assigned_candidates(assistant_id)

    result=[]
    logger.info(f"Fetching job applications for assistant {assistant_id} from {week_start} to {week_end}")
    for candidate_id in candidates:

        items=query_all(

            job_table,

            IndexName="candidate_date_index",

            KeyConditionExpression=
            Key("jaa_candidate_id").eq(candidate_id)&
            Key("application_date").between(week_start,week_end)
        )

        jobs=[]

        for j in items:

            jobs.append({

                "job_id":j.get("job_id"),
                "company_name":j.get("company_name"),
                "job_title":j.get("job_title"),
                "application_date":j.get("application_date")
            })

        result.append({

            "candidate_id":candidate_id,
            "job_applications":jobs
        })

    return JSONResponse(convert_decimal(result))


# ============================================================
# LinkedIn Activities
# ============================================================

@app.get("/admin/assistants/{assistant_id}/linkedin-activities")
def get_linkedin_activities(

    assistant_id:str=Path(...),
    date:str=Query(...),
    admin=Depends(verify_admin)

):

    week_start,week_end=get_week_range(date)

    candidates=get_assigned_candidates(assistant_id)

    result=[]

    for candidate_id in candidates:

        items=query_all(

            linkedin_table,

            IndexName="CreatedAtIndex",

            KeyConditionExpression=
            Key("jaa_candidate_id").eq(candidate_id)&
            Key("create_date").between(week_start,week_end)
        )

        activities=[]

        for l in items:

            activities.append({

                "task_id":l.get("task_id"),
                "task_type":l.get("task_type"),
                "title":l.get("title"),
                "status":l.get("status"),
                "create_date":l.get("create_date")
            })

        result.append({

            "candidate_id":candidate_id,
            "linkedin_activities":activities
        })

    return JSONResponse(convert_decimal(result))


# ============================================================
# GitHub Activities
# ============================================================

@app.get("/admin/assistants/{assistant_id}/github-activities")
def get_github_activities(

    assistant_id:str=Path(...),
    date:str=Query(...),
    admin=Depends(verify_admin)

):

    week_start,week_end=get_week_range(date)
    logger.info(f"Fetching GitHub activities for assistant {assistant_id} from {week_start} to {week_end}")

    candidates=get_assigned_candidates(assistant_id)
    logger.info(f"Assistant {assistant_id} assigned candidates: {candidates}")
    result=[]

    for candidate_id in candidates:

        items=query_all(

            github_table,

            IndexName="CandidateIndex",

            KeyConditionExpression=
            Key("jaa_candidate_id").eq(candidate_id)
        )

        projects=[]

        for item in items:

            if item.get("entity_type")!="PROJECT":
                continue

            project_id=item.get("project_id")

            commits=query_all(

                github_table,

                KeyConditionExpression=
                Key("project_id").eq(project_id)&
                Key("commit_date").between(
                    week_start,
                    week_end
                )
            )

            commit_list=[]

            for c in commits:

                if c.get("entity_type")!="COMMIT":
                    continue

                commit_list.append({

                    "commit_id":c.get("id"),
                    "message":c.get("message"),
                    "author":c.get("author"),
                    "commit_date":c.get("commit_date")
                })

            projects.append({

                "project_id":project_id,
                "project_name":item.get("project_name"),
                "repo_url":item.get("repo_url"),
                "commits":commit_list
            })

        result.append({

            "candidate_id":candidate_id,
            "github_projects":projects
        })

    return JSONResponse(convert_decimal(result))


# ============================================================
# Portfolio
# ============================================================

@app.get("/admin/assistants/{assistant_id}/portfolio")
def get_portfolio(

    assistant_id:str=Path(...),
    admin=Depends(verify_admin)

):

    logger.info(f"Fetching portfolio for assistant {assistant_id}")
    candidates=get_assigned_candidates(assistant_id)

    result=[]

    for candidate_id in candidates:

        response=portfolio_table.get_item(

            Key={
                "jaa_candidate_id":candidate_id
            }
        )

        item=response.get("Item")

        portfolio=None

        if item:

            portfolio={

                "portfolio_id":item.get("portfolio_id"),
                "status":item.get("status"),
                "deployment_url":item.get("vercel_deployment_url"),
                "deployment_status":item.get("deployment_status")
            }

        result.append({

            "candidate_id":candidate_id,
            "portfolio":portfolio
        })

    return JSONResponse(convert_decimal(result))


# ============================================================
# Lambda Handler
# ============================================================

handler=Mangum(app)