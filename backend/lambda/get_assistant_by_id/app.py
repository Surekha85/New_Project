import os
import json
import jwt
import boto3
import logging

from datetime import datetime,timedelta
from decimal import Decimal
from fastapi import FastAPI,Request,HTTPException,Depends
from fastapi.responses import JSONResponse
from boto3.dynamodb.conditions import Key
from mangum import Mangum


# ============================================================
# Logger
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


# ============================================================
# Cache
# ============================================================

JWT_SECRET_CACHE=None
ASSISTANT_TABLE=None
CANDIDATE_DYNAMO=None


# ============================================================
# Convert DynamoDB Decimal → JSON safe
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

    response=secrets_client.get_secret_value(
        SecretId=os.environ["JWT_SECRET_NAME"]
    )

    JWT_SECRET_CACHE=json.loads(
        response["SecretString"]
    )["jwt_secret"]

    return JWT_SECRET_CACHE


# ============================================================
# Verify admin token
# ============================================================

def verify_admin(request:Request):

    auth=request.headers.get("Authorization")

    if not auth:
        raise HTTPException(401,"Authorization missing")

    token=auth.split(" ")[1]

    decoded=jwt.decode(
        token,
        get_jwt_secret(),
        algorithms=["HS256"]
    )

    if decoded.get("user_type")!="admin":
        raise HTTPException(403,"Unauthorized")

    return decoded


# ============================================================
# Assistant table
# ============================================================

def get_assistant_table():

    global ASSISTANT_TABLE

    if ASSISTANT_TABLE:
        return ASSISTANT_TABLE

    assumed=sts_client.assume_role(

        RoleArn=os.environ["ASSISTANT_DYNAMO_ROLE_ARN"],
        RoleSessionName="assistant"

    )

    creds=assumed["Credentials"]

    dynamodb=boto3.resource(

        "dynamodb",

        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"]

    )

    ASSISTANT_TABLE=dynamodb.Table(
        os.environ["ASSISTANTS_TABLE"]
    )

    return ASSISTANT_TABLE


# ============================================================
# Candidate tables
# ============================================================

def get_candidate_tables():

    global CANDIDATE_DYNAMO

    if not CANDIDATE_DYNAMO:

        assumed=sts_client.assume_role(

            RoleArn=os.environ["CANDIDATE_DYNAMO_ROLE_ARN"],
            RoleSessionName="candidate"

        )

        creds=assumed["Credentials"]

        CANDIDATE_DYNAMO=boto3.resource(

            "dynamodb",

            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"]

        )

    return(

        CANDIDATE_DYNAMO.Table(os.environ["JOB_APPLICATIONS_TABLE"]),
        CANDIDATE_DYNAMO.Table(os.environ["LINKEDIN_ACTIVITIES_TABLE"]),
        CANDIDATE_DYNAMO.Table(os.environ["GITHUB_ACTIVITIES_TABLE"]),
        CANDIDATE_DYNAMO.Table(os.environ["PORTFOLIO_TABLE"])

    )


# ============================================================
# Get assigned candidates
# ============================================================

def get_assigned_candidates(assistant_id):

    table=get_assistant_table()

    r=table.get_item(
        Key={"assistantId":assistant_id}
    )

    item=r.get("Item")

    if not item:
        return []

    return item.get("assigned_candidates",[])


# ============================================================
# Week range helper
# ============================================================

def get_week_range(date):

    start=datetime.strptime(date,"%Y-%m-%d")

    end=start+timedelta(days=6)

    return start.strftime("%Y-%m-%d"),end.strftime("%Y-%m-%d")


# ============================================================
# Query pagination helper
# ============================================================

def query_all(table,**kwargs):

    r=table.query(**kwargs)

    items=r.get("Items",[])

    while "LastEvaluatedKey" in r:

        r=table.query(

            ExclusiveStartKey=r["LastEvaluatedKey"],
            **kwargs
        )

        items.extend(r.get("Items",[]))

    return items


# ============================================================
# JOB APPLICATION API
# ============================================================

@app.get("/admin/assistants/{assistant_id}/job-applications")
def jobs(assistant_id:str,date:str,admin=Depends(verify_admin)):

    start_time=datetime.now()

    week_start,week_end=get_week_range(date)

    job_table,_,_,_=get_candidate_tables()

    candidates=get_assigned_candidates(assistant_id)

    result={

        "assistant_id":assistant_id,
        "week_start_date":week_start,
        "week_end_date":week_end,
        "total_candidates":len(candidates),
        "assignedCandidates":[],
        "message":""

    }

    if not candidates:

        result["message"]="No candidates assigned"

        return JSONResponse(result)

    for cid in candidates:

        items=query_all(

            job_table,

            IndexName="candidate_date_index",

            KeyConditionExpression=
            Key("jaa_candidate_id").eq(cid)&
            Key("application_date").between(week_start,week_end)

        )

        applications=[]

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

        result["assignedCandidates"].append({

            "candidate_id":cid,
            "total_records":len(applications),
            "job_applications":applications

        })

    result["execution_time"]=str(datetime.now()-start_time)

    result["message"]="Success"

    return JSONResponse(convert_decimal(result))


# ============================================================
# LINKEDIN API
# ============================================================

@app.get("/admin/assistants/{assistant_id}/linkedin-activities")
def linkedin(assistant_id:str,date:str,admin=Depends(verify_admin)):

    start_time=datetime.now()

    week_start,week_end=get_week_range(date)

    _,linkedin_table,_,_=get_candidate_tables()

    candidates=get_assigned_candidates(assistant_id)

    result={

        "assistant_id":assistant_id,
        "week_start_date":week_start,
        "week_end_date":week_end,
        "total_candidates":len(candidates),
        "assignedCandidates":[],
        "message":""

    }

    if not candidates:

        result["message"]="No candidates assigned"

        return JSONResponse(result)

    for cid in candidates:

        items=query_all(

            linkedin_table,

            IndexName="CreatedAtIndex",

            KeyConditionExpression=
            Key("jaa_candidate_id").eq(cid)&
            Key("create_date").between(week_start,week_end)

        )

        activities=[]

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
                "created_date": item.get("created_date"),
                "created_by": item.get("created_by"),
                "created_at": item.get("created_at"),
                "updated_at": item.get("updated_at"),
                "completed_at": item.get("completed_at")

            })

        result["assignedCandidates"].append({

            "candidate_id":cid,
            "total_records":len(activities),
            "linkedin_activities":activities

        })

    result["execution_time"]=str(datetime.now()-start_time)

    result["message"]="Success"

    return JSONResponse(convert_decimal(result))


# ============================================================
# GITHUB API
# ============================================================

@app.get("/admin/assistants/{assistant_id}/github-activities")
def github(assistant_id:str,date:str,admin=Depends(verify_admin)):

    start_time=datetime.now()

    week_start,week_end=get_week_range(date)

    _,_,github_table,_=get_candidate_tables()

    candidates=get_assigned_candidates(assistant_id)

    result={

        "assistant_id":assistant_id,
        "week_start_date":week_start,
        "week_end_date":week_end,
        "total_candidates":len(candidates),
        "assignedCandidates":[],
        "message":""

    }

    if not candidates:

        result["message"]="No candidates assigned"

        return JSONResponse(result)

    for cid in candidates:

        projects=query_all(

            github_table,

            IndexName="CandidateIndex",

            KeyConditionExpression=
            Key("jaa_candidate_id").eq(cid)

        )

        project_data=[]

        for project in projects:

            if project.get("entity_type")!="PROJECT":
                continue

            project_id=project.get("project_id")

            commits=github_table.query(

                KeyConditionExpression=
                Key("project_id").eq(project_id)&
                Key("commit_date").between(week_start,week_end)

            )

            commit_list=[

                {

                    "id":c.get("id"),
                    "message":c.get("message"),
                    "author":c.get("author"),
                    "commit_date":c.get("commit_date"),
                    "files_changed":c.get("files_changed"),
                    "commit_url":c.get("commit_url")

                }

                for c in commits.get("Items",[])
                if c.get("entity_type")=="COMMIT"

            ]

            project_data.append({

                "project_id":project_id,
                "project_name":project.get("project_name"),
                "repo_url":project.get("repo_url"),
                "status":project.get("status"),
                "repo_visibility":project.get("repo_visibility"),
                "start_date":project.get("start_date"),
                "estimation_date":project.get("estimation_date"),
                "repo_created_at":project.get("repo_created_at"),
                "commits":commit_list

            })

        result["assignedCandidates"].append({

            "candidate_id":cid,
            "total_records":len(project_data),
            "github_projects":project_data

        })

    result["execution_time"]=str(datetime.now()-start_time)

    result["message"]="Success"

    return JSONResponse(convert_decimal(result))


# ============================================================
# PORTFOLIO API
# ============================================================
# ============================================================
# PORTFOLIO JOB PREPARATION API
# ============================================================

@app.get("/admin/assistants/{assistant_id}/portfolio")
def portfolio_job_preparation(assistant_id:str,admin=Depends(verify_admin)):

    start_time=datetime.now()


    _,_,_,portfolio_table=get_candidate_tables()

    candidates=get_assigned_candidates(assistant_id)

    result={

        "assistant_id":assistant_id,

        "total_candidates":len(candidates),

        "assignedCandidates":[],

        "message":""

    }

    if not candidates:

        result["message"]="No candidates assigned"

        return JSONResponse(result)


    for cid in candidates:

        r=portfolio_table.get_item(

            Key={"jaa_candidate_id":cid}

        )

        item=r.get("Item")

        if item:

            portfolio_data={

                "candidate_id":item.get("jaa_candidate_id"),

                "portfolio_id":item.get("portfolio_id"),

                "status":item.get("status"),

                "github":{

                    "repo_url":item.get("github_repo_url"),

                    "repo_name":item.get("github_repo_name")

                },

                "deployment":{

                    "vercel_project":item.get("vercel_project_name"),

                    "deployment_url":item.get("vercel_deployment_url"),

                    "deployment_status":item.get("deployment_status")

                },

                "created_at":item.get("created_at"),

                "updated_at":item.get("updated_at")

            }


        result["assignedCandidates"].append({

            "candidate_id":cid,
            "portfolio":portfolio_data

        })


    result["execution_time"]=str(datetime.now()-start_time)

    result["message"]="Success"

    return JSONResponse(convert_decimal(result))


# ============================================================
# Lambda handler
# ============================================================

handler=Mangum(app)






{
  "httpMethod": "GET",
  "resource": "/admin/assistants/{assistantId}/github-activities",
  "path": "/admin/assistants/asst1/github-activities",
  "pathParameters": {
    "assistant_Id": "asst1"
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