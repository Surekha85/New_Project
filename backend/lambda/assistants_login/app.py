import json
import boto3
import hashlib
import jwt
import re
import os
import logging
from datetime import datetime, timedelta
from botocore.exceptions import ClientError

# ---------------------------
# CloudWatch Logger Setup
# ---------------------------
logger = logging.getLogger()
logger.setLevel(logging.INFO)

cloudwatch = boto3.client('cloudwatch')

# Initialize AWS clients
dynamodb = boto3.client('dynamodb')
secrets_client = boto3.client('secretsmanager')

def get_cors_headers():
    """Get CORS headers based on deployment stage"""
    stage = os.getenv('STAGE', 'prod').lower()
    
    if stage == 'beta':
        origin = 'https://beta.jobsyme.com'
    elif stage == 'gamma':
        origin = 'https://gamma.jobsyme.com'  # In case you have gamma environment
    else:
        origin = 'https://www.jobsyme.com'  # Production - most secure
    
    return {
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
        'Access-Control-Allow-Methods': 'POST,OPTIONS',
        'Access-Control-Allow-Credentials': 'true'
    }

def handler(event, context):
    """
    Candidate Login Lambda Function
    
    Authenticates candidates with email/password and returns JWT token.
    Checks email verification status before allowing login.
    """
    
    logger.info("Candidate login request received")
    
    # CORS headers for API Gateway - Environment-aware configuration
    cors_headers = get_cors_headers()
    
    try:
        # Handle preflight requests
        if event.get('httpMethod') == 'OPTIONS':
            logger.info("CORS preflight request handled")
            return {
                'statusCode': 200,
                'headers': cors_headers,
                'body': json.dumps({'message': 'CORS preflight'})
            }
        
        # Parse request body
        if 'body' not in event or not event['body']:
            return error_response(400, "Missing request body", cors_headers)
        
        try:
            body = json.loads(event['body'])
        except json.JSONDecodeError:
            return error_response(400, "Invalid JSON in request body", cors_headers)
        
        # Validate required fields
        email = body.get('email', '').strip().lower()
        password = body.get('password', '').strip()
        
        logger.info(f"Login attempt for email: {email}")
        
        # Validation
        validation_error = validate_inputs(email, password)
        if validation_error:
            logger.warning(f"Validation failed for {email}: {validation_error}")
            return error_response(400, validation_error, cors_headers)
        
        # Authenticate user
        auth_result = authenticate_candidate(email, password)
        if not auth_result['success']:
            logger.warning(f"Authentication failed for {email}: {auth_result['error']}")
            return error_response(401, auth_result['error'], cors_headers)
        
        candidate_data = auth_result['candidate']
        
        # Check email verification status
        if not candidate_data.get('email_verified', False):
            logger.warning(f"Email not verified for {email}")
            return error_response(403, "Please verify your email before logging in", cors_headers)
        
        # Generate JWT token
        token_result = generate_jwt_token(candidate_data)
        if not token_result['success']:
            return error_response(500, f"Failed to generate token: {token_result['error']}", cors_headers)
        
        # Update last login timestamp
        update_result = update_last_login(candidate_data['user_id'])
        if not update_result['success']:
            logger.warning(f"Failed to update last login for {email}: {update_result['error']}")
        
        # Success response
        logger.info(f"Successful login for {email}")
        return {
            'statusCode': 200,
            'headers': cors_headers,
            'body': json.dumps({
                'message': 'Login successful',
                'token': token_result['token'],
                'expires_in': token_result['expires_in'],
                'user': {
                    'user_id': candidate_data['user_id'],
                    'user_type': 'candidate',
                    'email': candidate_data['email'],
                    'first_name': candidate_data['first_name'],
                    'last_name': candidate_data['last_name'],
                    'email_verified': candidate_data['email_verified']
                }
            })
        }
        
    except Exception as e:
        logger.error(f"Unexpected error in candidate_login: {str(e)}")
        return error_response(500, "Internal server error", cors_headers)


def validate_inputs(email, password):
    """Validate login inputs"""
    
    # Email validation
    if not email:
        return "Email is required"
    
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        return "Invalid email format"
    
    # Password validation
    if not password:
        return "Password is required"
    
    return None


def authenticate_candidate(email, password):
    """Authenticate candidate credentials"""
    
    try:
        table_name = os.getenv('CANDIDATES_TABLE_NAME')
        if not table_name:
            return {'success': False, 'error': 'Candidates table not configured'}
        
        # Query candidate by email using GSI
        response = dynamodb.query(
            TableName=table_name,
            IndexName='email-index',
            KeyConditionExpression='email = :email',
            ExpressionAttributeValues={
                ':email': {'S': email}
            }
        )
        
        if not response.get('Items'):
            return {'success': False, 'error': 'Invalid email or password'}
        
        item = response['Items'][0]
        
        # Extract candidate data
        candidate_data = {
            'user_id': item.get('user_id', {}).get('S', ''),
            'email': item.get('email', {}).get('S', ''),
            'password_hash': item.get('password_hash', {}).get('S', ''),
            'first_name': item.get('first_name', {}).get('S', ''),
            'last_name': item.get('last_name', {}).get('S', ''),
            'email_verified': item.get('email_verified', {}).get('BOOL', False),
            'created_at': item.get('created_at', {}).get('S', ''),
            'last_login_at': item.get('last_login_at', {}).get('S')
        }
        
        # Verify password
        if not verify_password(password, candidate_data['password_hash']):
            return {'success': False, 'error': 'Invalid email or password'}
        
        logger.info(f"Authentication successful for candidate {email}")
        return {'success': True, 'candidate': candidate_data}
        
    except ClientError as e:
        error_msg = f"DynamoDB error: {e.response['Error']['Message']}"
        logger.error(error_msg)
        return {'success': False, 'error': error_msg}
    except Exception as e:
        error_msg = f"Unexpected error authenticating candidate: {str(e)}"
        logger.error(error_msg)
        return {'success': False, 'error': error_msg}


def verify_password(password, stored_hash):
    """Verify password against stored hash"""
    salt = os.getenv('PASSWORD_SALT', 'jobsyme_secure_salt_2025')
    salted_password = salt + password
    computed_hash = hashlib.sha256(salted_password.encode()).hexdigest()
    return computed_hash == stored_hash


def generate_jwt_token(candidate_data):
    """Generate JWT token for authenticated user"""
    
    try:
        # Get JWT secret from AWS Secrets Manager
        jwt_secret = get_jwt_secret()
        if not jwt_secret:
            return {'success': False, 'error': 'JWT secret not configured'}
        
        # Token expiration (2 weeks)
        expires_in_seconds = int(os.getenv('JWT_EXPIRES_IN_SECONDS', '1209600'))  # 2 weeks (14 days)
        expiration = datetime.utcnow() + timedelta(seconds=expires_in_seconds)
        
        # JWT payload
        payload = {
            'user_id': candidate_data['user_id'],
            'email': candidate_data['email'],
            'user_type': 'candidate',
            'first_name': candidate_data['first_name'],
            'last_name': candidate_data['last_name'],
            'email_verified': candidate_data['email_verified'],
            'iat': datetime.utcnow(),
            'exp': expiration
        }
        
        # Generate JWT token
        token = jwt.encode(payload, jwt_secret, algorithm='HS256')
        
        logger.info(f"JWT token generated for candidate {candidate_data['email']}")
        return {
            'success': True, 
            'token': token,
            'expires_in': expires_in_seconds
        }
        
    except Exception as e:
        error_msg = f"Error generating JWT token: {str(e)}"
        logger.error(error_msg)
        return {'success': False, 'error': error_msg}


def get_jwt_secret():
    """Get JWT secret from AWS Secrets Manager"""
    
    try:
        secret_name = os.getenv('JWT_SECRET_NAME')
        if not secret_name:
            return None
        
        response = secrets_client.get_secret_value(SecretId=secret_name)
        secret_data = json.loads(response['SecretString'])
        return secret_data.get('jwt_secret')
        
    except Exception as e:
        logger.error(f"Error retrieving JWT secret: {str(e)}")
        return None


def update_last_login(user_id):
    """Update candidate's last login timestamp"""
    
    try:
        table_name = os.getenv('CANDIDATES_TABLE_NAME')
        if not table_name:
            return {'success': False, 'error': 'Candidates table not configured'}
        
        # Update last login timestamp using user_id (primary key)
        dynamodb.update_item(
            TableName=table_name,
            Key={'user_id': {'S': user_id}},
            UpdateExpression='SET last_login_at = :login_time, updated_at = :updated_at',
            ExpressionAttributeValues={
                ':login_time': {'S': datetime.utcnow().isoformat() + 'Z'},
                ':updated_at': {'S': datetime.utcnow().isoformat() + 'Z'}
            }
        )
        
        logger.info(f"Last login updated for candidate {user_id}")
        return {'success': True}
        
    except ClientError as e:
        error_msg = f"DynamoDB error: {e.response['Error']['Message']}"
        logger.error(error_msg)
        return {'success': False, 'error': error_msg}
    except Exception as e:
        error_msg = f"Unexpected error updating last login: {str(e)}"
        logger.error(error_msg)
        return {'success': False, 'error': error_msg}


def error_response(status_code, message, headers):
    """Generate standardized error response"""
    return {
        'statusCode': status_code,
        'headers': headers,
        'body': json.dumps({
            'error': message,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
    }
