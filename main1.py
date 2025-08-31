"""
FastAPI Secure Auth Example
==========================

This API demonstrates a secure authentication flow using:
- IP-based HMAC tokens for initial session validation
- JWT tokens bound to client IP for session management
- Rate limiting with slowapi
- Role-based access (admin/user)
- Password reset demo

Endpoints:
----------
1. GET /           : Returns a public IP, client IP, and an IP-based token
2. POST /login     : Accepts username, password, role, and IP token; returns JWT if valid
3. POST /forgotpassword : Accepts username and IP token; returns password reset message
4. GET /dashboard  : Protected endpoint, requires JWT (returns username, role, and IP)

Testing:
--------
- All endpoints return the client IP for easy testing.
- Use the returned token from `/` as the `token` field in `/login` and `/forgotpassword`.
- Use the returned JWT as a Bearer token for `/dashboard`.

Security Notes:
---------------
- In production, use a real user database and hashed passwords.
- JWTs are bound to the client IP for extra security.
- Rate limits are applied to all endpoints.
"""

from fastapi import FastAPI, Request, HTTPException, status, Depends, Header, Query
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.openapi.docs import get_swagger_ui_html
import httpx
import os
import time
from jose import jwt, JWTError
import hmac
import hashlib
from datetime import datetime, timedelta
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel, Field
import ipaddress
from typing import Optional
from database import router as db_router, SessionLocal, employees
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from collections import defaultdict

app = FastAPI(
    title="FastAPI Secure Auth Example",
    description="""
This API demonstrates a secure authentication flow using:
- IP-based HMAC tokens for initial session validation
- JWT tokens bound to client IP for session management
- Rate limiting with slowapi
- Role-based access (admin/user)
- Password reset demo
""",
    version="1.0.0"
)

# Include the database router
app.include_router(db_router)

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security configurations
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
JWT_SECRET = os.getenv("JWT_SECRET", "jwt-secret-key-here")
INITIAL_TOKEN_EXPIRY = 300  # 5 minutes
JWT_EXPIRY_MINUTES = 30

# OAuth2 scheme for JWT tokens
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

class LoginRequest(BaseModel):
    username: str = Field(..., description="Your username")
    password: str = Field(..., description="Your password")
    token: str = Field(..., description="IP-based token from `/` endpoint")
    ip: str = Field(..., description="Your client IP (should match token)")

class LoginResponse(BaseModel):
    message: str
    role: str
    access_token: str
    token_type: str
    ip: str

class ForgotPasswordResponse(BaseModel):
    message: str
    ip: str

class DashboardResponse(BaseModel):
    message: str
    role: str
    ip: str

def generate_ip_based_token(ip: str) -> str:
    """Generate HMAC-based token using client IP and timestamp"""
    timestamp = str(int(time.time()))
    message = f"{ip}|{timestamp}".encode()
    return hmac.new(SECRET_KEY.encode(), message, hashlib.sha256).hexdigest() + "|" + timestamp

def validate_ip_token(token: str, ip: str) -> bool:
    """Validate IP-based token with timestamp and IP check"""
    try:
        token_signature, token_timestamp = token.split("|")
        if time.time() - int(token_timestamp) > INITIAL_TOKEN_EXPIRY:
            return False  # Token expired
            
        expected_message = f"{ip}|{token_timestamp}".encode()
        expected_signature = hmac.new(
            SECRET_KEY.encode(), 
            expected_message, 
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(token_signature, expected_signature)
    except Exception:
        return False

def generate_jwt(username: str, emp_id:str,role: str, ip: str) -> str:
    """Generate JWT token with username, role, and bound to IP"""
    payload = {
        "sub": username,
        "role": role,
        "emp_id": emp_id,
        "ip": ip,
        "issued":"user based token",
        "exp": datetime.utcnow() + timedelta(minutes=JWT_EXPIRY_MINUTES)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def validate_jwt(token: str, ip: str) -> dict:
    """Validate JWT token and check IP binding and user existence"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        # Check if token is bound to the same IP
        if payload.get("ip") != ip:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session invalidated by IP change"
            )
        # User validation: only allow admin/user
        if payload.get("role") not in ["admin", "user"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or unauthorized"
            )
        # --- NEW: Validate emp_id with DB ---
        session = SessionLocal()
        try:
            # Fetch user by username (sub) or emp_id from JWT
            query = employees.select().where(employees.c.username == payload.get("sub"))
            result = session.execute(query).mappings().first()
            if not result:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found in database"
                )
            db_empid = result["empid"]
            jwt_empid = payload.get("emp_id")
            if str(db_empid) != str(jwt_empid):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token emp_id does not match database empid"
                )
        finally:
            session.close()
        return payload

    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )



async def get_current_user(request: Request, token: str = Depends(oauth2_scheme)):
    """Dependency to get current user from JWT with IP validation"""
    client_ip = get_remote_address(request)
    payload = validate_jwt(token, client_ip)
    return payload

@app.get(
    "/",
    response_model=dict,
    summary="Get initial IP-based token",
    description="Returns a public IP, client IP, and an IP-based token for session initiation."
)
@limiter.limit("5/minute")
async def initial(request: Request, message: str = "Hello! your initial token generated or invalid ip or invalid token  "):
    error_msg = request.cookies.get("error_msg")
    client_ip = get_remote_address(request)
    token = generate_ip_based_token(client_ip)
    return {
        "message": message,
        "token": token,
        "client_ip": client_ip,
        "error": error_msg
    }

@app.post(
    "/login",
    response_model=LoginResponse,
    summary="Login and get JWT",
    description="Login with username, password, and IP token. Returns JWT if valid."
)
@limiter.limit("5/minute")
async def login(request: Request, form_data: LoginRequest):
    """Login endpoint with strict token validation. Returns JWT and your IP for testing."""
    if not validate_ip_token(form_data.token, form_data.ip):
        response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(key="error_msg", value="Invalid IP or token", max_age=5)
        return response

    # --- Check user in PostgreSQL ---
    session = SessionLocal()
    try:
        query = employees.select().where(employees.c.username == form_data.username)
        result = session.execute(query).mappings().first()
        if not result:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        # Password check (plain for demo; use hashing in production!)
        if form_data.password != result["password_hash"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid password"
            )
        role = result["role"]
        jwt_token = generate_jwt(
            form_data.username,
            result["empid"],
            role,
            form_data.ip
        )
        return {
            "message": f"Welcome {role} {form_data.username}!",
            "role": role,
            "access_token": jwt_token,
            "token_type": "bearer",
            "ip": form_data.ip
        }
    finally:
        session.close()

@app.post(
    "/forgotpassword",
    response_model=ForgotPasswordResponse,
    summary="Forgot password (demo)",
    description="Request password reset (demo). Checks user in DB."
)
@limiter.limit("2/minute")
async def forgot_password(
    request: Request,
    username: str = Query(..., description="Your username"),
    token: str = Query(..., description="IP-based token from `/` endpoint"),
    ip: str = Query(..., description="Your client IP (should match token)")
):
    if not validate_ip_token(token, ip):
        response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(key="error_msg", value="Invalid IP or token", max_age=5)
        return response

    # --- Check user in PostgreSQL ---
    session = SessionLocal()
    try:
        query = employees.select().where(employees.c.username == username)
        result = session.execute(query).mappings().first()
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Username not found"
            )
        return {"message": "Password reset email sent", "ip": ip}
    finally:
        session.close()

@app.get(
    "/dashboard",
    response_model=DashboardResponse,
    summary="Get dashboard (protected)",
    description="Protected endpoint. Requires JWT Bearer token."
)
async def dashboard(request: Request, authorization: str = Header(None)):
    """Example protected endpoint. Returns your username, role, and IP for testing."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization.replace("Bearer ", "")
    client_ip = get_remote_address(request)
    user = validate_jwt(token, client_ip)
    return {
        "message": f"Welcome to your dashboard, {user['sub']}!",
        "role": user["role"],
        "ip": user["ip"]
    }

# Security middleware for IP filtering
@app.middleware("http")
async def ip_filter_middleware(request: Request, call_next):
    client_ip = get_remote_address(request)
    
    
    response = await call_next(request)
    return response

# --- IP throttling state ---
IP_REQUEST_LIMIT = 15
IP_BLOCK_TIME = 60 * 60  # Block for 1 hour (adjust as needed)
ip_request_counts = defaultdict(lambda: {"count": 0, "first_seen": time.time(), "blocked_until": 0})

class IPThrottleMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        client_ip = get_remote_address(request)
        now = time.time()
        ip_state = ip_request_counts[client_ip]

        # Unblock if block time expired
        if ip_state["blocked_until"] and now > ip_state["blocked_until"]:
            ip_state["count"] = 0
            ip_state["first_seen"] = now
            ip_state["blocked_until"] = 0

        # Block if currently blocked
        if ip_state["blocked_until"] and now <= ip_state["blocked_until"]:
            return JSONResponse(
                status_code=429,
                content={"detail": f"IP {client_ip} blocked due to too many requests. Try again later."}
            )

        # Count request
        ip_state["count"] += 1

        # If over limit, block IP and (optionally) deactivate user
        if ip_state["count"] > IP_REQUEST_LIMIT:
            ip_state["blocked_until"] = now + IP_BLOCK_TIME

            # Try to deactivate user if username is present in request
            try:
                data = await request.json()
                username = data.get("username")
            except Exception:
                username = None

            if username:
                # Deactivate user in DB
                session = SessionLocal()
                try:
                    query = employees.update().where(employees.c.username == username).values(is_active=False)
                    session.execute(query)
                    session.commit()
                finally:
                    session.close()

            return JSONResponse(
                status_code=429,
                content={"detail": f"IP {client_ip} blocked due to too many requests. User deactivated if present."}
            )

        return await call_next(request)

# Add the middleware to your app
app.add_middleware(IPThrottleMiddleware)

@app.get("/docs", include_in_schema=False)
def custom_swagger_ui_html():
    return get_swagger_ui_html(openapi_url=app.openapi_url, title="API Docs")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="10.130.140.16", port=8000)