"""
=============================================================================
Module: main.py
Project: Production-Grade Google OAuth 2.0 Backend Service (Python / FastAPI)
Framework: FastAPI, google-auth, PyJWT, Pydantic v2, SlowAPI
Architecture: Security-Hardened Token Verification & Custom Session Management
=============================================================================

SECURITY ARCHITECTURAL PRINCIPLES:
1. Cryptographic ID Token Verification: Validates Google JWT signatures via
   Google's official `google.oauth2.id_token` module, which automatically
   caches and rotates Google public certificates (JWKS).
2. Audience & Issuer Integrity: Enforces audience (`aud`) matching GOOGLE_CLIENT_ID
   and issuer (`iss`) matching accounts.google.com or https://accounts.google.com.
3. Identity Invariance: Uses Google's immutable user subject identifier (`sub`)
   instead of mutable email addresses for primary account binding.
4. Token Segregation: Translates verified Google ID Tokens into custom signed
   internal application JWT session tokens. Never exposes raw external tokens.
5. Defense-in-Depth: Rate-limiting via SlowAPI, strict CORS origin controls,
   HTTP-only cookie protection, and security headers.
=============================================================================
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import jwt
from dotenv import load_dotenv
from fastapi import Cookie, Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from google.auth.exceptions import GoogleAuthError
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
from pydantic import BaseModel, Field, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware

# -----------------------------------------------------------------------------
# 1. Environment Loading & Logging Configuration
# -----------------------------------------------------------------------------
load_dotenv()

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("GoogleAuthBackend")

# -----------------------------------------------------------------------------
# 2. Configuration & Startup Validation
# -----------------------------------------------------------------------------
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
PORT = int(os.getenv("PORT", "5000"))
HOST = os.getenv("HOST", "0.0.0.0")

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
RESTRICTED_HOSTED_DOMAIN = os.getenv("RESTRICTED_HOSTED_DOMAIN", "").strip() or None

JWT_SECRET = os.getenv("JWT_SECRET", "")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRES_MINUTES = int(os.getenv("JWT_EXPIRES_MINUTES", "60"))

ALLOWED_ORIGIN = os.getenv("ALLOWED_ORIGIN", "http://localhost:4200")
RATE_LIMIT_AUTH = os.getenv("RATE_LIMIT_AUTH", "20/minute")
RATE_LIMIT_GLOBAL = os.getenv("RATE_LIMIT_GLOBAL", "100/minute")

if not GOOGLE_CLIENT_ID or "your-google-client-id" in GOOGLE_CLIENT_ID:
    logger.critical("GOOGLE_CLIENT_ID is not configured in .env. Authentication cannot proceed.")
    if ENVIRONMENT == "production":
        sys.exit(1)

if not JWT_SECRET or ("super_secret" in JWT_SECRET and ENVIRONMENT == "production"):
    logger.critical("Insecure default JWT_SECRET detected in production environment!")
    if ENVIRONMENT == "production":
        sys.exit(1)

# Pre-instantiate Google HTTP transport request adapter (thread-safe, caches certs)
google_transport_request = google_requests.Request()

# Rate Limiter setup
limiter = Limiter(key_func=get_remote_address, default_limits=[RATE_LIMIT_GLOBAL])

# -----------------------------------------------------------------------------
# 3. Pydantic Request & Response Schemas
# -----------------------------------------------------------------------------
class GoogleAuthRequest(BaseModel):
    """Payload sent by frontend clients (e.g., Angular GIS One Tap / Sign-In Button)."""
    credential: Optional[str] = Field(default=None, description="Google ID Token emitted by GIS")
    idToken: Optional[str] = Field(default=None, description="Alternative key for Google ID Token")

    @field_validator("credential", "idToken")
    @classmethod
    def check_non_empty(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not v.strip():
            raise ValueError("Token must not be empty or whitespace.")
        return v

    def resolve_token(self) -> str:
        token = self.credential or self.idToken
        if not token:
            raise ValueError("Request body must contain either 'credential' or 'idToken'.")
        return token.strip()


class UserProfile(BaseModel):
    """Sanitized identity claims for internal session usage."""
    sub: str = Field(description="Google immutable unique subject ID")
    email: str = Field(description="Verified user email address")
    name: str = Field(description="User display name")
    picture: str = Field(default="", description="Avatar image URL")
    given_name: Optional[str] = Field(default="", description="First name")
    family_name: Optional[str] = Field(default="", description="Last name")


class AuthResponse(BaseModel):
    """Structured response returned upon successful authentication."""
    success: bool = True
    message: str = "Google authentication successful."
    token: str = Field(description="Custom signed application session JWT")
    user: UserProfile
    expiresIn: str = "1h"


# -----------------------------------------------------------------------------
# 4. Security Headers Middleware (ASGI)
# -----------------------------------------------------------------------------
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Applies defense-in-depth HTTP security headers to all responses."""
    async def dispatch(self, request: Request, call_next: Any) -> Response:
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if ENVIRONMENT == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


# -----------------------------------------------------------------------------
# 5. FastAPI Application Initialization
# -----------------------------------------------------------------------------
app = FastAPI(
    title="Google OAuth 2.0 Backend Service",
    description="Production-Grade Google ID Token Verification & JWT Session Management",
    version="1.0.0",
)

# Register rate limiter exception handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Register security headers
app.add_middleware(SecurityHeadersMiddleware)

# Register CORS policy
app.add_middleware(
    CORSMiddleware,
    allow_origins=[ALLOWED_ORIGIN],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
)

# Optional Bearer extractor (does not auto-error to allow cookie fallback)
bearer_security = HTTPBearer(auto_error=False)


# -----------------------------------------------------------------------------
# 6. Session Token Helpers
# -----------------------------------------------------------------------------
def generate_session_token(user: UserProfile) -> str:
    """
    Mints an internal custom signed JWT session token.
    
    Contains sanitized non-sensitive claims, signed with HMAC-SHA256.
    """
    now = datetime.now(timezone.utc)
    expiration = now + timedelta(minutes=JWT_EXPIRES_MINUTES)

    claims: Dict[str, Any] = {
        "sub": user.sub,
        "email": user.email,
        "name": user.name,
        "picture": user.picture,
        "roles": ["user"],
        "iat": int(now.timestamp()),
        "exp": int(expiration.timestamp()),
        "iss": "google-oauth-backend",
        "aud": "angular-client",
    }

    return jwt.encode(claims, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_session_token(token: str) -> UserProfile:
    """Decodes and validates the internal custom session JWT."""
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            issuer="google-oauth-backend",
            audience="angular-client",
        )
        return UserProfile(
            sub=payload["sub"],
            email=payload["email"],
            name=payload.get("name", "User"),
            picture=payload.get("picture", ""),
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "TOKEN_EXPIRED", "message": "Authentication session expired."},
        )
    except jwt.InvalidTokenError as err:
        logger.warning("Session token validation failed: %s", err)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "INVALID_TOKEN", "message": "Authentication token verification failed."},
        )


async def get_current_user(
    auth_header: Optional[HTTPAuthorizationCredentials] = Depends(bearer_security),
    session_token: Optional[str] = Cookie(default=None),
) -> UserProfile:
    """
    FastAPI Dependency: Extracts and verifies session token from either:
    1. HTTP Header: 'Authorization: Bearer <token>'
    2. HttpOnly Cookie: 'session_token=<token>'
    """
    token: Optional[str] = None

    if auth_header and auth_header.credentials:
        token = auth_header.credentials.strip()
    elif session_token:
        token = session_token.strip()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "UNAUTHORIZED", "message": "No valid authentication token provided."},
        )

    return verify_session_token(token)


# -----------------------------------------------------------------------------
# 7. Routes & Endpoints
# -----------------------------------------------------------------------------
@app.get("/health", tags=["System"])
async def health_check() -> Dict[str, Any]:
    """Liveness probe used by Cloud Run, Kubernetes, and load balancers."""
    return {
        "status": "HEALTHY",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "environment": ENVIRONMENT,
    }


@app.post("/api/auth/google", response_model=AuthResponse, tags=["Authentication"])
@limiter.limit(RATE_LIMIT_AUTH)
async def authenticate_google(
    request: Request,
    payload_body: GoogleAuthRequest,
    response: Response,
) -> AuthResponse:
    """
    Primary Authentication Endpoint:
    
    1. Receives raw Google ID Token (credential) from Angular GIS client.
    2. Cryptographically validates signature via Google's official JWKS public certs.
    3. Enforces claims: aud, iss, email_verified, and optional hosted domain (hd).
    4. Generates an internal custom application JWT.
    5. Sets an HttpOnly, Secure session cookie and returns JSON token payload.
    """
    try:
        raw_token = payload_body.resolve_token()
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "BAD_REQUEST", "message": str(err)},
        )

    # Cryptographic verification via official google-auth library
    try:
        google_payload = id_token.verify_oauth2_token(
            id_token=raw_token,
            request=google_transport_request,
            audience=GOOGLE_CLIENT_ID,
        )
    except (ValueError, GoogleAuthError) as verify_err:
        logger.warning("[SECURITY] Google ID Token verification rejected: %s", verify_err)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "INVALID_GOOGLE_TOKEN",
                "message": "Google ID Token signature verification failed or token is expired.",
            },
        )

    # Security Check 1: Issuer validation
    valid_issuers = ["accounts.google.com", "https://accounts.google.com"]
    if google_payload.get("iss") not in valid_issuers:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "INVALID_ISSUER", "message": f"Untrusted token issuer: {google_payload.get('iss')}"},
        )

    # Security Check 2: Email verification check
    if not google_payload.get("email_verified", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "EMAIL_NOT_VERIFIED", "message": "Google account email address is not verified."},
        )

    # Security Check 3: Google Workspace Hosted Domain restriction (Optional)
    if RESTRICTED_HOSTED_DOMAIN and google_payload.get("hd") != RESTRICTED_HOSTED_DOMAIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "DOMAIN_RESTRICTED",
                "message": f"Access restricted to accounts belonging to '{RESTRICTED_HOSTED_DOMAIN}'.",
            },
        )

    # Extract sanitized claims
    user = UserProfile(
        sub=google_payload["sub"],
        email=google_payload["email"],
        name=google_payload.get("name", "Google User"),
        picture=google_payload.get("picture", ""),
        given_name=google_payload.get("given_name", ""),
        family_name=google_payload.get("family_name", ""),
    )

    # Mint internal session JWT
    session_token = generate_session_token(user)

    # Set secure HttpOnly cookie (defense-in-depth against XSS)
    response.set_cookie(
        key="session_token",
        value=session_token,
        max_age=JWT_EXPIRES_MINUTES * 60,
        httponly=True,
        secure=(ENVIRONMENT == "production"),
        samesite="lax",
    )

    logger.info("Successfully authenticated Google user: %s (sub: %s)", user.email, user.sub)

    return AuthResponse(
        success=True,
        message="Google authentication successful.",
        token=session_token,
        user=user,
        expiresIn=f"{JWT_EXPIRES_MINUTES}m",
    )


@app.get("/api/auth/me", tags=["Authentication"])
async def get_current_session(current_user: UserProfile = Depends(get_current_user)) -> Dict[str, Any]:
    """Returns profile for currently authenticated session."""
    return {"authenticated": True, "user": current_user}


@app.post("/api/auth/logout", tags=["Authentication"])
async def logout(response: Response) -> Dict[str, Any]:
    """Destroys server-side session cookie."""
    response.delete_cookie(key="session_token")
    return {"success": True, "message": "Session terminated successfully."}


@app.get("/api/protected/resource", tags=["Protected"])
async def access_protected_resource(current_user: UserProfile = Depends(get_current_user)) -> Dict[str, Any]:
    """Demonstrates role-protected enterprise data access."""
    return {
        "message": "Authorized access to confidential enterprise resource.",
        "authorizedUser": current_user.email,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "clearance": "Verified Google OAuth 2.0 Identity",
    }


# -----------------------------------------------------------------------------
# 8. Entrypoint Execution
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    print("=" * 80)
    print(" Google OAuth 2.0 Python Backend (FastAPI)")
    print(f" Listening on:       http://{HOST}:{PORT}")
    print(f" Environment:        {ENVIRONMENT}")
    print(f" Allowed Origin:     {ALLOWED_ORIGIN}")
    print(f" Client ID Prefix:   {GOOGLE_CLIENT_ID[:16]}..." if GOOGLE_CLIENT_ID else " [!] Unset")
    print("=" * 80)

    uvicorn.run("main:app", host=HOST, port=PORT, reload=(ENVIRONMENT == "development"))
