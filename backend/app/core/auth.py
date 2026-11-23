import os
from typing import Optional, Dict, Any
from fastapi import Request, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import jwt
import httpx
from app.config import settings
from app.core.logging import logger

security_scheme = HTTPBearer(auto_error=False)

class UserIdentity(BaseModel):
    user_id: str
    email: Optional[str] = None
    role: str = "authenticated"
    is_demo: bool = False

def is_preview_or_dev() -> bool:
    """Returns True if running in a Vercel preview or development/test environment."""
    vercel_env = os.getenv("VERCEL_ENV", "").lower()
    env_name = settings.ENVIRONMENT.lower()
    if vercel_env == "production" or env_name == "production":
        return False
    return (
        settings.ALLOW_DEMO_AUTH
        or vercel_env in ["preview", "development"]
        or env_name in ["development", "dev", "test", "preview"]
    )

async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme)
) -> UserIdentity:
    """
    Validates Supabase authentication tokens.
    Supports:
    1. Demo tokens in preview / development environments or when ALLOW_DEMO_AUTH is True.
    2. Local HS256 JWT signature verification when SUPABASE_JWT_SECRET is configured.
    3. Supabase Auth API verification via httpx (official /auth/v1/user endpoint) for HS256/ES256/RS256.
    4. Structured diagnostic logging on 401 rejection without exposing credentials.
    """
    allow_demo = is_preview_or_dev()
    
    token: Optional[str] = None
    if credentials and credentials.credentials:
        token = credentials.credentials.strip()
    else:
        # Fallback check directly in request headers for reverse proxy compatibility
        auth_header = request.headers.get("authorization", "") or request.headers.get("Authorization", "")
        if auth_header and auth_header.strip().lower().startswith("bearer "):
            token = auth_header.strip()[7:].strip()
    
    if not token:
        if allow_demo:
            logger.info("Authenticated unauthenticated guest/demo analyst session (preview/dev mode).")
            return UserIdentity(
                user_id="00000000-0000-0000-0000-000000002026",
                email="analyst@malguard.ai",
                role="analyst",
                is_demo=True
            )
        logger.warning(
            "Authentication rejected: Missing Authorization header (environment=%s, vercel_env=%s)",
            settings.ENVIRONMENT,
            os.getenv("VERCEL_ENV", "unset")
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header with Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    is_demo_token = token in ["demo-token", "demo-analyst-uuid-2026"] or token.startswith("demo_")
    
    # 1. Demo Mode Check
    if is_demo_token:
        if allow_demo:
            logger.info("Authenticated demo analyst session (preview/dev mode).")
            return UserIdentity(
                user_id="00000000-0000-0000-0000-000000002026",
                email="analyst@malguard.ai",
                role="analyst",
                is_demo=True
            )
        logger.warning("Rejected demo token in production environment.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Demo authentication tokens are disabled in production. Please sign in with Supabase.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Parse unverified JWT header to detect algorithm safely
    token_alg = "HS256"
    try:
        header = jwt.get_unverified_header(token)
        token_alg = header.get("alg", "HS256")
    except Exception:
        token_alg = "unknown"
    
    # 2. Local JWT Secret Verification (for HS256 tokens when secret is configured)
    if settings.SUPABASE_JWT_SECRET and token_alg == "HS256":
        try:
            payload = jwt.decode(
                token,
                settings.SUPABASE_JWT_SECRET,
                algorithms=["HS256"],
                audience="authenticated"
            )
            user_id = payload.get("sub")
            if not user_id:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token claims: 'sub' (user_id) missing.",
                )
            return UserIdentity(
                user_id=user_id,
                email=payload.get("email"),
                role=payload.get("role", "authenticated"),
                is_demo=False
            )
        except jwt.ExpiredSignatureError:
            logger.warning("Authentication token has expired.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication token has expired. Please refresh your session.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except jwt.PyJWTError as e:
            logger.info("Local HS256 JWT decode unsuccessful (%s); falling through to Supabase Auth API", type(e).__name__)
            # Fall through to remote validation if secret failed
            
    # 3. Supabase Auth API Verification (Cloud Endpoint)
    if settings.SUPABASE_URL:
        auth_url = f"{settings.SUPABASE_URL.rstrip('/')}/auth/v1/user"
        headers = {
            "Authorization": f"Bearer {token}",
            "apikey": settings.SUPABASE_ANON_KEY or ""
        }
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                res = await client.get(auth_url, headers=headers)
                if res.status_code == 200:
                    user_data = res.json()
                    user_id = user_data.get("id")
                    if user_id:
                        return UserIdentity(
                            user_id=user_id,
                            email=user_data.get("email"),
                            role=user_data.get("role", "authenticated"),
                            is_demo=False
                        )
                elif res.status_code == 401:
                    logger.warning("Supabase Auth API rejected user token with HTTP 401")
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Session expired or invalid Supabase authentication token.",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
        except httpx.RequestError as e:
            logger.error(f"Failed to communicate with Supabase Auth: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Unable to verify authentication session with Supabase identity provider.",
            )

    # 4. Fallback: Parse unverified claims in dev/preview mode ONLY if allow_demo
    if allow_demo:
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
            sub = unverified.get("sub")
            if sub:
                logger.info(f"Accepted unverified development token for user {sub} in non-production mode")
                return UserIdentity(
                    user_id=sub,
                    email=unverified.get("email"),
                    role=unverified.get("role", "authenticated"),
                    is_demo=False
                )
        except Exception:
            pass

    # Safe structured rejection logging
    logger.warning(
        "Authentication failure: token_type=%s, token_alg=%s, supabase_url_set=%s, jwt_secret_set=%s, allow_demo=%s, env=%s, vercel_env=%s",
        "demo" if is_demo_token else "jwt" if "." in token else "opaque",
        token_alg,
        bool(settings.SUPABASE_URL),
        bool(settings.SUPABASE_JWT_SECRET),
        allow_demo,
        settings.ENVIRONMENT,
        os.getenv("VERCEL_ENV", "unset")
    )

    if not settings.SUPABASE_URL and not settings.SUPABASE_JWT_SECRET:
        rejection_detail = "Authentication unconfigured on server: SUPABASE_URL and SUPABASE_JWT_SECRET are not set."
    else:
        rejection_detail = "Invalid authentication token. Unable to verify user session."

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=rejection_detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


