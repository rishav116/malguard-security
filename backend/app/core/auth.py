from typing import Optional, Dict, Any
from fastapi import Depends, HTTPException, status
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

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme)
) -> UserIdentity:
    """
    Validates Supabase authentication tokens.
    Supports:
    1. Demo tokens in development when ALLOW_DEMO_AUTH is True.
    2. Supabase Auth API verification via httpx (official Supabase /auth/v1/user endpoint).
    3. Server-side JWT signature verification when SUPABASE_JWT_SECRET is configured.
    """
    if not credentials or not credentials.credentials:
        if settings.ALLOW_DEMO_AUTH:
            logger.info("Authenticated unauthenticated guest/demo analyst session.")
            return UserIdentity(
                user_id="demo-analyst-uuid-2026",
                email="analyst@malguard.ai",
                role="analyst",
                is_demo=True
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header with Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = credentials.credentials.strip()
    
    # 1. Demo Mode Check
    if settings.ALLOW_DEMO_AUTH and (token in ["demo-token", "demo-analyst-uuid-2026"] or token.startswith("demo_")):
        logger.info("Authenticated demo analyst session.")
        return UserIdentity(
            user_id="demo-analyst-uuid-2026",
            email="analyst@malguard.ai",
            role="analyst",
            is_demo=True
        )
    
    # 2. Local JWT Secret Verification (if configured)
    if settings.SUPABASE_JWT_SECRET:
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
        except jwt.PyJWTError as e:
            logger.warning(f"Local JWT decode failed: {e}")
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
                    logger.warning(f"Supabase Auth rejected token: {res.text}")
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

    # 4. Fallback: Parse unverified claims in dev mode ONLY if ALLOW_DEMO_AUTH
    if settings.ALLOW_DEMO_AUTH:
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
            sub = unverified.get("sub")
            if sub:
                logger.info(f"Accepted unverified development token for user {sub}")
                return UserIdentity(
                    user_id=sub,
                    email=unverified.get("email"),
                    role=unverified.get("role", "authenticated"),
                    is_demo=False
                )
        except Exception:
            pass

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication token. Unable to verify user session.",
        headers={"WWW-Authenticate": "Bearer"},
    )

