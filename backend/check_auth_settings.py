import httpx
from app.config import settings

def check_auth_methods():
    url = f"{settings.SUPABASE_URL.rstrip('/')}/auth/v1/settings"
    headers = {"apikey": settings.SUPABASE_ANON_KEY}
    resp = httpx.get(url, headers=headers)
    print("Auth settings status:", resp.status_code)
    if resp.status_code == 200:
        print("Auth settings:", resp.json())

if __name__ == "__main__":
    check_auth_methods()
