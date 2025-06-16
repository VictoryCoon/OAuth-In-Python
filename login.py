import os
import httpx
import base64
import hashlib
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from urllib.parse import urlencode
from dotenv import load_dotenv

load_dotenv()

CLIENT_ID=os.getenv('CLIENT_ID')
CLIENT_SECRET=os.getenv('CLIENT_SECRET')
AUTHORIZATION_ENDPOINT=os.getenv('AUTHORIZATION_ENDPOINT')
TOKEN_ENDPOINT=os.getenv('TOKEN_ENDPOINT')
REDIRECT_URI=os.getenv('REDIRECT_URI')
HOST=os.getenv('HOST')

app = APIRouter()
templates = Jinja2Templates(directory="views")

authorization_codes = {}

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

@app.get("/login")
async def login():
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid profile email",
        "code_challenge": "dummy_challenge",  # 임시: 실제로는 PKCE 구현 필요
        "code_challenge_method": "plain"
    }
    url = f"{AUTHORIZATION_ENDPOINT}?{urlencode(params)}"
    return RedirectResponse(url)

@app.get("/callback")
async def callback(request:Request):
    code = request.query_params.get("code")
    async with httpx.AsyncClient() as client:
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code_verifier": "dummy_challenge"
        }
        header = {"Content-Type":"application/x-www-form-urlencoded"}
        token_response = await client.post(TOKEN_ENDPOINT,data=data,headers=header)

    return templates.TemplateResponse("login.html", {"request": request,"code":code,"header":header,"data":data,"token":token_response.json()})


@app.post("/token")
async def token(request: Request):
    form = await request.form()
    code = form.get("code")
    code_verifier = form.get("code_verifier")

    if code not in authorization_codes:
        raise HTTPException(status_code=400, detail="Invalid authorization code")

    stored = authorization_codes[code]
    method = stored.get("method")
    expected_challenge = stored.get("code_challenge")

    if method == "S256":
        hashed = hashlib.sha256(code_verifier.encode()).digest()
        computed_challenge = base64url_encode(hashed)
    elif method == "plain":
        computed_challenge = code_verifier
    else:
        raise HTTPException(status_code=400, detail="Unsupported challenge method")

    if computed_challenge != expected_challenge:
        raise HTTPException(status_code=400, detail="PKCE verification failed")

    # ✅ PKCE 통과 — 토큰 발급 로직으로 진행
    return {
        "access_token": "dummy_access_token",
        "token_type": "Bearer",
        "id_token": "dummy_id_token"
    }


@app.get("/.well-known/openid-configuration")
async def openid_config():
    return {
        "issuer": "https://astalgia.com",
        "authorization_endpoint": f"{HOST}/auth",
        "token_endpoint": f"{HOST}/token",
        "userinfo_endpoint": f"{HOST}/userinfo",
        "jwks_uri": f"{HOST}/.well-known/jwks.json",
        "response_types_supported": ["code", "token", "id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "claims_supported": ["sub", "name", "email", "picture"],
        "code_challenge_methods_supported": ["S256"]
    }

@app.get("/.well-known/jwks.json")
async def jwks():
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": "your-key-id",
                "alg": "RS256",
                "n": "base64url-encoded-modulus",
                "e": "AQAB"
            }
        ]
    }
