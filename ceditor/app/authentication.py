import jwt
import os
import requests
from base64 import b64decode
from cryptography.hazmat.primitives import serialization
from fastapi import Depends, HTTPException, Request
from jwt import PyJWKClient

url = os.getenv("KEYCLOAK_URL_REALM")
client_id = os.getenv("KEYCLOAK_CLIENT_ID")

jwks_client = PyJWKClient(url)

def decode_token(jwtoken):
    keycloak_realm = requests.get(url)
    keycloak_realm.raise_for_status()
    key_der_base64 = keycloak_realm.json()["public_key"]
    key_der = b64decode(key_der_base64.encode())
    public_key = serialization.load_der_public_key(key_der)
    payload = jwt.decode(jwtoken, public_key, algorithms=["RS256"], 
                         audience=client_id)
    return payload

def get_token_in_cookie(request):
    try:
        return request.cookies.get("auth_token")
    except:
        return None


def get_token_in_header(request):
    try:
        return request.headers.get('authorization').replace("Bearer ", "")
    except:
        return None


def get_current_token(
    request: Request
) -> dict:
    state = request.state._state
    return state["token"]


def get_current_user(
    request: Request,
) -> dict:
    try:
        token = get_token_in_cookie(request) or get_token_in_header(request)
        # gets user_data from state (see AuthMiddleware)
        if token:
            user_data = decode_token(token)
            return user_data
        return None
    except Exception as e:
        print(str(e))
        return None


def get_current_active_user(
    current_user: dict = Depends(get_current_user),
) -> dict:
    # calls get_current_user, and if nothing is returned, raises Not authenticated exception
    if not current_user:
        raise HTTPException(status_code=403, detail="Not authenticated")
    return current_user
