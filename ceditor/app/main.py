import json
import os
import random
import string
import time
import uuid
from typing import Optional

import requests
from fastapi import (
    APIRouter,
    Body,
    Cookie,
    Depends,
    FastAPI,
    HTTPException,
    Request,
    status,
)
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.cors import CORSMiddleware
from starlette.status import HTTP_422_UNPROCESSABLE_ENTITY

from app.authentication import get_current_active_user, get_current_user
from app.config import settings
from app.database import (
    AsyncIOMotorCollection,
    close_mongo_connection,
    connect_to_mongo,
    get_collection,
)
from app.errors import http_422_error_handler
from app.etherpad import *
from app.model import AssetCreate

BASE_PATH = os.getenv("BASE_PATH", "")

app = FastAPI(
    title="Collaborative Editor API", openapi_url=f"/openapi.json", docs_url="/docs", root_path=BASE_PATH
)
app.add_event_handler("startup", connect_to_mongo)
app.add_event_handler("shutdown", close_mongo_connection)


templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Set all CORS enabled origins
if settings.BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

mainrouter = APIRouter()


@mainrouter.get("/")
def main():
    return RedirectResponse(url=f"{BASE_PATH}/docs")


@mainrouter.get("/healthcheck")
def healthcheck():
    return True


integrablerouter = APIRouter()


@integrablerouter.post("/assets", response_description="Add new asset")
async def create_asset(asset_in: AssetCreate = Body(...), collection: AsyncIOMotorCollection = Depends(get_collection)):
    created_asset = await create_pad(collection, asset_in.name)
    return JSONResponse(status_code=status.HTTP_201_CREATED, content=created_asset)


@integrablerouter.get(
    "/assets/instantiate", response_description="GUI for asset creation"
)
async def instantiate_asset(request: Request):
    return templates.TemplateResponse("instantiator.html", {"request": request, "BASE_PATH": BASE_PATH})


@integrablerouter.get(
    "/assets/{id}", response_description="Asset JSON"
)
async def asset_data(id: str, collection: AsyncIOMotorCollection = Depends(get_collection)):
    if (asset := await collection.find_one({"_id": id})) is not None:
        return asset

    raise HTTPException(status_code=404, detail="Asset {id} not found")


@integrablerouter.delete("/assets/{id}", response_description="No content")
async def delete_asset(id: str, collection: AsyncIOMotorCollection = Depends(get_collection)):
    if (asset := await collection.find_one({"_id": id})) is not None:
        response = requests.get(deletePad(padID=asset["padID"]))
        data = json.loads(response._content)
        print(data)
        delete_result = await collection.delete_one({"_id": id})
        if delete_result.deleted_count == 1:
            return JSONResponse(status_code=status.HTTP_204_NO_CONTENT)
        return HTTPException(status_code=503, detail="Error while deleting")

    raise HTTPException(status_code=404, detail="Asset {id} not found")


@integrablerouter.get(
    "/assets/{id}/view", response_description="GUI for interaction with asset"
)
async def view_asset(request: Request, id: str, current_user: dict = Depends(get_current_active_user), collection: AsyncIOMotorCollection = Depends(get_collection), sessionID: Optional[str] = Cookie(None)):
    if (asset := await collection.find_one({"_id": id})) is not None:
        user_id = current_user["sub"]
        email = current_user["email"]

        # TODO: check if user has access to this resource
        print(email)
        response = requests.get(createAuthorIfNotExistsFor(
            authorName=email, authorMapper=user_id))
        data = json.loads(response._content)
        authorID = data["data"]["authorID"]

        valid_until = int(time.time()) + 5 * 60 * 60  # 5 hours from now
        response = requests.get(createSession(groupID=asset["groupID"],
                                authorID=authorID, validUntil=valid_until))
        data = json.loads(response._content)
        session_id = data["data"]["sessionID"]
        print(f"Session for {authorID}: {session_id}")
        url = iframeUrl(asset["padID"])
        response = templates.TemplateResponse(
            "gui.html", {"request": request, "url": url})

        # TODO: sessionID cookie can container session IDS separated by commas, so it would be nice to check if any of the current sessions is valid for this pad
        response.set_cookie(
            key="sessionID",
            value=session_id,
            # TODO: if https, true
            secure=False
        )
        return response

    raise HTTPException(status_code=404, detail="Asset {id} not found")


@integrablerouter.post(
    "/assets/{id}/clone", response_description="Asset JSON"
)
async def clone_asset(id: str, collection: AsyncIOMotorCollection = Depends(get_collection)):
    if (asset := await collection.find_one({"_id": id})) is not None:
        original_name = asset["name"]
        created_asset = await create_pad(collection, f"Copy of {original_name}")
        response = requests.get(getHTML(padID=asset["padID"]))
        data = json.loads(response._content)
        html = data["data"]["html"]

        print(f"Setting html {html}")
        requests.get(setHTML(padID=created_asset["padID"], html=html))
        # response = requests.get(getHTML(padID=created_asset["padID"]))
        # data = json.loads(response._content)
        # print(data)
        return JSONResponse(status_code=status.HTTP_201_CREATED, content=created_asset)

    raise HTTPException(status_code=404, detail="Asset {id} not found")

customrouter = APIRouter()


@customrouter.get("/pads", response_description="Get real pads")
async def get_real_pads():
    response = requests.get(listAllPads)
    data = json.loads(response._content)
    data = data["data"]["padIDs"]
    for i in data:
        print(i)
        requests.get(deletePad(i))
    return JSONResponse(status_code=status.HTTP_200_OK, content=data)


@customrouter.get("/pads/delete", response_description="Delete unused pads")
async def delete_unused_pads(collection: AsyncIOMotorCollection = Depends(get_collection)):
    assets = await collection.find().to_list(1000)
    response = requests.get(listAllPads)
    data = json.loads(response._content)
    data = data["data"]["padIDs"]
    matches = [asset["_id"] for asset in assets if asset["padID"] not in data]
    for id in matches:
        collection.delete_one({"_id": id})
    return JSONResponse(status_code=status.HTTP_200_OK, content=data)


@customrouter.get("/pads/clean", response_description="Delete all pads")
async def delete_all_pads(collection: AsyncIOMotorCollection = Depends(get_collection)):
    assets = await collection.find().to_list(1000)
    for asset in assets:
        requests.get(deletePad(asset["padID"]))
        collection.delete_one({"_id": asset["_id"]})

    return JSONResponse(status_code=status.HTTP_200_OK)


async def create_pad(collection, name):
    if not name or name == "":
        raise HTTPException(status_code=400, detail="Invalid name")
    groupMapper = ''.join(random.choice(string.ascii_lowercase) for i in range(10))
    response = requests.get(createGroupIfNotExistsFor(groupMapper=groupMapper)).json()
    groupID = response["data"]["groupID"]
    response = requests.get(createGroupPad(groupID=groupID, padName=name)).json()
    padID = response["data"]["padID"]
    print(f"Created pad {padID} for {groupID}")

    asset = {
        "_id": uuid.uuid4().hex,
        "groupMapper": groupMapper,
        "name": name,
        "groupID": groupID,
        "padID": padID
    }
    print(asset)
    asset = jsonable_encoder(asset)
    new_asset = await collection.insert_one(asset)
    return await collection.find_one({"_id": new_asset.inserted_id})


@customrouter.get(
    "/assets", response_description="List all assets"
)
async def list_assets(collection: AsyncIOMotorCollection = Depends(get_collection)):
    assets = await collection.find().to_list(1000)
    return JSONResponse(status_code=status.HTTP_200_OK, content=assets)


app.include_router(mainrouter, tags=["main"])
app.include_router(integrablerouter, tags=["Integrable"])
app.include_router(customrouter, prefix=settings.API_V1_STR, tags=["Custom endpoints"])


app.add_exception_handler(HTTP_422_UNPROCESSABLE_ENTITY, http_422_error_handler)