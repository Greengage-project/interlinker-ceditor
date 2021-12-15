from fastapi import FastAPI, Request, HTTPException, status, Body
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from app.config import settings
from starlette.middleware.cors import CORSMiddleware
from app.database import db
from fastapi.responses import RedirectResponse
import os
from fastapi import File, UploadFile, APIRouter
from app.etherpad import *
from app.model import AssetCreate
import json
import random
import string
import requests



ROOT_PATH = "/etherpadwrapper"

app = FastAPI(
    title="Etherpad API Wrapper", openapi_url=f"/openapi.json", docs_url="/docs", root_path=ROOT_PATH
)

# Set all CORS enabled origins
if settings.BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        # localhost only
        allow_methods=["*"],
        allow_headers=["*"],
    )

"""
from fastapi_utils.tasks import repeat_every
@apirouter.on_event("startup")
@repeat_every(seconds=60 * 60)  # 1 hour
def repetitive_task() -> None:
    pass
    # clean(db)
"""


@app.get("/")
def main():
    return RedirectResponse(url=f"{ROOT_PATH}/docs")

@app.get("/healthcheck")
def healthcheck():
    return True

apirouter = APIRouter()

@apirouter.post("/assets/", response_description="Add new asset")
async def create_asset(asset_in: AssetCreate = Body(...)):
   
    groupMapper = ''.join(random.choice(string.ascii_lowercase) for i in range(10))
    response = requests.get(createGroupIfNotExistsFor(groupMapper=groupMapper))
    print(createGroupIfNotExistsFor(groupMapper=groupMapper))
    data = json.loads(response._content)
    print(data)
    groupID = data["data"]["groupID"]
    response = requests.get(createGroupPad(groupID=groupID, padName=asset_in.name))
    data = json.loads(response._content)
    print(data)
    padID = data["data"]["padID"]
    response = requests.get(getHTML(padID=padID))
    data = json.loads(response._content)
    print(data)

    asset = jsonable_encoder(data)
    new_asset = await db["assets"].insert_one(asset)
    created_asset = await db["assets"].find_one({"_id": new_asset.inserted_id})
    return JSONResponse(status_code=status.HTTP_201_CREATED, content=created_asset)


@apirouter.get(
    "/assets/", response_description="List all assets"
)
async def list_assets():
    assets = await db["assets"].find().to_list(1000)
    return JSONResponse(status_code=status.HTTP_200_OK, content=assets)


@apirouter.get(
    "/assets/{id}", response_description="Get a single asset"
)
async def show_asset(id: str):
    if (asset := await db["assets"].find_one({"_id": id})) is not None:
            return JSONResponse(status_code=status.HTTP_200_OK, content=asset)

    raise HTTPException(status_code=404, detail="Asset {id} not found")

@apirouter.post(
    "/assets/{id}/clone", response_description="Clone specific asset"
)
async def clone_asset(id: str):
    if (asset := await db["assets"].find_one({"_id": id})) is not None:
        file = copy_file("newTitle", id)
        file["_id"] = file["id"]
        del file["id"]
        asset = jsonable_encoder(file)
        new_asset = await db["assets"].insert_one(asset)
        created_asset = await db["assets"].find_one({"_id": new_asset.inserted_id})
        return JSONResponse(status_code=status.HTTP_201_CREATED, content=created_asset)

    raise HTTPException(status_code=404, detail="Asset {id} not found")


@apirouter.delete("/assets/{id}", response_description="Delete a asset")
async def delete_asset(id: str):
    delete_result = await db["assets"].delete_one({"_id": id})

    if delete_result.deleted_count == 1:
        return JSONResponse(status_code=status.HTTP_204_NO_CONTENT)

    raise HTTPException(status_code=404, detail="Asset {id} not found")


from fastapi.templating import Jinja2Templates
templates = Jinja2Templates(directory="templates")

@apirouter.get(
    "/assets/{id}/gui", response_description="GUI for specific asset"
)
async def gui_asset(request: Request, id: str):
    if (asset := await db["assets"].find_one({"_id": id})) is not None:
        response = requests.get("/auth/api/v1/users/me")
        current_user = json.loads(response._content)
        email = current_user["email"] if current_user else "AnonymousUser"

        response = requests.get(createAuthorIfNotExistsFor(
            authorName=email, authorMapper=email))
        data = json.loads(response._content)
        authorID = data["data"]["authorID"]
        response = requests.get(createSession(groupID=asset.groupID,
                                authorID=authorID, validUntil=2022201246))
        data = json.loads(response._content)
        sessionID = data["data"]["sessionID"]

        url = iframeUrl(sessionID, asset.groupID, asset.name)
        response = templates.TemplateResponse(
            "index.html", {"request": request, "url": url})
        return response

    raise HTTPException(status_code=404, detail="Asset {id} not found")


app.include_router(apirouter, prefix=settings.API_V1_STR)