import io
import os
import traceback
import uuid
from pathlib import Path

import bleach
import filetype
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .logger_config import logger
from .schemas import LoginRequest, UserCreate

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret-key-change-me")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "")
APP_SECRET = os.getenv("APP_SECRET", "")
MAX_FILE_SIZE = 2 * 1024 * 1024

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    if request.url.path not in ["/docs", "/redoc", "/openapi.json"]:
        policy = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:;"
        )
        response.headers["Content-Security-Policy"] = policy
    return response


templates = Jinja2Templates(directory="templates")

STORAGE_DIR = Path("storage")
STORAGE_DIR.mkdir(exist_ok=True)

users_db: dict = {
    "alice": {"username": "alice", "role": "user", "password": "Alice123!"},
    "bob": {"username": "bob", "role": "user", "password": "Bob123!"},
    "admin": {"username": "admin", "role": "admin", "password": "Admin123!"},
}

files_db: list = [
    {"id": 1, "filename": "report_alice.pdf", "owner": "alice", "size": 1024,
     "path": None, "original_name": "report_alice.pdf", "is_encrypted": False},
    {"id": 2, "filename": "photo_bob.jpg", "owner": "bob", "size": 2048,
     "path": None, "original_name": "photo_bob.jpg", "is_encrypted": False},
    {"id": 3, "filename": "admin_keys.txt", "owner": "admin", "size": 12,
     "path": None, "original_name": "admin_keys.txt", "is_encrypted": False},
]

comments_list: list = []


def get_cipher() -> Fernet | None:
    if ENCRYPTION_KEY:
        key = ENCRYPTION_KEY.encode() if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY
        return Fernet(key)
    return None


def get_current_user(request: Request) -> dict:
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def get_file_secure(file_id: int, user_data: dict = Depends(get_current_user)) -> dict:
    file = next((f for f in files_db if f["id"] == file_id), None)
    if not file:
        raise HTTPException(status_code=404, detail="File not found")
    is_owner = file["owner"] == user_data["username"]
    is_admin = user_data["role"] == "admin"
    if not (is_owner or is_admin):
        logger.warning(
            f"IDOR attempt: user '{user_data['username']}' tried to access "
            f"file {file_id} owned by '{file['owner']}'"
        )
        raise HTTPException(status_code=404, detail="File not found")
    return file


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception on {request.url}: {traceback.format_exc()}")
    return JSONResponse(
        status_code=500,
        content={"detail": "We are sorry, something went wrong."},
    )


@app.on_event("startup")
async def startup_event():
    if not APP_SECRET:
        logger.warning("APP_SECRET is not set")
    else:
        logger.info(f"System started. Secret hash: {APP_SECRET[:3]}***")


@app.post("/login")
async def login(request: Request, credentials: LoginRequest):
    username = credentials.username
    password = credentials.password
    user = users_db.get(username)
    if not user or user["password"] != password:
        logger.warning(f"Failed login attempt for username: '{username}'")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    request.session["user"] = {"username": user["username"], "role": user["role"]}
    logger.info(f"User '{username}' logged in")
    return {"msg": "Logged in", "role": user["role"]}


@app.post("/logout")
async def logout(request: Request):
    user = request.session.get("user")
    if user:
        logger.info(f"User '{user['username']}' logged out")
    request.session.clear()
    return {"msg": "Logged out"}


@app.post("/registration")
async def register(user: UserCreate):
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="Username already taken")
    users_db[user.username] = {
        "username": user.username,
        "role": "user",
        "password": user.password,
    }
    logger.info(f"New user registered: '{user.username}'")
    return {"msg": "User created", "user": user.username}


@app.get("/comments")
async def get_comments(request: Request):
    return templates.TemplateResponse(
        "comments.html",
        {"request": request, "comments": comments_list},
        headers={
            "Content-Security-Policy": (
                "default-src 'self'; script-src 'self'; "
                "style-src 'self'; object-src 'none';"
            )
        },
    )


@app.post("/comments")
async def post_comment(text: str = Form(...)):
    clean = bleach.clean(
        text,
        tags=["b", "i", "u", "em", "strong"],
        attributes={},
        strip=True,
    )
    comments_list.append(clean)
    logger.info("New comment added")
    return RedirectResponse(url="/comments", status_code=303)


@app.get("/files/my")
async def my_files(user_data: dict = Depends(get_current_user)):
    return [
        {k: v for k, v in f.items() if k != "path"}
        for f in files_db
        if f["owner"] == user_data["username"]
    ]


@app.get("/files/all")
async def all_files(user_data: dict = Depends(get_current_user)):
    if user_data["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return [{k: v for k, v in f.items() if k != "path"} for f in files_db]


@app.get("/files/{file_id}")
async def get_file_info(file: dict = Depends(get_file_secure)):
    return {k: v for k, v in file.items() if k != "path"}


@app.delete("/files/{file_id}")
async def delete_file(file_id: int, user_data: dict = Depends(get_current_user)):
    file = next((f for f in files_db if f["id"] == file_id), None)
    if not file:
        raise HTTPException(status_code=404, detail="File not found")
    is_owner = file["owner"] == user_data["username"]
    is_admin = user_data["role"] == "admin"
    if not (is_owner or is_admin):
        logger.warning(
            f"Unauthorized delete: user '{user_data['username']}' on file {file_id}"
        )
        raise HTTPException(status_code=404, detail="File not found")
    if file.get("path") and Path(file["path"]).exists():
        Path(file["path"]).unlink()
    files_db.remove(file)
    logger.info(f"File {file_id} deleted by '{user_data['username']}'")
    return {"msg": "File deleted"}


@app.post("/files/upload")
async def upload_file(
    file: UploadFile = File(...),
    encrypt: bool = Query(False),
    user_data: dict = Depends(get_current_user),
):
    head = await file.read(2048)
    kind = filetype.guess(head)
    if kind is None or kind.mime not in ["image/jpeg", "image/png"]:
        raise HTTPException(status_code=400, detail="Only JPEG and PNG images are allowed")

    await file.seek(0)

    file_data = b""
    total_size = 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        total_size += len(chunk)
        if total_size > MAX_FILE_SIZE:
            raise HTTPException(status_code=413, detail="File too large (max 2MB)")
        file_data += chunk

    if encrypt:
        cipher = get_cipher()
        if cipher is None:
            raise HTTPException(status_code=500, detail="Encryption key not configured")
        file_data = cipher.encrypt(file_data)

    physical_name = f"{uuid.uuid4()}.bin"
    file_path = STORAGE_DIR / physical_name
    with open(file_path, "wb") as f:
        f.write(file_data)

    new_id = max((f["id"] for f in files_db), default=0) + 1
    files_db.append({
        "id": new_id,
        "filename": file.filename,
        "owner": user_data["username"],
        "size": total_size,
        "path": str(file_path),
        "original_name": file.filename,
        "is_encrypted": encrypt,
    })

    logger.info(f"File '{file.filename}' uploaded by '{user_data['username']}' (encrypted={encrypt})")
    return {"msg": "File uploaded", "id": new_id}


@app.get("/files/{file_id}/download")
async def download_file(file: dict = Depends(get_file_secure)):
    if not file.get("path") or not Path(file["path"]).exists():
        raise HTTPException(status_code=404, detail="File not found on disk")

    with open(file["path"], "rb") as f:
        data = f.read()

    if file.get("is_encrypted"):
        cipher = get_cipher()
        if cipher is None:
            raise HTTPException(status_code=500, detail="Encryption key not configured")
        data = cipher.decrypt(data)

    return StreamingResponse(
        io.BytesIO(data),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{file["original_name"]}"'
        },
    )


@app.get("/cause_error")
async def cause_error():
    result = 1 / 0
    return result
