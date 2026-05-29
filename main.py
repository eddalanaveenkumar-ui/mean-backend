from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from pymongo import MongoClient
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
import os

import firebase_admin
from firebase_admin import credentials, auth as firebase_auth

# --- Configurations ---
SECRET_KEY = os.environ.get("JWT_SECRET", "super-secret-mean-ai-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7 # 7 days
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")

# --- Firebase Setup ---
cred = credentials.Certificate(os.path.join(os.path.dirname(__file__), "mean-firebase-adminsdk.json"))
firebase_admin.initialize_app(cred)

# --- Database Setup ---
client = MongoClient(MONGO_URI)
db = client["mean_ai_db"]
users_collection = db["users"]
chats_collection = db["chats"]
classes_collection = db["classes"]

# Create index on email to ensure uniqueness
users_collection.create_index("email", unique=True)

# --- Security & Auth ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
        
    user = users_collection.find_one({"email": email})
    if user is None:
        raise credentials_exception
    return user

# --- Models ---
class UserCreate(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class UserResponse(BaseModel):
    email: str
    has_api_key: bool
    api_key_last_chars: Optional[str] = None

class ApiKeyUpdate(BaseModel):
    api_key: str

class GoogleToken(BaseModel):
    token: str

class ChatSync(BaseModel):
    chat_id: str
    title: str
    messages: list

class ClassCreate(BaseModel):
    name: str
    description: Optional[str] = None
    slides: list = []

# --- FastAPI App Initializer ---    
app = FastAPI(title="Mean AI Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://www.meanai.site",
        "https://meanai.site",
        "https://mean-85713.web.app",
        "http://localhost:3000",
        "http://localhost:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# --- API Endpoints ---

@app.post("/google-login", response_model=Token)
def google_login(payload: GoogleToken):
    try:
        # Verify the token against Firebase
        decoded_token = firebase_auth.verify_id_token(payload.token)
        email = decoded_token.get("email")
        if not email:
            raise HTTPException(status_code=400, detail="Google token does not contain an email.")
            
        # Check if user exists in MongoDB, if not create them
        user = users_collection.find_one({"email": email})
        if not user:
            user = {
                "email": email,
                "password": "", # No password for google-auth users natively
                "openrouter_api_key": None
            }
            users_collection.insert_one(user)
            
        # Return standard JWT identical to normal login
        access_token = create_access_token(data={"sub": email})
        return {"access_token": access_token, "token_type": "bearer"}
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid Google Token: {str(e)}")

@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(user: UserCreate):
    if users_collection.find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user_dict = {
        "email": user.email,
        "password": get_password_hash(user.password),
        "openrouter_api_key": None
    }
    users_collection.insert_one(user_dict)
    return {"message": "User registered successfully"}

@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_collection.find_one({"email": form_data.username})
    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(data={"sub": user["email"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/me", response_model=UserResponse)
def get_me(current_user: dict = Depends(get_current_user)):
    api_key = current_user.get("openrouter_api_key")
    return {
        "email": current_user["email"],
        "has_api_key": bool(api_key),
        "api_key_last_chars": api_key[-4:] if api_key else None
    }

@app.get("/me/api_key")
def get_my_api_key(current_user: dict = Depends(get_current_user)):
    """ Returns the raw API key for the frontend to use in requests """
    api_key = current_user.get("openrouter_api_key")
    if not api_key:
        raise HTTPException(status_code=404, detail="OpenRouter API Key not linked")
    return {"openrouter_api_key": api_key}

@app.post("/update-api-key")
def update_api_key(data: ApiKeyUpdate, current_user: dict = Depends(get_current_user)):
    users_collection.update_one(
        {"email": current_user["email"]},
        {"$set": {"openrouter_api_key": data.api_key}}
    )
    return {"message": "API Key linked successfully"}

@app.get("/")
def health_check():
    return {"status": "ok", "app": "Mean AI Backend"}

# --- Chat Endpoints ---
@app.get("/chats")
def get_chats(current_user: dict = Depends(get_current_user)):
    user_chats = list(chats_collection.find({"user_email": current_user["email"]}, {"_id": 0}))
    return {"chats": user_chats}

@app.post("/chats")
def sync_chat(chat: ChatSync, current_user: dict = Depends(get_current_user)):
    chat_dict = chat.dict()
    chat_dict["user_email"] = current_user["email"]
    chat_dict["updated_at"] = datetime.utcnow()
    
    chats_collection.update_one(
        {"user_email": current_user["email"], "chat_id": chat.chat_id},
        {"$set": chat_dict},
        upsert=True
    )
    return {"message": "Chat synced"}

@app.delete("/chats/{chat_id}")
def delete_chat(chat_id: str, current_user: dict = Depends(get_current_user)):
    chats_collection.delete_one({"user_email": current_user["email"], "chat_id": chat_id})
    return {"message": "Chat deleted"}

# --- Class Endpoints ---
@app.get("/classes")
def get_classes(current_user: dict = Depends(get_current_user)):
    user_classes = list(classes_collection.find({"user_email": current_user["email"]}, {"_id": 0}))
    return {"classes": user_classes}

@app.post("/classes")
def create_class(cls: ClassCreate, current_user: dict = Depends(get_current_user)):
    import uuid
    class_id = str(uuid.uuid4())
    cls_dict = {
        "class_id": class_id,
        "user_email": current_user["email"],
        "name": cls.name,
        "description": cls.description,
        "slides": cls.slides,
        "created_at": datetime.utcnow()
    }
    classes_collection.insert_one(cls_dict)
    return {"message": "Class created", "class_id": class_id}

@app.delete("/classes/{class_id}")
def delete_class(class_id: str, current_user: dict = Depends(get_current_user)):
    classes_collection.delete_one({"user_email": current_user["email"], "class_id": class_id})
    return {"message": "Class deleted"}
