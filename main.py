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

# --- FastAPI App Initializer ---    
app = FastAPI(title="Mean AI Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict this to standard UI domains e.g., ["http://localhost:5173"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
