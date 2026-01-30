from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, EmailStr, Field, field_validator
from typing import Optional, Literal
from datetime import datetime
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from passlib.context import CryptContext
import re
import uvicorn
import hashlib

# ==================== FastAPI App ==================
app = FastAPI(
    title="User Registration API",
    description="Registration System for Admin, Student, School/College and Promoter",
    version="1.0.0"
)

# ==================== MongoDB Connection ====================
try:
    client = MongoClient("mongodb://localhost:27017/")
    db = client["MyDatabase"]
    collection = db["MyCollection"]
    
    # Connection test
    client.admin.command('ping')
    print("✅ MongoDB connected successfully!")
except ConnectionFailure as e:
    print(f"❌ MongoDB connection failed: {e}")
    raise

# ==================== Password Hashing ====================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# def hash_password(password: str) -> str:
#     """Password ko hash karta hai - 72 bytes limit ke sath"""
#     # Bcrypt ki 72 bytes limit ke liye password truncate karna
#     if len(password.encode('utf-8')) > 72:
#         password = password[:72]
#     return pwd_context.hash(password)

def hash_password(password: str) -> str:
    sha256_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    return pwd_context.hash(sha256_hash)

# ==================== Pydantic Models (Schemas) ====================

class AdminSignup(BaseModel):
    """Admin ke liye signup schema"""
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=72)
    phone: str = Field(..., pattern=r'^\+92 \d{11}$')
    name: str = Field(..., min_length=2, max_length=100)
    # user_type: Literal["admin", "student", "school/college", "promoter"] = "admin"
    # is_active: Literal[True, False] = True
    admin_code: str  # Special admin verification code
    
    @field_validator('phone')
    @classmethod
    def validate_phone(cls, v):
        if not re.match(r'^\+92 \d{11}$', v):
            raise ValueError('Phone format: +92 12345678910 (space ke baad 11 digits)')
        return v
    
    class Config:
        json_schema_extra = {
            "example": {
                "email": "admin@example.com",
                "password": "admin12345",
                "phone": "+92 12345678910",
                "name": "Admin User",
                "admin_code": "ADMIN2024SECRET"
            }
        }

class StudentSignup(BaseModel):
    """Student ke liye signup schema"""
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=72)
    phone: Optional[str] = Field(None, pattern=r'^\+92 \d{11}$')
    name: str = Field(..., min_length=2, max_length=100)
    institution_name: str = Field(..., min_length=2)
    
    @field_validator('phone')
    @classmethod
    def validate_phone(cls, v):
        if v is not None and not re.match(r'^\+92 \d{11}$', v):
            raise ValueError('Phone format: +92 12345678910 (space ke baad 11 digits)')
        return v
    
    class Config:
        json_schema_extra = {
            "example": {
                "email": "student@example.com",
                "password": "student123",
                "phone": "+92 12345678910",
                "name": "Ahmed Ali",
                "institution_name": "ABC School"
            }
        }

class SchoolCollegeSignup(BaseModel):
    """School/College ke liye signup schema"""
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=72)
    phone: str = Field(..., pattern=r'^\+92 \d{11}$')
    institute_name: str = Field(..., min_length=2, max_length=200)
    # user_type: Literal["admin", "student", "school/college", "promoter"] = "school/college"
    # is_active: Literal[True, False] = True
    address: str = Field(..., min_length=5)
    head_of_institute: Optional[str] = None
    
    @field_validator('phone')
    @classmethod
    def validate_phone(cls, v):
        if not re.match(r'^\+92 \d{11}$', v):
            raise ValueError('Phone format: +92 12345678910 (space ke baad 11 digits)')
        return v
    
    class Config:
        json_schema_extra = {
            "example": {
                "email": "school@example.com",
                "password": "school123",
                "phone": "+92 12345678910",
                "institute_name": "XYZ College",
                # "user_type": "school/college",
                # "is_active": True,
                "address": "Karachi, Pakistan",
                "head_of_institute": "Dr. Principal Name"
            }
        }

class PromoterSignup(BaseModel):
    """Promoter ke liye signup schema"""
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=72)
    phone: str = Field(..., pattern=r'^\+92 \d{11}$')
    name: str = Field(..., min_length=2, max_length=100)
    # user_type: Literal["admin", "student", "school/college", "promoter"] = "promoter"
    # is_active: Literal[True, False] = True
    
    @field_validator('phone')
    @classmethod
    def validate_phone(cls, v):
        if not re.match(r'^\+92 \d{11}$', v):
            raise ValueError('Phone format: +92 12345678910 (space ke baad 11 digits)')
        return v
    
    class Config:
        json_schema_extra = {
            "example": {
                "email": "promoter@example.com",
                "password": "promoter123",
                "phone": "+92 12345678910",
                "name": "Promoter Name",
                # "user_type": "promoter",
                # "is_active": True
            }
        }

class UserResponse(BaseModel):
    id: str
    email: str
    user_type: str
    message: str

# ==================== Configuration ====================
ADMIN_SECRET_CODE = "ADMIN2024SECRET"  # Production mein environment variable se lena

# ==================== API Endpoints ====================

@app.get("/")
async def root():
    """Welcome endpoint"""
    return {
        "message": "Welcome to User Registration API",
        "endpoints": {
            "admin_signup": "/signup/admin",
            "student_signup": "/signup/student",
            "school_college_signup": "/signup/school_college",
            "promoter_signup": "/signup/promoter",
            "users_count": "/users/count",
            "all_users": "/users/all"
        }
    }

@app.post("/signup/admin", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def admin_signup(user: AdminSignup):
    """
    Admin Registration
    Admin code verify karke registration karta hai
    """
    # Admin code verify karna
    if user.admin_code != ADMIN_SECRET_CODE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid admin code. Access denied!"
        )
    
    # Email already exists check
    existing_user = collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered!"
        )
    
    # Phone already exists check
    existing_user = collection.find_one({"phone": user.phone})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Phone number already registered!"
        )
    
    # User document banao - sirf required fields
    user_document = {
        "email": user.email,
        "password": hash_password(user.password),
        "phone": user.phone,
        "name": user.name,
        "user_type": 'admin',
        "is_active": True
    }
    
    try:
        # MongoDB mein insert karo
        result = collection.insert_one(user_document)
        
        return UserResponse(
            id=str(result.inserted_id),
            email=user.email,
            user_type=user_document['user_type'],
            message="Admin registered successfully!"
        )
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {str(e)}"
        )

@app.post("/signup/student", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def student_signup(user: StudentSignup):
    """
    Student Registration
    """
    # Email already exists check
    existing_user = collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered!"
        )
    
    # Phone already exists check
    existing_user = collection.find_one({"phone": user.phone})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Phone number already registered!"
        )

    # User document banao - sirf required fields
    user_document = {
        "email": user.email,
        "password": hash_password(user.password),
        "name": user.name,
        "user_type": 'student',
        "is_active": True,
        "institution_name": user.institution_name
    }
    
    # Optional field add karo agar di gayi ho
    if user.phone is not None:
        user_document["phone"] = user.phone
    
    try:
        # MongoDB mein insert karo
        result = collection.insert_one(user_document)
        
        return UserResponse(
            id=str(result.inserted_id),
            email=user.email,
            user_type=user_document['user_type'],
            message="Student registered successfully!"
        )
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {str(e)}"
        )

@app.post("/signup/school_college", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def school_college_signup(user: SchoolCollegeSignup):
    """
    School/College Registration
    """
    # Email already exists check
    existing_user = collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered!"
        )
    
    # Phone already exists check
    existing_user = collection.find_one({"phone": user.phone})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Phone number already registered!"
        )

    # User document banao - sirf required fields
    user_document = {
        "email": user.email,
        "password": hash_password(user.password),
        "phone": user.phone,
        "institute_name": user.institute_name,
        "user_type": 'school/college',
        "is_active": True,
        "address": user.address
    }
    
    # Optional field add karo agar di gayi ho
    if user.head_of_institute is not None:
        user_document["head_of_institute"] = user.head_of_institute
    
    try:
        # MongoDB mein insert karo
        result = collection.insert_one(user_document)
        
        return UserResponse(
            id=str(result.inserted_id),
            email=user.email,
            user_type=user_document['user_type'],
            message="School/College registered successfully!"
        )
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {str(e)}"
        )

@app.post("/signup/promoter", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def promoter_signup(user: PromoterSignup):
    """
    Promoter Registration
    """
    # Email already exists check
    existing_user = collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered!"
        )
    
    # Phone already exists check
    existing_user = collection.find_one({"phone": user.phone})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Phone number already registered!"
        )

    # User document banao - sirf required fields
    user_document = {
        "email": user.email,
        "password": hash_password(user.password),
        "phone": user.phone,
        "name": user.name,
        "user_type": 'promoter',
        "is_active": True
    }
    
    try:
        # MongoDB mein insert karo
        result = collection.insert_one(user_document)
        
        return UserResponse(
            id=str(result.inserted_id),
            email=user.email,
            user_type=user_document['user_type'],
            message="Promoter registered successfully!"
        )
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {str(e)}"
        )

@app.get("/users/count")
async def get_users_count():
    """
    Har user type ka count return karta hai
    """
    try:
        total_users = collection.count_documents({})
        admins = collection.count_documents({"user_type": "admin"})
        students = collection.count_documents({"user_type": "student"})
        schools = collection.count_documents({"user_type": "school/college"})
        promoters = collection.count_documents({"user_type": "promoter"})
        
        return {
            "total_users": total_users,
            "admins": admins,
            "students": students,
            "schools_colleges": schools,
            "promoters": promoters
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch user count: {str(e)}"
        )

@app.get("/users/all")
async def get_all_users():
    """
    Sab users ki list return karta hai (passwords ke bina)
    """
    try:
        users = list(collection.find({}, {"password": 0}))
        
        # MongoDB ObjectId ko string mein convert karo
        for user in users:
            user['_id'] = str(user['_id'])
        
        return {
            "total_users": len(users),
            "users": users
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch users: {str(e)}"
        )

# ==================== Server Run ====================
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True  
    )