# User Registration API

A robust FastAPI-based application for managing user registrations across multiple roles (Admin, Student, School/College, Promoter).

## Features

- **Multi-Role Registration**: Distinct sign-up flows for Admins, Students, Schools, and Promoters.
- **Data Validation**: Strictly typed schemas using Pydantic.
- **Security**: Password hashing using Bcrypt and SHA-256.
- **Database**: Efficient data storage with MongoDB.
- **Admin Verification**: Secured admin registration via secret code.

## Tech Stack

- **Python 3.13**
- **FastAPI**
- **MongoDB** (pymongo)

## Installation

1. **Clone the repository**
2. **Install dependencies**:
   ```bash
   pip install fastapi uvicorn pymongo passlib[bcrypt] pydantic[email]
   ```
3. **Start MongoDB**: Ensure your local MongoDB instance is running on `mongodb://localhost:27017/`.

## Usage

Run the server:
```bash
python main.py
```
Or using uvicorn directly:
```bash
uvicorn main:app --reload
```

## API Documentation

Once running, access the interactive API docs at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`
