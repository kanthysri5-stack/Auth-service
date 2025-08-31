from fastapi import APIRouter, HTTPException, Request, Header, Depends, status
from sqlalchemy import create_engine, MetaData, Table, insert, select
from sqlalchemy.orm import sessionmaker
from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from typing import Optional
from jose import jwt, JWTError
import os

# Database connection string (update this!)
DATABASE_URL = "postgresql://postgres:123456@localhost:5432/postgres"

# SQLAlchemy setup
engine = create_engine(DATABASE_URL)
metadata = MetaData()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Reflect the existing table
employees = Table('employees', metadata, autoload_with=engine)

# FastAPI app
router = APIRouter()

class EmployeeBase(BaseModel):
    firstname: Optional[str] = Field(None, description="First name")
    lastname: Optional[str] = Field(None, description="Last name")
    mail: Optional[EmailStr] = Field(None, description="Email address")
    username: Optional[str] = Field(None, description="Username")
    role: Optional[str] = Field(None, description="Role (admin/user/employee)")
    is_active: Optional[bool] = Field(None, description="Active status")
    leaves_available: Optional[int] = Field(None, description="Leaves available")
    password_hash: Optional[str] = Field(None, description="Password hash")
    created_at: Optional[datetime] = Field(None, description="Created at")
    last_login: Optional[datetime] = Field(None, description="Last login")

class EmployeeCreate(EmployeeBase):
    empid: int = Field(..., description="Employee ID")
    firstname: str = Field(..., description="First name")
    lastname: str = Field(..., description="Last name")
    mail: EmailStr = Field(..., description="Email address")
    username: str = Field(..., description="Username")
    role: str = Field(..., description="Role (admin/user/employee)")

class EmployeeUpdate(BaseModel):
    mail: EmailStr = Field(..., description="New email address")
    username: str = Field(..., description="New username")

class AdminEmployeeUpdate(EmployeeBase):
    pass  # All fields optional for admin update

# Security configurations (should match main1.py)
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
JWT_SECRET = os.getenv("JWT_SECRET", "jwt-secret-key-here")

def validate_jwt(token: str, ip: str) -> dict:
    """Validate JWT token and check IP binding and user existence"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        # Check if token is bound to the same IP
        if payload.get("ip") != ip:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session invalidated by IP change"
            )
        # User validation: only allow admin/user
        if payload.get("sub") not in ["admin", "user"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or unauthorized"
            )
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )

def get_token_and_ip(request: Request, authorization: str = Header(None)):
    print(f"Authorization header: {authorization}")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization.replace("Bearer ", "")
    client_ip = request.client.host
    return token, client_ip

def get_current_user(request: Request, authorization: str = Header(None)):
    print(f"Authorization get current: {authorization}")
    token, client_ip = get_token_and_ip(request, authorization)
    return validate_jwt(token, client_ip)

def require_admin(user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

# --- SECURED ENDPOINTS BELOW ---

@router.get(
    "/admin/employees",
    summary="Get all employees (admin only)",
    response_description="List of all employees"
)
def get_employees(request: Request, authorization: str = Header(None), user: dict = Depends(require_admin)):
    """
    Returns all employees. Admin only.
    """
    session = SessionLocal()
    try:
        query = select(employees)
        result = session.execute(query)
        employees_list = [dict(row) for row in result.mappings().all()]
        return {"employees": employees_list}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

@router.post(
    "/admin/create",
    status_code=201,
    summary="Create employee (admin only)",
    response_description="Created employee"
)
def create_employee(employee: EmployeeCreate, request: Request, authorization: str = Header(None), user: dict = Depends(require_admin)):
    """
    Create a new employee. Admin only.
    """
    session = SessionLocal()
    try:
        data = {
            "empid": employee.empid,
            "firstname": employee.firstname,
            "lastname": employee.lastname,
            "mail": employee.mail,
            "username": employee.username,
            "role": employee.role,
            "is_active": True,
            "leaves_available": 0,
            "password_hash": "default_pass",  # You should hash in real apps!
            "created_at": datetime.utcnow(),
            "last_login": None
        }
        session.execute(insert(employees).values(**data))
        session.commit()
        return {"message": "Employee created successfully", "data": data}
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=f"Error creating employee: {str(e)}")
    finally:
        session.close()

@router.get(
    "/employees/{empid}",
    summary="Get employee by ID",
    response_description="Employee details"
)
def get_employee(empid: int, request: Request, authorization: str = Header(None), user: dict = Depends(get_current_user)):
    """
    Get employee details by ID. Admin or the user themselves.
    """
    session = SessionLocal()
    try:
        query = select(employees).where(employees.c.empid == empid)
        result = session.execute(query).mappings().first()
        if result:
            # Only admin or the user themselves can view
            if user["role"] != "admin" and user["sub"] != result["username"]:
                raise HTTPException(status_code=403, detail="Access denied")
            filtered = {
                "empid": result["empid"],
                "firstname": result["firstname"],
                "lastname": result["lastname"],
                "mail": result["mail"],
                "is_active": result["is_active"],
                "leaves_available": result["leaves_available"],
                "username": result["username"],
                "created_at": result["created_at"],
                "role": result["role"]
            }
            return filtered
        else:
            raise HTTPException(status_code=404, detail="Employee not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

@router.put(
    "/updateuser/{empid}",
    summary="Update own email and username",
    response_description="Updated employee fields"
)
def update_employee(empid: int, employee: EmployeeUpdate, request: Request, authorization: str = Header(None), user: dict = Depends(get_current_user)):
    """
    Update your own email and username. Admin or the user themselves.
    """
    session = SessionLocal()
    try:
        query = select(employees).where(employees.c.empid == empid)
        result = session.execute(query).mappings().first()
        if not result:
            raise HTTPException(status_code=404, detail="Employee not found")
        # Only admin or the user themselves can update
        if user["role"] != "admin" and user["sub"] != result["username"]:
            raise HTTPException(status_code=403, detail="Access denied")
        update_data = {
            "mail": employee.mail,
            "username": employee.username
        }
        session.execute(
            employees.update().where(employees.c.empid == empid).values(**update_data)
        )
        session.commit()
        return {"message": "Employee updated successfully", "data": update_data}
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=f"Error updating employee: {str(e)}")
    finally:
        session.close()

@router.put(
    "/updateuserpassword/{empid}",
    summary="Update own password",
    response_description="Password updated"
)
def update_employee_password(empid: int, password: str, request: Request, authorization: str = Header(None), user: dict = Depends(get_current_user)):
    """
    Update your own password. Admin or the user themselves.
    """
    session = SessionLocal()
    try:
        query = select(employees).where(employees.c.empid == empid)
        result = session.execute(query).mappings().first()
        if not result:
            raise HTTPException(status_code=404, detail="Employee not found")
        # Only admin or the user themselves can update password
        if user["role"] != "admin" and user["sub"] != result["username"]:
            raise HTTPException(status_code=403, detail="Access denied")
        session.execute(
            employees.update().where(employees.c.empid == empid).values(password_hash=password)
        )
        session.commit()
        return {"message": "Password updated successfully"}
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=f"Error updating password: {str(e)}")
    finally:
        session.close()

@router.put(
    "/admin/employee/update/{empid}",
    summary="Admin update employee (any field)",
    response_description="Updated employee fields"
)
def admin_update_employee(empid: int, employee: AdminEmployeeUpdate, request: Request, authorization: str = Header(None), user: dict = Depends(require_admin)):
    """
    Admin can update any employee field (except empid).
    """
    session = SessionLocal()
    try:
        query = select(employees).where(employees.c.empid == empid)
        result = session.execute(query).mappings().first()
        if not result:
            raise HTTPException(status_code=404, detail="Employee not found")
        update_data = {field: value for field, value in employee.dict(exclude_unset=True).items() if field != "empid"}
        if not update_data:
            raise HTTPException(status_code=400, detail="No fields to update")
        session.execute(
            employees.update().where(employees.c.empid == empid).values(**update_data)
        )
        session.commit()
        return {"message": "Employee updated successfully", "updated_fields": update_data}
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=f"Error updating employee: {str(e)}")
    finally:
        session.close()


