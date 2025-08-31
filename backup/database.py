from fastapi import FastAPI, HTTPException
from sqlalchemy import create_engine, MetaData, Table
from sqlalchemy.orm import sessionmaker
from pydantic import BaseModel, EmailStr
from datetime import datetime
from sqlalchemy import create_engine, MetaData, Table, insert, select
import os
from typing import Optional

# Database connection string (update this!)
DATABASE_URL = "postgresql://postgres:123456@localhost:5432/postgres"

# SQLAlchemy setup
engine = create_engine(DATABASE_URL)
metadata = MetaData()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Reflect the existing table
employees = Table('employees', metadata, autoload_with=engine)

# FastAPI app
app = FastAPI()

class EmployeeBase(BaseModel):
    firstname: Optional[str] = None
    lastname: Optional[str] = None
    mail: Optional[EmailStr] = None
    username: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    leaves_available: Optional[int] = None
    password_hash: Optional[str] = None
    created_at: Optional[datetime] = None
    last_login: Optional[datetime] = None

class EmployeeCreate(EmployeeBase):
    empid: int
    firstname: str
    lastname: str
    mail: EmailStr
    username: str
    role: str

class EmployeeUpdate(BaseModel):
    mail: EmailStr
    username: str

class AdminEmployeeUpdate(EmployeeBase):
    pass  # All fields optional for admin update

@app.get("/admin/employees")
def get_employees():
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
@app.post("/admin/create", status_code=201)
def create_employee(employee: EmployeeCreate):
    session = SessionLocal()
    try:
        # Default values
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

        # Insert into DB
        session.execute(insert(employees).values(**data))
        session.commit()

        return {"message": "Employee created successfully", "data": data}
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=f"Error creating employee: {str(e)}")
    finally:
        session.close()
@app.get("/employees/{empid}") 
def get_employee(empid: int):
    session = SessionLocal()
    try:
        query = select(employees).where(employees.c.empid == empid)
        result = session.execute(query).mappings().first()
        if result:
            # Only include the requested fields
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
@app.put("/updateuser/{empid}")
def update_employee(empid: int, employee: EmployeeUpdate):
    session = SessionLocal()
    try:
        query = select(employees).where(employees.c.empid == empid)
        result = session.execute(query).mappings().first()
        if not result:
            raise HTTPException(status_code=404, detail="Employee not found")

        # Update fields
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
@app.put("/updateuserpassword/{empid}")
def update_employee_password(empid: int, password: str):
    session = SessionLocal()
    try:
        query = select(employees).where(employees.c.empid == empid)
        result = session.execute(query).mappings().first()
        if not result:
            raise HTTPException(status_code=404, detail="Employee not found")

        # Update password
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
@app.put("/admin/employee/update/{empid}")
def admin_update_employee(empid: int, employee: AdminEmployeeUpdate):
    """
    Admin can update any field that is sent in the request body.
    Only fields provided in the request will be updated.
    """
    session = SessionLocal()
    try:
        query = select(employees).where(employees.c.empid == empid)
        result = session.execute(query).mappings().first()
        if not result:
            raise HTTPException(status_code=404, detail="Employee not found")

        # Only update fields that are provided (not None)
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


