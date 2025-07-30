from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import List, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field
from uuid import uuid4, UUID

# Secret key for JWT; in production read from environment variable!
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Simple password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# In-memory storage (replace with actual DB in production)
fake_users_db = {}
fake_tasks_db = {}

# FastAPI app initialization
app = FastAPI(
    title="Todo Backend API",
    description="API backend for a fullstack todo application",
    version="1.0.0",
    openapi_tags=[
        {"name": "health", "description": "Healthcheck endpoint"},
        {"name": "auth", "description": "User Authentication"},
        {"name": "tasks", "description": "Task management"}
    ]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# =================== MODELS & SCHEMAS ===================

# PUBLIC_INTERFACE
class UserBase(BaseModel):
    email: EmailStr = Field(..., description="User email")

class UserIn(UserBase):
    password: str = Field(..., min_length=6, description="User password")

class UserOut(UserBase):
    id: UUID

class User(UserBase):
    id: UUID
    hashed_password: str

# PUBLIC_INTERFACE
class Token(BaseModel):
    access_token: str
    token_type: str

# PUBLIC_INTERFACE
class TaskBase(BaseModel):
    title: str = Field(..., description="Title of the task", min_length=1)
    description: Optional[str] = Field(None, description="Details of the task")
    due_date: Optional[datetime] = Field(None, description="Due date (UTC)")

class TaskCreate(TaskBase):
    pass

class TaskUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1)
    description: Optional[str] = None
    due_date: Optional[datetime] = None
    completed: Optional[bool] = None

class Task(TaskBase):
    id: UUID
    owner_id: UUID
    created_at: datetime
    updated_at: datetime
    completed: bool

# =================== HELPER FUNCTIONS ===================

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user(email: str) -> Optional[User]:
    user_dict = fake_users_db.get(email)
    if user_dict:
        return User(**user_dict)
    return None

def authenticate_user(email: str, password: str):
    user = get_user(email)
    if user and verify_password(password, user.hashed_password):
        return user
    return None

# PUBLIC_INTERFACE
async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """Get the user object from the JWT access token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(email)
    if user is None:
        raise credentials_exception
    return user

# =================== ROUTES ===================

# HEALTHCHECK
@app.get("/", tags=["health"])
def health_check():
    """Public health check endpoint."""
    return {"message": "API is healthy"}

# AUTHENTICATION

# PUBLIC_INTERFACE
@app.post("/auth/register", response_model=UserOut, tags=["auth"], summary="Register a new user")
def register(user_in: UserIn):
    """
    Register a new user with email and password.
    Returns user details (without password).
    """
    if user_in.email in fake_users_db:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_id = uuid4()
    user = {
        "email": user_in.email,
        "id": user_id,
        "hashed_password": get_password_hash(user_in.password)
    }
    fake_users_db[user_in.email] = user
    return {"id": user_id, "email": user_in.email}

# PUBLIC_INTERFACE
@app.post("/auth/login", response_model=Token, tags=["auth"], summary="Login for access token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Authenticate a user and return JWT access token.
    """
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

# TASK CRUD

# PUBLIC_INTERFACE
@app.post("/tasks/", response_model=Task, tags=["tasks"], summary="Create a new task")
def create_task(task_in: TaskCreate, current_user: User = Depends(get_current_user)):
    """
    Create a new task for the authenticated user.
    """
    task_id = uuid4()
    now = datetime.utcnow()
    task = {
        "id": task_id,
        "owner_id": current_user.id,
        "title": task_in.title,
        "description": task_in.description,
        "due_date": task_in.due_date,
        "created_at": now,
        "updated_at": now,
        "completed": False
    }
    fake_tasks_db[task_id] = task
    return Task(**task)

# PUBLIC_INTERFACE
@app.get("/tasks/", response_model=List[Task], tags=["tasks"], summary="List user tasks")
def list_tasks(
    current_user: User = Depends(get_current_user),
    completed: Optional[bool] = None,
    search: Optional[str] = None,
    sort_by: Optional[str] = None,    # "created_at", "due_date"
    sort_desc: Optional[bool] = False
):
    """
    List all tasks for the user with optional filtering and sorting.
    - Filter by completion status and text search in title/desc.
    - Sort by "created_at" or "due_date", ascending/descending.
    """
    tasks = [
        Task(**task)
        for task in fake_tasks_db.values()
        if task["owner_id"] == current_user.id
    ]
    if completed is not None:
        tasks = [t for t in tasks if t.completed == completed]
    if search:
        tasks = [
            t for t in tasks
            if search.lower() in (t.title or "").lower()
            or search.lower() in (t.description or "").lower()
        ]
    if sort_by in {"created_at", "due_date"}:
        tasks = sorted(
            tasks,
            key=lambda t: getattr(t, sort_by) or datetime.max,
            reverse=sort_desc,
        )
    return tasks

# PUBLIC_INTERFACE
@app.get("/tasks/{task_id}", response_model=Task, tags=["tasks"], summary="Get a task by ID")
def get_task(task_id: UUID, current_user: User = Depends(get_current_user)):
    """
    Get details of a specific task by ID.
    """
    task = fake_tasks_db.get(task_id)
    if not task or task["owner_id"] != current_user.id:
        raise HTTPException(status_code=404, detail="Task not found")
    return Task(**task)

# PUBLIC_INTERFACE
@app.put("/tasks/{task_id}", response_model=Task, tags=["tasks"], summary="Update a task by ID")
def update_task(task_id: UUID, task_update: TaskUpdate, current_user: User = Depends(get_current_user)):
    """
    Update one or more fields of a specific task.
    """
    task = fake_tasks_db.get(task_id)
    if not task or task["owner_id"] != current_user.id:
        raise HTTPException(status_code=404, detail="Task not found")
    updated = dict(task)
    if task_update.title is not None:
        updated["title"] = task_update.title
    if task_update.description is not None:
        updated["description"] = task_update.description
    if task_update.due_date is not None:
        updated["due_date"] = task_update.due_date
    if task_update.completed is not None:
        updated["completed"] = task_update.completed
    updated["updated_at"] = datetime.utcnow()
    fake_tasks_db[task_id] = updated
    return Task(**updated)

# PUBLIC_INTERFACE
@app.delete("/tasks/{task_id}", status_code=204, tags=["tasks"], summary="Delete a task by ID")
def delete_task(task_id: UUID, current_user: User = Depends(get_current_user)):
    """
    Delete a specific task by ID.
    """
    task = fake_tasks_db.get(task_id)
    if not task or task["owner_id"] != current_user.id:
        raise HTTPException(status_code=404, detail="Task not found")
    del fake_tasks_db[task_id]
    return

# PUBLIC_INTERFACE
@app.patch("/tasks/{task_id}/toggle", response_model=Task, tags=["tasks"], summary="Toggle task completion status")
def toggle_task_completed(task_id: UUID, current_user: User = Depends(get_current_user)):
    """
    Toggle the 'completed' status of a task.
    """
    task = fake_tasks_db.get(task_id)
    if not task or task["owner_id"] != current_user.id:
        raise HTTPException(status_code=404, detail="Task not found")
    updated = dict(task)
    updated["completed"] = not updated["completed"]
    updated["updated_at"] = datetime.utcnow()
    fake_tasks_db[task_id] = updated
    return Task(**updated)
