from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta
import uvicorn

# JWT configuration
SECRET_KEY = "secret"  # In production, use a strong, unpredictable key.
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

# OAuth2 schema: expects the token in the Authorization header as "Bearer <token>".
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# In-memory user store for demonstration.
VALID_USERS = {
    "admin": "admin",
    "user1": "password1",
}

# Function to create the JWT token.
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return token

# Function to decode and validate a JWT token.
def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )

# Dependency to extract the current user from the JWT token.
def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = decode_access_token(token)
    # Check if the token contains the "sub" claim (subject).
    if not payload or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )
    return payload["sub"]

def get_current_admin(token: str = Depends(oauth2_scheme)):
    payload = decode_access_token(token)
    if not payload or "sub" not in payload or payload.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return payload["sub"]

# Public endpoints remain unchanged.
@app.get("/")
def index():
    return {"message": "Welcome to our API!"}

@app.get("/public-data")
def public_data():
    return {"data": "This is public data accessible by anyone."}

# Login endpoint to obtain JWT token.
@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    username = form_data.username
    password = form_data.password

    if username not in VALID_USERS or VALID_USERS[username] != password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    
    # Set a role based on username (or from your database)
    role = "admin" if username == "admin" else "user"
    
    access_token = create_access_token(data={"sub": username, "role": role})
    return {"access_token": access_token, "token_type": "bearer"}

# Protected endpoint: accessible only with a valid JWT.
@app.get("/secure-data")
def secure_data(current_user: str = Depends(get_current_user)):
    return {"message": f"Hello {current_user}, you have access to this secure data!"}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)


@app.get("/admin-data")
def admin_data(current_admin: str = Depends(get_current_admin)):
    return {"message": f"Hello {current_admin}, you have admin access!"}




'''(NO AUTHENTICATION)
from fastapi import FastAPI
import uvicorn

app = FastAPI()

@app.get("/")
def index():
    return {"message": "Welcome to our API! No authentication required."}

@app.get("/public-data")
def public_data():
    return {"data": "This is public data accessible by anyone."}

@app.get("/secure-data")
def secure_data():
    # This endpoint is currently unprotected
    return {"data": "This is sensitive data that should eventually be secured with JWT."}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
'''