from fastapi import FastAPI, Request, HTTPException, Depends, status
from base64 import b64decode
import uvicorn

app = FastAPI()

# A simple user database (for demonstration only)
USERS = {
    "admin": "admin",
    "user1": "password1",
}

def basic_auth(request: Request):
    # Extract the "Authorization" header from the incoming request.
    auth = request.headers.get("Authorization")
    if not auth:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials.",
        )

    # The header should be in the form: "Basic <encoded_credentials>"
    try:
        scheme, credentials = auth.split(" ")
        if scheme.lower() != "basic":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication scheme. Expected 'Basic'.",
            )
        # Decode the Base64 encoded credentials
        decoded_bytes = b64decode(credentials)
        decoded_str = decoded_bytes.decode("utf-8")
        # Expecting credentials in "username:password" format
        username, password = decoded_str.split(":", 1)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials format.",
        )

    # Validate credentials against the USERS database
    if USERS.get(username) == password:
        return username
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

@app.get("/")
def index():
    return {"message": "Welcome to our API!"}

@app.get("/public-data")
def public_data():
    return {"data": "This is publicly available data."}

@app.get("/secure-data")
def secure_data(username: str = Depends(basic_auth)):
    # This endpoint is now secured using the basic_auth dependency.
    return {"data": f"Hello {username}, this is secure data accessible only with valid credentials."}

if __name__ == '__main__':
    uvicorn.run(app, host="127.0.0.1", port=8000)



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