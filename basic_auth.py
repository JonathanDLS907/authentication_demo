from fastapi import FastAPI, Request, HTTPException, Depends, status
from base64 import b64decode, b64encode
import uvicorn

app = FastAPI()
USERS = {
    "admin": "admin",
    "user1": "password1",
}

def basic_auth(request: Request):
    auth = request.headers.get("Authorization")

    if not auth:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    
    encode_credentials = auth.split(" ")[1]
    try:
        decoded_bytes = b64decode(encode_credentials)
        decoded_str = decoded_bytes.decode("utf-8")
        username, password = decoded_str.split(":")
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )

    if USERS.get(username) == password:
        return username
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )

@app.get("/secure-data")
async def secure_data(username: str = Depends(basic_auth)):
    return {"message": f"Hello {username}, you have access to this secure data!"}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
# To test the basic authentication, you can use curl or Postman.