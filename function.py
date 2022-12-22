import jwt
import os
import bcrypt
from dotenv import load_dotenv
load_dotenv()


def hash_password(password):
    password = str(password)
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)

def generateToken(app, userDetails):
    app.config["JWT_SECRET_KEY"] = "secret"
    return jwt.encode(userDetails, app.config["JWT_SECRET_KEY"],algorithm="HS256").encode("utf-8")

def decode_jwt(encoded,secret_key):
    print(jwt)
    return jwt.decode(encoded, "secret", algorithms=["HS256"])
    # return jwt.decode(jwt, secret_key,algorithm="HS256")