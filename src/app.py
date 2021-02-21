import json
from bson.objectid import ObjectId
from flask import Flask, config
from flask.globals import request
from flask.wrappers import Response
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from jwt import decode, encode, ExpiredSignatureError, InvalidTokenError
from datetime import timedelta, datetime
from bson import json_util

app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb://localhost:27017/flask"
mongo = PyMongo(app)


def decode_token(token):
    try:
        payload = decode(token, "secret")
        return payload["sub"]
    except ExpiredSignatureError:
        return "Signature expired, Please Login Again"
    except InvalidTokenError:
        return "Invalid Token"


@app.route("/users", methods=["POST"])
def createUser():
    # data
    try:
        username = request.json["username"]
        email = request.json["email"]
        password = generate_password_hash(request.json["password"])
    except:
        return {"msg": "We Need A Username Email And A Password"}

    if username and email and password:
        try:
            id = mongo.db.users.insert(
                {"username": username, "email": email, "password": password}
            )
            print(str(id))
            payload = {
                "exp": datetime.utcnow() + timedelta(days=1),
                "iat": datetime.utcnow(),
                "sub": str(id),
            }

            token = encode(payload, "secret", algorithm="HS256")
            print(token)
            return {"token": str(token)}
        except Exception as e:
            print(e)
            return {"msg": "Error By Inserting The Data in The Db"}

    return {
        "msg": "received",
    }


@app.route("/login",methods=['POST'])
def login():
    try:
        email = request.json["email"]
        password = request.json["password"]
    except:
        return {"msg": "We Need A Username Email And A Password"}
    try:
        user = mongo.db.users.find_one({
            "email": email
        })
        print(user)
        verify = check_password_hash(user['password'],password)

        print(str(user['_id']))
        payload = {
            "exp": datetime.utcnow() + timedelta(days=1),
            "iat": datetime.utcnow(),
            "sub": str(id),
        }

        token = encode(payload, "secret", algorithm="HS256")
        print(token)
        return {"token": str(token)}
    except Exception as e:
        print(e)
        return {"msg": "Error"}


@app.route("/profile")
def profile():
    try:
        user_id = decode_token(request.headers["x-access-token"])
        user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
        res = json_util.dumps(user)
        return Response(res, mimetype="application/json")
    except Exception as e:
        print(e)
        return {"msg": "Token Invalid"}


if __name__ == "__main__":
    app.run(debug=True)