from flask import Flask,jsonify, render_template, request,make_response
from function import generateToken,decode_jwt,hash_password
from loguru import logger
import pymongo
import json
import jwt
import bcrypt
import os
from dotenv import load_dotenv
load_dotenv()

client = pymongo.MongoClient('mongodb://localhost:27017/')
db = client[os.getenv('DATABASE')]
app = Flask(__name__)


@app.route('/login',methods=['GET'])
def login():
    try:
        users_collection = db[os.getenv('USER_COLLECTION')]
        data = request.get_json()
        username = data['username']
        password = data['password']
        passwordDB = (users_collection.find_one({"username":username}))["password"]
        unHashedPassword = str(password)
        bytes = unHashedPassword.encode('utf-8')
        validate = bcrypt.checkpw(bytes,passwordDB)
        if not validate:
            response = {'message': 'User not loggeed IN'}
            return make_response(jsonify(response), 404)
        response = {'message': 'User logged IN successfully'}
        return make_response(jsonify(response), 200)
    except:
        response = {'message': 'User login Error'}
        return make_response(jsonify(response), 400)

@app.route('/register',methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data['username']
        password = data['password']
        hashedPassword = hash_password(password)
        agent_id = data['agent_id']
        token = generateToken(app,{"agent_id":agent_id})  
        logger.info("Token Generated")
        logger.info(f"token:{token}")
        users_collection = db[os.getenv('USER_COLLECTION')]
        new_user={'username':username,'password':hashedPassword,'agent_id':agent_id}
        users_collection.insert_one(new_user)
        response = {'message': 'User added successfully'}
        return make_response(jsonify(response), 200)
    except:
        response = {'message': 'Error in adding user'}
        return make_response(jsonify(response), 400)
        
@app.route('/update',methods=['PATCH'])
def update():
    try:
        data = request.get_json()
        data = request.get_json()
        updateKey = request.args.get('id')
        updaterField = request.args.get('updater')
        token = request.headers.get("Authorization")
        authenticatedUser = (decode_jwt(token,os.getenv('SECRET')))["agent_id"]
        if(str(authenticatedUser)!=updateKey):
            response = {'message': 'User not authenticated'}
            return make_response(jsonify(response), 400)
        
        users_collection = db[os.getenv('USER_COLLECTION')]
        print(list(users_collection.find()))
        if updaterField == 'username':
            new_username = data['username']
            users_collection.update_one({"agent_id": updateKey}, {"$set": {"username": new_username}})
        else:
            new_password = data['password']
            users_collection.update_one({"agent_id": updateKey}, {"$set": {"password": new_password}})
        
        response = {'message': 'User details updated successfully'}
        return make_response(jsonify(response), 200)
    except:
        response = {'message': 'User added not added'}
        return make_response(jsonify(response), 400)

@app.route('/delete',methods=['DELETE'])
def delete():
    try:
        agentID = request.args.get('id')
        users_collection = db[os.getenv('USER_COLLECTION')]
        users_collection.delete_one({"agent_id": agentID})
        response = {'message': 'User deleted successfully'}
        return make_response(jsonify(response), 200)
    except:
        response = {'message': 'User not deleted'}
        return make_response(jsonify(response), 400)

@app.route('/listUser',methods=['GET'])
def listUser():
    try:
        updateKey = request.args.get('id')
        
        users_collection = db[os.getenv('USER_COLLECTION')]
        # print(list(users_collection.find()))
        users = list(users_collection.find())
        token = request.headers.get("Authorization")
        authenticatedUser = (decode_jwt(token,os.getenv('SECRET')))["agent_id"]
        for user in users:
            user['_id'] = str(user['_id'])
        print(users)
        if(str(authenticatedUser)!=updateKey):
            response = {'message': 'User not authenticated'}
            return make_response(jsonify(response), 400)
        response = {'message': 'User details updated successfully'}
        return make_response(jsonify(response), 200)
    except:
        response = {'message': 'Cannot list details'}
        return make_response(jsonify(response), 400)
        

if __name__=="__main__":
    app.run(host='0.0.0.0',port=os.getenv('PORT'), debug=True)
    logger.debug(f"Flask app started at port:{os.getenv('PORT')}")



