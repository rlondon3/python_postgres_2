from flask import Flask, request, session, redirect, url_for, flash
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import os
import re
import psycopg2
import psycopg2.extras

CREATE_USERS_TABLE = """CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY, 
                        first_name VARCHAR (100) NOT NULL, 
                        last_name VARCHAR (100) NOT NULL,
                        city VARCHAR (100) NOT NULL,
                        state VARCHAR (2) NOT NULL, 
                        user_name VARCHAR (50) NOT NULL,
                        email VARCHAR (50) NOT NULL,
                        password VARCHAR (255) NOT NULL
                        )"""
CREATE_INCREMENT_USERS_TABLE = "CREATE TABLE increment_users (id serial PRIMARY KEY)"
GET_USER = "SELECT * FROM users WHERE user_name = %s"
INSERT_INTO_USERS_TABLE_RETURNING_ID = """INSERT INTO users (
                                        first_name, 
                                        last_name, 
                                        city, 
                                        state, 
                                        user_name, 
                                        email, 
                                        password
                                    ) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id"""

load_dotenv()
url = os.getenv("DATABASE_URL")
connection = psycopg2.connect(url)
#psycopg2.connect(dbname=DB_NAME_ENV_VAR, user=DB_USER_ENV, password=DB_PASSWRD_ENV_VAR, host=DB_HOST_ENV_VAR)

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

@app.route("/")
def home():
    if 'loggedin' in session:
        return {"message": {session['user_name']}}, 201
    return {"message": "User is not logged in!"}
@app.post("/api/login")
def login():
    data = request.get_json()
    user_name = data["user_name"]
    password = data["password"]
    with connection:
        with connection.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
            cursor.execute(CREATE_USERS_TABLE)
            cursor.execute(GET_USER, (user_name,))
            account = cursor.fetchone()

            if account:
                password_rs = account['password']
                if check_password_hash(password_rs, password):
                    session['loggedin'] =  True
                    session['id'] = account['id']
                    session['user_name'] = account['user_name']
                    return {"message": "Login successful!"}, 201
                else:
                    return {"message": "Please check user name and/or password"}
            else:
                return {"message": "Account not found!"}
@app.post("/api/signup")
def register():
    data = request.get_json()
    first_name = data['first_name']
    last_name = data['last_name']
    city = data['city']
    state = data["state"]
    user_name =  data['user_name']
    email = data['email']
    password = data['password']
    
    with connection:
        with connection.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
            cursor.execute(CREATE_USERS_TABLE)
            cursor.execute(GET_USER, (user_name,))
            account = cursor.fetchone()
            if account:
                return {"message": "User already exists. Please login."}
            elif not re.match(r'[^@]+@[^@]+\.[^a]+', email):
                return {"message": "Invalid: please check email address."}
            elif not re.match(r'[A-Za-z0-9]+', user_name):
                return {"message": "Invalid: username must contain only characters and numbers."}
            elif not user_name or not password or not email:
                return {"message": "Invalid: please check username, email, and password."}
            else:
                cursor.execute(INSERT_INTO_USERS_TABLE_RETURNING_ID, (first_name, last_name, city, state, user_name, email, generate_password_hash(password)))
                connection.commit()
                return {"message": "User successful registered"}, 201

