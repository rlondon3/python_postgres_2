from flask import Flask, request, session, redirect, url_for, flash
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import os
import psycopg2
import psycopg2.extras
CREATE_USERS_TABLE = """CREATE TABLE IF NOT EXISTS users (
                        id serial PRIMARY KEY, 
                        first_name VARCHAR (100) NOT NULL, 
                        last_name VARCHAR (100) NOT NULL, 
                        user_name VARCHAR (50) NOT NULL,
                        city VARCHAR (100) NOT NULL,
                        state VARCHAR (2) NOT NULL,
                        password VARCHAR (255) NOT NULL,
                        email VARCHAR (50) NOT NULL
                    )"""
CREATE_INCREMENT_USERS_TABLE = "CREATE TABLE increment_users (id serial PRIMARY KEY)"
GET_USER = "SELECT * FROM users WHERE user_name = %s"

load_dotenv()
url = os.getenv("DATABASE_URL")
connection = psycopg2.connect(url)
#psycopg2.connect(dbname=DB_NAME_ENV_VAR, user=DB_USER_ENV, password=DB_PASSWRD_ENV_VAR, host=DB_HOST_ENV_VAR)

app = Flask(__name__)

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
            cursor.execute(GET_USER, (user_name))
            account = cursor.fetchone()

            if account:
                password_rs = account['password']
                print(password_rs)
                if check_password_hash(password_rs, password):
                    session['loggedin'] =  True
                    session['id'] = account['id']
                    session['user_name'] = account['user_name']
                    return {"message": account['user_name'] +" is logged in." + "Login success: " + {session['loggedin']}}
                else:
                    return {"message": "Please check user name and/or password"}
            else:
                return {"message": "Account not found!"}
          
