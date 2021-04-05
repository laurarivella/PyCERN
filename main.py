from flask import Flask
from flask import render_template
from flask import request
from flask import redirect
from flask import url_for
from flask import flash
from sqlalchemy import MetaData
from sqlalchemy import create_engine
from sqlalchemy import Column, String, BINARY
from sqlalchemy.orm import sessionmaker, query
from sqlalchemy.ext.declarative import declarative_base
import sqlalchemy
import hashlib
import json
import ast
import os
import sys
import sqlite3

app = Flask(__name__)
app.secret_key = b'\x88\xd0\xe4\x18\xc1\x1e\xe7\xfb~\xbb\xc7\xb3lP0\xb9\xcb>\xcd\x97\xb1\x18\xaa\n'

Base = declarative_base()

#Defines the User table in the database for SQLAlchemy
class User(Base):
    __tablename__ = 'USERS'

    ID = Column(String, primary_key=True)
    PASSWORD = Column(BINARY)
    SALT = Column(BINARY)

    def __repr__(self):
        return f'User {self.ID}'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register/')
def register_user():
    return render_template('register.html')

@app.route('/register/', methods=['POST'])
def register_user_post():
    username = request.form.get('username')
    password = request.form.get('password')
    confirm_password = request.form.get('confirmpassword')

    success = register_user(username, password, confirm_password)


    if success:
        flash("Registration Successful!")
        return redirect(url_for('login_user'))

    return redirect(url_for('register_user'))

@app.route('/login/')
def login_user():
    return render_template('login.html')

@app.route('/login/', methods=['POST'])
def login_user_post():
    username = request.form.get('username')
    password = request.form.get('password')

    success = validate_login(username, password)

    if success:
        flash(username + " login successful!")
    else:
        flash("Username or password incorrect. Please try again.")

    return redirect(url_for('login_user'))


def validate_login(username, password):
    "Checks the database for the supplied login credentials"
    db = create_engine('sqlite:///users2.db')
    db.echo = True

    metadata = MetaData(db)

    Session = sessionmaker(bind=db)
    session = Session()

    q = session.query(User).filter_by(ID=username)

    # If the select statement found no match for the username, count will return 0
    if q.count() <= 0:
        print("User not found. Please check your spelling and try again, or register a new user.\n")
        return False

    key = q.first().PASSWORD
    salt = q.first().SALT

    # Check if the supplied hashed password matches the stored hashed password
    if key != hash_password(password, salt)[0]:
        return False

    return True


def register_user(username, password, confirmPassword):
    # Check the database to see if the entered username is already taken
    db = create_engine('sqlite:///users2.db')
    db.echo = True

    metadata = MetaData(db)

    Session = sessionmaker(bind=db)
    session = Session()

    q = session.query(User).filter_by(ID=username)

    # If the select statement found an existing user, count will return 1
    if q.count() > 0:
        flash("User already exists. Please login or choose a different Username.\n")
        return False

    if password != confirmPassword:
        flash("Error: passwords didn't match. Please try registering again.")
        return False

    passAndSalt = hash_password(password)

    insert_new_user(username, passAndSalt[0], passAndSalt[1])

    return True

def insert_new_user(username, password, salt):
    db = create_engine('sqlite:///users2.db')
    db.echo = True

    metadata = MetaData(db)

    user = User(ID=username, PASSWORD=password, SALT=salt)

    Session = sessionmaker(bind=db)
    session = Session()


    session.add(user)
    session.commit()

    return

#If no salt is given, returns a new random salt with the hashed password.
#Otherwise, hashes the password with the supplied salt.
def hash_password(password, salt=None):
    if salt==None:
        salt = os.urandom(16)

    pass_bytes = salt + password.encode()

    key = hashlib.sha256(pass_bytes).digest()

    return (key, salt)

#For debugging flask things
def list_routes():
    import urllib
    output = []
    for rule in app.url_map.iter_rules():

        options = {}
        for arg in rule.arguments:
            options[arg] = "[{0}]".format(arg)

        methods = ','.join(rule.methods)
        url = url_for(rule.endpoint, **options)
        line = urllib.unquote("{:50s} {:20s} {}".format(rule.endpoint, methods, url))
        output.append(line)

    for line in sorted(output):
        print(line)
