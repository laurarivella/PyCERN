<<<<<<< HEAD
import os, hashlib
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
=======
import os, hashlib, re
from flask_login import LoginManager, login_user, current_user, logout_user
>>>>>>> main
from sqlalchemy import Column, String, BINARY, INTEGER, TEXT, DATETIME
from sqlalchemy import MetaData, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, query

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for
)
#from db_handler import db
import datetime

from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename

#import models

# Initialize the Flask application
app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "./uploads/"
# Upload folder permission need to be check and full read write
ALLOWED_EXTENSIONS = {"txt", "doc", "docx", "xls", "xlsx", "pdf", "png", "jpg", "jpeg", "gif","csv"}
#app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

Base = declarative_base()

login_manager = LoginManager()
login_manager.init_app(app)

# DB
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///upload_db.sqlite3"
#sqlite with 3 slashes is for reletive path of the database
app.config["SECRET_KEY"] = "random string"

# Options added to improve cookie security
app.config.update(
# SECURE limits cookies to HTTPS traffic only
    SESSION_COOKIE_SECURE=True,
# HTTPONLY protects the contents of cookies from being read with JavaScript
    SESSION_COOKIE_HTTPONLY=True,
# SAMESITE restricts how cookies are sent with requests from external sites
    SESSION_COOKIE_SAMESITE='Lax',
)
#response.set_cookie('username', 'flask', secure=True, httponly=True, samesite='Lax')

#db_init(app)

# Function that initializes the db and creates the tables
#def __init__(self, name, url):
#    self.name = name
#    self.url = url
#    self.created_date = datetime.datetime.now()

# Creates the logs tables if the db doesnt already exist
#    with app.app_context():
#        db.create_all()

db = SQLAlchemy(app)

class files(db.Model):
    id = db.Column("file_id", db.Integer, primary_key=True)
    #setup primary key
    name = db.Column(db.String(100))
    #Name with 100 charater string
    url = db.Column(db.String(200))
    created_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    #seutp default time of creating at the time of upload

    #def __init__(self, name, url):
    #    self.name = name
    #    self.url = url
    #    self.created_date = datetime.datetime.now()

#Defines the USERS table in the database for SQLAlchemy
class User(Base):
    __tablename__ = 'USERS'

    ID = Column(String, primary_key=True)
    PASSWORD = Column(BINARY)
    SALT = Column(BINARY)
    is_admin = db.Column(db.Boolean, default = False)

    def __repr__(self):
        return f'User {self.ID}'

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.ID

#Defines the uploads table in the database for SQLAlchemy
class UploadedFile(Base):
    __tablename__ = 'uploads'

    file_id = Column(INTEGER, primary_key=True)
    name = Column(TEXT)
    url = Column(TEXT)
    created_date = Column(DATETIME)
    edited_date = Column(DATETIME)
    creator_id = Column(TEXT)
    editor_id = Column(TEXT)

    def __repr__(self):
        return f'UploadedFile {self.file_id}'

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.file_id

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# password complexity minimum requirements: 8 characters long, 1 number, 1 symbol , 1 lower case letter, 1 upper case letter
def password_check(password):

    length_error = len(password) < 8
    digit_error = re.search(r"\d", password) is None
    uppercase_error = re.search(r"[A-Z]", password) is None
    lowercase_error = re.search(r"[a-z]", password) is None
    symbol_error = re.search(r"\W", password) is None
    password_ok = not ( length_error or digit_error or uppercase_error or lowercase_error or symbol_error )

    return {
        'password_ok' : password_ok,
        'length_error' : length_error,
        'digit_error' : digit_error,
        'uppercase_error' : uppercase_error,
        'lowercase_error' : lowercase_error,
        'symbol_error' : symbol_error,
    }

@login_manager.user_loader
def load_user(user_id):
    return get_user(user_id)

@app.route("/downloads/<filename>")
def download_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

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

    if not password_check(password).get("password_ok"):
        flash("Password not secure enough")
        return render_template("register.html")

    success = register_user(username, password, confirm_password)

    if success:
        flash("Registration Successful!")
        return redirect(url_for('login_user_route'))

    return redirect(url_for('register_user'))

@app.route('/login/')
def login_user_route():
    if current_user.is_authenticated:
        flash("Welcome back " + current_user.ID + "!")
        return redirect(url_for("upload_file"))
    return render_template('login.html')

@app.route('/login/', methods=['POST'])
def login_user_post():
    username = request.form.get('username')
    password = request.form.get('password')

    success = validate_login(username, password)

    if success:
        login_user(get_user(username))

        flash(current_user.__repr__() + " login successful!")
        next = 'upload_file'
    else:
        flash("Username or password incorrect. Please try again.")
        next = 'login_user_route'

    return redirect(url_for(next))

@app.route("/files", methods=["GET", "POST"])
@login_required
def upload_file():

    if request.method == "POST":
        # check if the post request has the file part
        if "file" not in request.files:
            flash("No file part", "error")
            return redirect(request.url)
        file = request.files["file"]
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == "":
            flash("No selected file", "error")
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            file_obj = files(
                filename, url_for("download_file", filename=filename)
            )
            db.session.add(file_obj)
            db.session.commit()
            flash("Record was successfully added")

    filenames = files.query.all()
    return render_template("upload.html", filenames=filenames)

@app.route("/search", methods=["GET", "POST"])
def search():

    if request.method == "POST":
        form = request.form
        search_value = form['search_string']
        search = f"%{search_value}%"
        filenames = files.query.filter(files.name.like(search)).all()
        return render_template("search.html", filenames=filenames)
    else:
        return redirect('/')
        
@app.route("/delete/<int:id>",methods=['POST'])
def delete(id):
     filename_to_delete = models.files.query.get_or_404(id)
     try:
         db.session.delete(filename_to_delete)
         db.session.commit()
         return redirect('/')
     except:
        return "Error deleting file"


@app.route("/logout")
def logout():
    logout_user()

    return redirect(url_for("index"))


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

    if not password_check(password):
        flash("Password not secure enough.")
        return

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

def get_user(username):
    db = create_engine('sqlite:///users2.db')
    db.echo = True

    metadata = MetaData(db)

    Session = sessionmaker(bind=db)
    session = Session()

    q = session.query(User).filter_by(ID=username)

    if q.count() < 1:
        return None

    return q[0]

#If no salt is given, returns a new random salt with the hashed password.
#Otherwise, hashes the password with the supplied salt.
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)

    pass_bytes = salt + password.encode()

    key = hashlib.sha256(pass_bytes).digest()

    return key, salt


if __name__ == "__main__":
    app.run(debug=True)
