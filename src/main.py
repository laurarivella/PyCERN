import os, hashlib, re, datetime
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
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

"""
Admin user hard-coded in to begin - username: 'admin' password: 'Admin123'
"""

#If no salt is given, returns a new random salt with the hashed password.
#Otherwise, hashes the password with the supplied salt.
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)

    pass_bytes = salt + password.encode()

    key = hashlib.sha256(pass_bytes).digest()

    return key, salt

# Build a substitution dictionary to pass to the template
def build_subs(page=None):
    # Get information about current logged in user for template
    if current_user.is_authenticated:
        logged_in = True
        user = current_user.id
        is_admin = current_user.is_admin
        is_staff = current_user.is_staff
    else:
        # Default info if no one is logged in
        logged_in = False
        user = ""
        role = None
        is_admin = False
        is_staff = False
    subs = {
        'page': page,
        'user': user,
        'logged_in': logged_in,
        'is_admin': is_admin,
        'is_staff': is_staff,
    }
    return subs

# Enable class based application config
class ConfigClass(object):
    """Flask app config"""

    SECRET_KEY = "random string"
    UPLOAD_FOLDER = "./uploads/"

    SQLALCHEMY_TRACK_MODIFICATIONS = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///main_db.sqlite3"

    # Settings for improving cookie security
    SESSION_COOKIE_SECURE=True
    SESSION_COOKIE_HTTPONLY=True
    SESSION_COOKIE_SAMESITE='Lax'


# Initialize the Flask application
app = Flask(__name__)

# Use a config class to improve readability 
app.config.from_object(__name__+'.ConfigClass')

# Upload folder permission need to be check and full read write
ALLOWED_EXTENSIONS = {"txt", "doc", "docx", "xls", "xlsx", "pdf", "png", "jpg", "jpeg", "gif","csv"}

Base = declarative_base()

login_manager = LoginManager()
login_manager.init_app(app)

db = SQLAlchemy(app)

# Defines the `files` table in the database for SQLAlchemy
class Files(db.Model):
    __tablename__ = 'files'

    id = db.Column("file_id", db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    url = db.Column(db.String(200))
    created_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    creator_id = db.Column(db.String(100, collation='NOCASE'), nullable=False)
    downloadable = db.Column(db.Boolean(), nullable=False, server_default='0')

#D efines the `users` table in the database for SQLAlchemy
class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.String(100, collation='NOCASE'), nullable=False, unique=True, primary_key=True)
    password = db.Column(db.LargeBinary(), nullable=False, server_default='')
    salt = db.Column(db.LargeBinary(), nullable=False, server_default='')
    is_admin = db.Column(db.Boolean(), nullable=False, server_default='0')
    is_staff = db.Column(db.Boolean(), nullable=False, server_default='0')
    active = db.Column('is_active', db.Boolean(), nullable=False, server_default='1')

    # rewrote user class to be a different format to use the UserMixin
    # TODO remove this comment - just here to show change incase i break everything
    # ID = Column(String, primary_key=True)
    # PASSWORD = Column(BINARY)
    # SALT = Column(BINARY)
    # is_admin = db.Column(db.Boolean, default = False)

    # def __repr__(self):
    #     return f'User {self.ID}'

    # def is_authenticated(self):
    #     return True

    # def is_active(self):
    #     return True

    # def is_anonymous(self):
    #     return False

    # def get_id(self):
    #     return self.ID


#Defines the uploads table in the database for SQLAlchemy
class UploadedFile(db.Model):
    __tablename__ = 'uploads'

    file_id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(255))
    url = db.Column(db.String(255))
    created_date = db.Column(db.DateTime())
    edited_date = db.Column(db.DateTime())
    creator_id = db.Column(db.String(255))
    editor_id = db.Column(db.String(255))

    # rewrote to be same format as other definitions
    # TODO remove this comment - just here to show change incase i break everything
    # file_id = Column(INTEGER, primary_key=True)
    # name = Column(TEXT)
    # url = Column(TEXT)
    # created_date = Column(DATETIME)
    # edited_date = Column(DATETIME)
    # creator_id = Column(TEXT)
    # editor_id = Column(TEXT)

    # def __repr__(self):
    #     return f'UploadedFile {self.file_id}'

    # def is_authenticated(self):
    #     return True

    # def is_active(self):
    #     return True

    # def is_anonymous(self):
    #     return False

    # def get_id(self):
    #     return self.file_id


db.create_all()

#  Hardcode an admin user into the database
p,s = hash_password('Admin123')
if not User.query.filter(User.id == 'admin').first():
    user = User(
        id='admin',
        password=p,
        salt=s,
        is_admin = True,
        is_staff = True
    )
    db.session.add(user)
    db.session.commit()

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
    return User.query.get(user_id)

@app.route("/downloads/<filename>")
def download_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

@app.route('/')
def index():
    return render_template('index.html', subs=build_subs('Home'))

@app.route('/register/')
def register_user():
    return render_template('register.html', subs=build_subs('Register'), error = "")

@app.route('/register/', methods=['POST'])
def register_user_post():
    username = request.form.get('username')
    password = request.form.get('password')
    confirm_password = request.form.get('confirmpassword')

    if not password_check(password).get("password_ok"):
        # flash("Password not secure enough")
        return render_template("register.html", subs=build_subs('Regsistration failed'), error="Password not secure enough")

    # Pass the error back if there is one
    success, error = register_user(username, password, confirm_password)

    if success:
        return render_template('login.html', subs=build_subs("Registration Successful"))

    return render_template("register.html", subs=build_subs('Regsistration'), error=error)

# @app.route('/login/')
# def login_user_route():
#     # if current_user.is_authenticated:
#     #     flash("Welcome back " + current_user.id + "!")
#     #     return redirect(url_for("upload_file"))

#     return render_template('login.html', subs=build_subs('Login'))

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        success = validate_login(username, password)

        if success:
            login_user(get_user(username))
        return render_template("index.html", subs=build_subs('Home'))

        # USE the new render templates    
            # flash(current_user.__repr__() + " login successful!")
            # next = 'upload_file'
        # else:
        #     # flash("Username or password incorrect. Please try again.")
        #     # next = 'login_user_route'

        # return redirect(url_for(next))
    elif request.method == 'GET':
        return render_template('login.html', subs=build_subs('Login'))

@app.route("/files")
@login_required
def files():
    filenames = Files.query.all()
    return render_template("all_files.html", subs = build_subs('Files'), files=filenames)

@app.route("/my_files")
@login_required
def my_files():
    if not (current_user.is_staff or current_user.is_admin):
        return render_template('permission_denied.html', subs=build_subs('My Files'))
    filenames = Files.query.filter(Files.creator_id == current_user.id)
    return render_template("my_files.html", subs = build_subs('Files'), files=filenames)

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if not (current_user.is_staff or current_user.is_admin):
        return render_template('permission_denied.html', subs=build_subs('Upload'))

    if request.method == 'GET':
        # return form for uploading a file
        return render_template('upload.html', subs=build_subs('Upload'))

    if request.method == 'POST':
        # process upload
        name = request.form.get('name')
        url = request.form.get('url')

        if url:
            file_obj = Files(
                name=name,
                url=url,
                created_date=datetime.datetime.now(),
                creator_id=current_user.id,
                downloadable = False
            )
            db.session.add(file_obj)
            db.session.commit()
            return redirect('/my_files')

        if "file" not in request.files:
            flash("No file part", "error")
            return render_template("upload.html", subs = build_subs('Upload'), error="File failed to send")

        file = request.files["file"]
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == "":
            return render_template("upload.html", subs = build_subs('Upload'), error="No file selected")

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            file_obj = Files(
                name = name,
                url = url_for("download_file", filename=filename),
                created_date = datetime.datetime.now(),
                creator_id = current_user.id,
                downloadable = True
            )
            db.session.add(file_obj)
            db.session.commit()

            return render_template("upload.html", subs = build_subs('Upload'), error="File uploaded")
        else:
            return render_template("upload.html", subs = build_subs('Upload'), error="File invalid")



@app.route("/search", methods=["GET", "POST"])
@login_required
def search():
    if request.method == "POST":
        search_value = request.form.get('search-string')
        search = f"%{search_value}%"
        filenames = Files.query.filter(Files.name.like(search)).all()
        return render_template("all_files.html", subs=build_subs('Search'), files=filenames)
    else:
        return render_template("index.html", subs=build_subs('Search'))
        
@app.route("/delete/<int:id>")
@login_required
def delete(id):
    if not (current_user.is_staff or current_user.is_admin):
        return redirect('/permission_denied')

    # filename_to_delete = models.files.query.get_or_404(id)
    file = Files.query.filter(Files.id == id).first()

    if (file.creator_id != current_user.id) and not current_user.is_admin:
        return redirect('/permission_denied')        

    try:
        db.session.delete(file)
        db.session.commit()
        return redirect('/my_files')
    except:
        return "Error deleting file"

@app.route('/delete', methods=['GET', 'POST'])
def delete(): 
    print('delete')  
    if request.method == 'POST': 
        print(request.form.getlist('mycheckbox'))
        getids=request.form.getlist('mycheckbox')
        files.query.filter(files.id.in_(getids)).delete(synchronize_session='fetch')
        db.session.commit()
    return redirect('/')


@app.route("/edit/<int:id>", methods=["POST", "GET"])
@login_required
def edit(id):
    if not (current_user.is_staff or current_user.is_admin):
        return redirect('/permission_denied')

    # filename_to_delete = models.files.query.get_or_404(id)
    file = Files.query.filter(Files.id == id).first()

    if (file.creator_id != current_user.id) and not current_user.is_admin:
        return redirect('/permission_denied')  

    if request.method == 'POST':
        new_url = request.form.get('new_url')
        new_title = request.form.get('new_title')
      
        if new_title:
            file.name = new_title
        if new_url:
            file.url = new_url

        db.session.commit()
        return redirect('/my_files')

    if request.method == 'GET':
        # add form for updating an element
        return render_template('edit.html', subs=build_subs('Edit ' + str(id)), file=file)


@app.route("/permission_denied")
def permission_denied():
    return render_template('permission_denied.html', subs=build_subs('Permission Denied'))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return render_template("index.html", subs=build_subs('Home'))

@app.route("/admin")
@login_required
def admin():
    if current_user.is_admin:
        admins = User.query.filter(User.is_admin == 1)
        staff = User.query.filter(User.is_admin == 0, User.is_staff == 1)
        users = User.query.filter(User.is_admin == 0, User.is_staff == 0)
        files = Files.query.all()
        return render_template('admin.html', subs=build_subs('Admin'), admins=admins, staff=staff, users=users, files=files)
    else:
        return render_template('permission_denied.html', subs=build_subs('Admin'))

@app.route("/admin/<action>/<level>/<id>")
@login_required
def admin_functions(action, level, id):
    if current_user.is_admin == 0:
        return render_template('permission_denied.html', subs=build_subs('Admin'))
    
    user = User.query.filter(User.id == id).first()

    if action=='promote':
        if level=='admin':
            user.is_admin = True
            user.is_staff = True
        elif level=='staff':
            user.is_staff = True

        db.session.commit()
        return redirect('/admin')
    
    if action=='demote':
        if level=='staff':
            user.is_admin = False
        if level=='user':
            user.is_admin = False
            user.is_staff = False 

        db.session.commit()
        return redirect('/admin')

    if action=='delete':
        db.session.delete(user)
        db.session.commit()
        return redirect('/admin')



def validate_login(username, password):
    "Checks the database for the supplied login credentials"
    # Used the already open db handles 
    # TODO remove the old code
     
    # db = create_engine('sqlite:///users2.db')
    # db.echo = True

    # metadata = MetaData(db)

    # Session = sessionmaker(bind=db)
    # session = Session()

    q = User.query.filter(User.id == username)

    # If the select statement found no match for the username, count will return 0
    if q.count() <= 0:
        print("User not found. Please check your spelling and try again, or register a new user.\n")
        return False

    key = q.first().password
    salt = q.first().salt

    # Check if the supplied hashed password matches the stored hashed password
    if key != hash_password(password, salt)[0]:
        return False

    return True

def register_user(username, password, confirmPassword):
    # Check the database to see if the entered username is already taken
    # Used the already open db handles 
    # TODO remove the old code

    # db = create_engine('sqlite:///users2.db')
    # db.echo = True

    # metadata = MetaData(db)

    # Session = sessionmaker(bind=db)
    # session = Session()

    q = User.query.filter(User.id == username)

    if not password_check(password):
        flash("Password not secure enough.")
        return (False, "Password not secure")

    # If the select statement found an existing user, count will return 1
    if q.count() > 0:
        flash("User already exists. Please login or choose a different Username.\n")
        return (False, "User already exists")

    if password != confirmPassword:
        flash("Error: passwords didn't match. Please try registering again.")
        return (False, "Passwords didnt match")

    passAndSalt = hash_password(password)

    if (insert_new_user(username, passAndSalt[0], passAndSalt[1])):
        return (True, "Success")
    else: 
        return (False,"Adding to database failed")



def insert_new_user(username, password, salt):
    # Used the already open db handles 
    # TODO remove the old code

    #  db.echo = True

    # metadata = MetaData(db)

    # user = User(id=username, password=password, salt=salt)

    # Session = sessionmaker(bind=db)
    # session = Session()

    # session.add(user)
    # session.commit()

    # return
    if not User.query.filter(User.id == username).first():
        user = User(
            id = username,
            password = password,
            salt = salt,
            is_admin = False,
            is_staff = False,
        )
        db.session.add(user)
        db.session.commit()
        return True
    else:
        # User already exists 
        return False 

def get_user(username):
    # Used the already open db handles 
    # TODO remove the old code
    # db.echo = True

    # metadata = MetaData(db)

    # Session = sessionmaker(bind=db)
    # session = Session()

    # q = session.query(User).filter_by(id=username)

    # if q.count() < 1:
    #     return None

    # return q[0]

    user = User.query.filter(User.id == username).first()

    return user


if __name__ == "__main__":
    app.run(debug=True)
