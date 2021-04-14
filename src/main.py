import os, hashlib, re, datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename

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

from flask_login import (
    LoginManager, 
    login_user, 
    login_required, 
    logout_user, 
    current_user, 
    UserMixin
)


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
    # Create subs dictionary for the templates
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
    # Flask app config
    SECRET_KEY = "random string"
    UPLOAD_FOLDER = "./uploads/"

    SQLALCHEMY_TRACK_MODIFICATIONS = True
    # Location of main database
    SQLALCHEMY_DATABASE_URI = "sqlite:///main_db.sqlite3"

    # Settings for improving cookie security
    # SECURE limits cookies to HTTPS traffic only
    SESSION_COOKIE_SECURE=True
    # HTTPONLY protects the contents of cookies from being read with JavaScript
    SESSION_COOKIE_HTTPONLY=True
    # SAMESITE restricts how cookies are sent with requests from external sites
    SESSION_COOKIE_SAMESITE='Lax'


# Initialize the Flask application
app = Flask(__name__)

# Use a config class to improve readability 
app.config.from_object(__name__+'.ConfigClass')

# Upload folder permission need to be check and full read write
ALLOWED_EXTENSIONS = {"txt", "doc", "docx", "xls", "xlsx", "pdf", "png", "jpg", "jpeg", "gif","csv"}


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

# Defines the `users` table in the database for SQLAlchemy
class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.String(100, collation='NOCASE'), nullable=False, unique=True, primary_key=True)
    password = db.Column(db.LargeBinary(), nullable=False, server_default='')
    salt = db.Column(db.LargeBinary(), nullable=False, server_default='')
    is_admin = db.Column(db.Boolean(), nullable=False, server_default='0')
    is_staff = db.Column(db.Boolean(), nullable=False, server_default='0')
    active = db.Column('is_active', db.Boolean(), nullable=False, server_default='1')


# Creates database if it doesn't already exist
db.create_all()

# Hardcode an admin user into the database username: 'admin' password: 'Admin123' - This will be removed once the first admin is made 
# I might do a bit more with this for eg. If all admins are deleted by mistake - Amy
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

# Password complexity minimum requirements: 8 characters long, 1 number, 1 symbol , 1 lower case letter, 1 upper case letter
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

# Redirects to permission denied template if user tries to access pages without logging in
@login_manager.unauthorized_handler
def unauthorized():
    return redirect('/permission_denied')

# Home page
@app.route('/')
def index():
    return render_template('index.html', subs=build_subs('Home'))

# Register new user page
@app.route('/register/')
def register_user():
    return render_template('register.html', subs=build_subs('Register'), error = "")

# Handle POST request for new user form
@app.route('/register/', methods=['POST'])
def register_user_post():
    username = request.form.get('username')
    password = request.form.get('password')
    confirm_password = request.form.get('confirmpassword')

    #Checks password meets complexity requirements
    if not password_check(password).get("password_ok"):
        # Returns error if it does not
        return render_template("register.html", subs=build_subs('Regsistration failed'), error="Password must be Min. 8 characters and contain at least 1 number, 1 uppercase, 1 lowercase, and a special character.")

    # Pass the error back if there is one
    success, error = register_user(username, password, confirm_password)

    if success:
        return render_template('login.html', subs=build_subs("Registration Successful"))

    return render_template("register.html", subs=build_subs('Regsistration'), error=error)

# User login page and login form
@app.route('/login', methods=['POST', 'GET'])
def login():
    # Process HTML login form
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Validate login credentials provided
        success = validate_login(username, password)
        
        if success:
            # login session with flask_login
            login_user(get_user(username))
            return redirect("/")
        return render_template("login.html", subs=build_subs('Home'), error="Login failed. Please try again.")

    # Display HTML login form
    elif request.method == 'GET':
        return render_template('login.html', subs=build_subs('Login'), error="")

# Allows user to view all files
@app.route("/files")
# Requires a user to be logged in, if user is not logged in redirects to permission denied page
@login_required
def files():
    filenames = Files.query.all()
    return render_template("all_files.html", subs = build_subs('Files'), files=filenames)

# Allows user to view only files they have uploaded
@app.route("/my_files")
# Requires a user to be logged in, if user is not logged in redirects to permission denied page
@login_required
def my_files():
    # Checks user has either 'staff' or 'admin' role, redirects to permission denied page if they do not.
    if not (current_user.is_staff or current_user.is_admin):
        return render_template('permission_denied.html', subs=build_subs('My Files'))
    
    # Get a list of all files where creator id and current logged in user match
    filenames = Files.query.filter(Files.creator_id == current_user.id)
    return render_template("my_files.html", subs = build_subs('Files'), files=filenames)

# Allows user to upload files or add a link to an external file, adds file info to the database.
@app.route("/upload", methods=["GET", "POST"])
# Requires a user to be logged in, if user is not logged in redirects to permission denied page
@login_required
def upload():
    # Checks user has either 'staff' or 'admin' role, redirects to permission denied page if they do not.
    if not (current_user.is_staff or current_user.is_admin):
        return render_template('permission_denied.html', subs=build_subs('Upload'))

    if request.method == 'GET':
        # return form for uploading a file
        return render_template('upload.html', subs=build_subs('Upload'))

    if request.method == 'POST':
        # process upload
        name = request.form.get('name')

        # Check if user has input a file name when attempting to upload a file
        if not name: 
            # Returns error message if no file name provided
            return render_template("upload.html", subs = build_subs('Upload'), error="No file name entered. Cannot upload file.")
        url = request.form.get('url')

        # If url field exists, user is submitting name + url form
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

        # url field did not exist, user submitting name + file form
        if "file" not in request.files:
            return render_template("upload.html", subs = build_subs('Upload'), error="File failed to send")

        file = request.files["file"]
        # if user does not select file, browser also submit an empty part without filename
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

# Expose uploaded files for downloading
@app.route("/downloads/<filename>")
def download_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# Search files in the database
@app.route("/search", methods=["GET", "POST"])
# Requires a user to be logged in, if user is not logged in redirects to permission denied page
@login_required
def search():
    if request.method == "POST":
        search_value = request.form.get('search-string')
        search = f"%{search_value}%"
        filenames = Files.query.filter(Files.name.like(search)).all()
        return render_template("all_files.html", subs=build_subs('Search'), files=filenames)
    else:
        return render_template("index.html", subs=build_subs('Search'))

# Allows user to delete a single file (id provided in route)       
@app.route("/delete/<int:id>")
# Requires a user to be logged in, if user is not logged in redirects to permission denied page
@login_required
def delete(id):
    # Checks user has either 'staff' or 'admin' role, redirects to permission denied page if they do not.
    if not (current_user.is_staff or current_user.is_admin):
        return redirect('/permission_denied')

    file = Files.query.filter(Files.id == id).first()

    # Checks if user trying to delete the files is either the creator or an admin
    if (file.creator_id != current_user.id) and not current_user.is_admin:
        return redirect('/permission_denied')        

    try:
        db.session.delete(file)
        db.session.commit()
        return redirect('/my_files')
    except:
        return "Error deleting file"

# Allows users to delete multiple files at once
@app.route('/delete', methods=['POST'])
# Requires a user to be logged in, if user is not logged in redirects to permission denied page
@login_required
def delete_multiple(): 
    # Checks user has either 'staff' or 'admin' role, redirects to permission denied page if they do not.
    if not (current_user.is_staff or current_user.is_admin):
        redirect('/permission_denied')
    if request.method == 'POST':
        # Processing items to delete checkboxes in HTML template
        f = request.form
        ids = []
        # Get all keys attached to HTML form
        for key in f.keys():
            # Get all keys that start with 'delete_' (key format will be delete_<id>)
            if key.startswith('delete_'):
                # Get the id out of the key
                id = key.split('_')[1]
                # Append id to list of ids to delete
                ids.append(id)
        
        # Delete all files containing the id's in the list
        files_to_delete = Files.query.filter(Files.id.in_(ids))

        # If user has 'staff' role, checks they are only trying to delete their own files 
        # (this is an extra check, they should not have the option to delete any files that aren't their own)
        # Doesn't run check if user is admin to improve efficiency as admin can delete all files anyway
        if not current_user.is_admin:
            for a in files_to_delete:
                # Compares the creator of the file with the current logged in user 
                if a.creator_id != current_user.id:
                    return redirect('/permission_denied')
        # Deletes selected files
        for a in files_to_delete:
            db.session.delete(a)

        db.session.commit()
    return redirect(request.referrer)

# Users can edit the links/paths to their own files
@app.route("/edit/<int:id>", methods=["POST", "GET"])
# Requires a user to be logged in, if user is not logged in redirects to permission denied page
@login_required
def edit(id):
    # Checks user has either 'staff' or 'admin' role, redirects to permission denied page if they do not.
    if not (current_user.is_staff or current_user.is_admin):
        return redirect('/permission_denied')

    file = Files.query.filter(Files.id == id).first()

    # Compares creator of the file with current logged in user, or if they are admin
    if (file.creator_id != current_user.id) and not current_user.is_admin:
        # Redirects to permission denied page if current user is neither an admin or creator of the file
        return redirect('/permission_denied')  

    if request.method == 'POST':
        # User inputs new file name or link
        new_url = request.form.get('new_url')
        new_title = request.form.get('new_title')

        # Update database with new file info
        if new_title:
            file.name = new_title
        if new_url:
            file.url = new_url

        db.session.commit()
        return redirect('/my_files')

    if request.method == 'GET':
        # add form for updating an element
        return render_template('edit.html', subs=build_subs(f"Edit {file.name} #{str(id)}"), file=file)

# Permission denied page
@app.route("/permission_denied")
def permission_denied():
    return render_template('permission_denied.html', subs=build_subs('Permission Denied'))

# Logout user page
@app.route("/logout")
# Requires a user to be logged in, if user is not logged in redirects to permission denied page
@login_required
def logout():
    logout_user()
    return render_template("index.html", subs=build_subs('Home'))

# Admin panel for user management and file management
@app.route("/admin")
# Requires a user to be logged in, if user is not logged in redirects to permission denied page
@login_required
def admin():
    # Checks current logged in user has 'Admin' role 
    if current_user.is_admin:
    # Pulls users from database to display them in the template
        admins = User.query.filter(User.is_admin == 1)
        staff = User.query.filter(User.is_admin == 0, User.is_staff == 1)
        users = User.query.filter(User.is_admin == 0, User.is_staff == 0)
        return render_template('admin.html', subs=build_subs('Admin'), admins=admins, staff=staff, users=users)
    else:
        # Redirects to permission denied page if user is not admin.
        return render_template('permission_denied.html', subs=build_subs('Admin'))

# Admin panel user management
@app.route("/admin/<action>/<level>/<id>")
# Requires a user to be logged in, if user is not logged in redirects to permission denied page
@login_required
def admin_functions(action, level, id):
    # Checks current logged in user has 'Admin' role and redirects to permission denied page if user is not admin.
    if current_user.is_admin == 0:
        return render_template('permission_denied.html', subs=build_subs('Admin'))
    
    user = User.query.filter(User.id == id).first()

    # Admin can promote users to higher roles
    if action=='promote':
        if level=='admin':
            user.is_admin = True
            user.is_staff = True
        elif level=='staff':
            user.is_staff = True

        db.session.commit()
        return redirect('/admin')
    
    #Admin can demote users to lower roles
    if action=='demote':
        if level=='staff':
            user.is_admin = False
        if level=='user':
            user.is_admin = False
            user.is_staff = False 

        db.session.commit()
        return redirect('/admin')
    # Admin can delete users
    if action=='delete':
        db.session.delete(user)
        db.session.commit()
        return redirect('/admin')

# Admin panel file management page
@app.route("/manage_files")
# Requires a user to be logged in, if user is not logged in redirects to permission denied page
@login_required
def manage_files():
    # Checks current logged in user has 'Admin' role and redirects to permission denied page if user is not admin.
    if not current_user.is_admin:
        redirect("/permission_denied")
    # Shows all files on admin file management page
    files = Files.query.all()
    return render_template("my_files.html", subs=build_subs("Manage All Files"), files=files)



def validate_login(username, password):
    #Checks the database for the supplied login credentials
    q = User.query.filter(User.id == username)

    # If the select statement found no match for the username, count will return 0
    if q.count() <= 0:
        return False

    key = q.first().password
    salt = q.first().salt

    # Check if the supplied hashed password matches the stored hashed password
    if key != hash_password(password, salt)[0]:
        return False

    return True

def register_user(username, password, confirmPassword):

    q = User.query.filter(User.id == username)

    if not password_check(password):
        return (False, "Password not secure")

    # If the select statement found an existing user, count will return 1
    if q.count() > 0:
        return (False, "User already exists. Please log in.")

    if password != confirmPassword:
        return (False, "Passwords didnt match")

    passAndSalt = hash_password(password)

    if (insert_new_user(username, passAndSalt[0], passAndSalt[1])):
        return (True, "Success")
    else: 
        return (False,"Adding to database failed")



def insert_new_user(username, password, salt):

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
    user = User.query.filter(User.id == username).first()

    return user


if __name__ == "__main__":
    app.run(debug=True)
