import os

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

# DB
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///upload_db.sqlite3"
#sqlite with 3 slashes is for reletive path of the database
app.config["SECRET_KEY"] = "random string"

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


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/downloads/<filename>")
def download_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


@app.route("/", methods=["GET", "POST"])
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



if __name__ == "__main__":
    app.run(debug=True)
