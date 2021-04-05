import os

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename

import models
from db_handler import db, db_init

# Initialize the Flask application
app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "./uploads/"
ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif"}
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

# DB
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///upload_db.sqlite3"
app.config["SECRET_KEY"] = "random string"
db_init(app)


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
            file_obj = models.files(
                filename, url_for("download_file", filename=filename)
            )
            db.session.add(file_obj)
            db.session.commit()
            flash("Record was successfully added")

    filenames = models.files.query.all()
    return render_template("upload.html", filenames=filenames)


if __name__ == "__main__":
    app.run(debug=True)
