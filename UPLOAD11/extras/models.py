from db_handler import db
from flask_sqlalchemy import SQLAlchemy
import datetime


class files(db.Model):
    id = db.Column("file_id", db.Integer, primary_key=True)
    #setup primary key
    name = db.Column(db.String(100))
    #Name with 100 charater string
    url = db.Column(db.String(200))
    created_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    #seutp default time of creating at the time of upload

    #def __repr__(self):
    # how our object is renter
    #    return f"files('{self.name}','{self.url}')"

    def __init__(self, name, url):
        self.name = name
        self.url = url
        self.created_date = datetime.datetime.now()
