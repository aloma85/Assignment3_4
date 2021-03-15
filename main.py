from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy import Boolean, Column, ForeignKey, func
from flask_migrate import Migrate

from flask_login import LoginManager, UserMixin, login_required, current_user, login_user, logout_user
import os
from flask_admin import Admin


app = Flask(__name__)

login_manager = LoginManager()
dir = os.path.abspath(os.path.dirname(__file__))
login_manager.init_app(app)
login_manager.login_view = "login"
admin = Admin(app)

@login_manager.user_loader
def load_user(userid):
    return Users.query.get(userid)

db = SQLAlchemy(app)
Migrate(app, db)

class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    note = relationship("Notes", backref="Users", lazy=True)