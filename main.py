from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy import Boolean, Column, ForeignKey, func
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash

from flask_login import LoginManager, UserMixin, login_required, current_user, login_user, logout_user
import jwt
import datetime
from functools import wraps
import os
from flask_admin.contrib.sqla import ModelView
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


app.config['SECRET_KEY'] = 'Th1s1ss3cr3t'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(dir, "notes.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db = SQLAlchemy(app)
Migrate(app, db)


class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    note = relationship("Notes", backref="Users", lazy=True)


class Notes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    body = db.Column(db.String(255))
    user = Column(db.Integer, ForeignKey('users.id'), nullable=False)


admin.add_view(ModelView(Users, db.session))
admin.add_view(ModelView(Notes, db.session))


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):

        token = None

        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

        if not token:
            return jsonify({'message': 'a valid token is missing'})

        try:
            data = token
            current_user = Users.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'token is invalid'})

            return f(current_user, *args, **kwargs)

    return decorator


@app.route('/register', methods=['GET', 'POST'])
def signup_user():
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = Users(name=data['name'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'registered successfully'})


@app.route('/login', methods=['GET', 'POST'])
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})

    user = Users.query.filter_by(name=auth.username).first()

    if check_password_hash(user.password, auth.password):
        token = jwt.encode(
            {'id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            app.config['SECRET_KEY'])
        login_user(user)
        return jsonify({'token': token})

    return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})


@app.route("/delete_User/<int:id>", methods=["DELETE"])
def delete_user(id):
    user = Users.query.get(id)
    if not user:
        return jsonify({'message': 'No User available with this id'})
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted'})


@app.route("/delete_notes/<int:id>", methods=["DELETE"])
def delete_Note(id):
    note = Notes.query.get(id)
    if not note:
        return jsonify({'message': 'No notes available with this id'})
    db.session.delete(note)
    db.session.commit()
    return jsonify({'message': 'note deleted'})


@app.route('/note', methods=['POST'])
def add_note():
    data = request.get_json()
    new_note = Notes(title=data['title'],body=data["body"], user=current_user.id)
    db.session.add(new_note)
    db.session.commit()

    return jsonify({'message':"added"})


@app.route("/user/<int:id>" , methods=["POST"])
def get_all_notes(id):
    note = Notes.query.all()
    if not note:
        return jsonify({"message":"No notes found for this users"})
    notes = {}
    for note in note:
        value = {'id':note.id ,'title': note.title, "body":note.body,
                 'user':1}
        notes.update(value)
    return jsonify({"notes":notes})


@app.route("/notes/<int:id>" , methods=["POST","GET"])
def note_by_id(id):
    note = Notes.query.get(id)
    if not note:
        return jsonify({"message":"No Notes found of this Id"})
    notes = {}
    value = {"id":note.id,"title":note.title,"body":note.body}
    notes.update(value)

    return jsonify({"notes":notes})


@app.route("/notes/<title>", methods = ["POST","GET"])
def note_by_title(title):
    note = Notes.query.filter_by(title = title).first()
    if not note:
        return jsonify({"message":"No notes found with specifiec title"})
    notes = {}
    notes.update({"id":note.id,"title":note.title,"body":note.body})
    return jsonify({"notes":notes})


@app.route("/user/note/<int:id>" , methods = ["POST"])
def update_note_by_id(id):
    data = request.get_json()
    note = Notes.query.get(id)
    if not note:
        return jsonify({"Message":"No Notes present with this Id"})
    note.title = data["title"]
    note.body = data["body"]
    db.session.commit()
    return jsonify({"message":"successfully update through id"})


@app.route("/user/note/<title>" , methods=["PUT"])
def update_note_by_title(title):
    data = request.get_json()
    note = Notes.query.filter_by(title = title).first()
    if not note:
        return jsonify({"Message":"No notes present with this title"})
    note.title = data["title"]
    note.body = data["body"]
    db.session.commit()
    return jsonify({"Message":"sucessfully update through title"})

if __name__=="__main__":
    app.run(debug=True)