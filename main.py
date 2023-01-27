#
# REST API
# Untuk Autentikasi
# SMABOY Canteen
#
# 2023 Hendra Manudinata
#

from flask import Flask
from flask import jsonify, request

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

from flask_jwt_extended import create_access_token, create_refresh_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

from datetime import timedelta

app = Flask(__name__)
app.secret_key = "secret-here"
app.config["JSON_SORT_KEYS"] = False

app.config ["SQLALCHEMY_DATABASE_URI"] = "sqlite:///user.sqlite3"
db = SQLAlchemy(app)
class User(db.Model):
   id = db.Column(db.Integer, primary_key = True, unique=True)
   username = db.Column(db.String(100))
   password = db.Column(db.String(100))

app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=1)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)
jwt = JWTManager(app)

def check_password(password_db, password):
    password_hash = generate_password_hash(password_db)
    return check_password_hash(password_hash, password)

@app.route("/")
def home():
    return jsonify(msg="Hello, World!")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", None)
    password = request.form.get("password", None)
    if not username or not password:
        return jsonify(msg="Insufficient arguments!")

    user = User.query.filter_by(username=username).one_or_none()

    if not user or not check_password(user.password, password):
        return jsonify(msg="Wrong user/pass!"), 401

    access_token = create_access_token(identity=username)
    refresh_token = create_refresh_token(identity=username)
    return jsonify(access_token=access_token, refresh_token=refresh_token)

@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    return jsonify(access_token=access_token)

@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    return jsonify(msg="If you see this, then you've successfully authenticated!")

if __name__ == "__main__":
    app.run(port=27723)
