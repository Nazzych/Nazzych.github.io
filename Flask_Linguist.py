from flask import Flask, render_template, request, url_for, flash, redirect
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///blog.db"
app.config['SECRET_KEY'] = 'your_secret_key'
ceruvanya = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

class User(ceruvanya.Model, UserMixin):
    id = ceruvanya.Column(ceruvanya.Integer, primary_key=True)
    username = ceruvanya.Column(ceruvanya.String(20), nullable=False)
    email = ceruvanya.Column(ceruvanya.String(120), unique=True, nullable=False)
    password = ceruvanya.Column(ceruvanya.String(128), nullable=False)

    def __repr__(self):
        return f"<User {self.email}>"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
@app.route("/home")
def hello_world():
    user = current_user
    return render_template("home.html", user=user)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash("You are now logged in!", "success")
            return redirect(url_for("hello_world"))
        else:
            flash("Login Unsuccessful. Please check email and password", "danger")
    return render_template("login.html", user=current_user)

@app.route("/singing", methods=["GET", "POST"])
def user_singing():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email address already exists. Please use a different email.", "danger")
            return redirect("/singing")

        user = User(username=username, email=email, password=hashed_password)
        try:
            ceruvanya.session.add(user)
            ceruvanya.session.commit()
            login_user(user)
            flash("Your account has been created and you are now logged in!", "success")
            return redirect("/home")
        except Exception as e:
            flash("Your account hasn't been created! Error: " + str(e), "danger")
            ceruvanya.session.rollback()
            return redirect("/singing")
    return render_template("singing.html", user=current_user)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("hello_world"))

@app.route("/deck")
@login_required
def create_deck():
    return render_template("create_deck.html", user=current_user)

@app.route("/account")
@login_required
def account():
    return render_template("account.html", user=current_user)

if __name__ == "__main__":
    with app.app_context():
        ceruvanya.create_all()
    app.run(debug=True, port=8080)
