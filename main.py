from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_wtf import FlaskForm
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'
login_manager = LoginManager()
login_manager.init_app(app)

# CREATE DATABASE
class Base(DeclarativeBase):
    pass

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CREATE TABLE IN DB
class User(db.Model, UserMixin):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["POST", "GET"])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        user_already_exist = db.session.execute(db.select(User).where(User.email == email)).scalar()
        if user_already_exist:
            flash("User already exist, please login.")
            return redirect(url_for("login"))
        else:
            password = generate_password_hash(password=request.form.get("password"), method='pbkdf2:sha256', salt_length=8)
            new_user = User(
                email=email,
                name=request.form.get('name'),
                password=password
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return render_template("secrets.html", name=request.form.get('name'), logged_in=new_user.is_authenticated)
    return render_template("register.html")


@app.route('/login', methods=["POST", "GET"])
def login():
    err = None

    if request.method == 'POST':
        email = request.form.get("email")
        password = request.form.get("password")
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('You were successfully logged in')
            return redirect(url_for('secrets'))
        else:
            err = True
            flash('Invalid credentials')

    return render_template("login.html", err=err)


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html", logged_in=True)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    directory = 'static'
    path = 'files/cheat_sheet.pdf'
    return send_from_directory(
        directory=directory, path=path
    )


if __name__ == "__main__":
    app.run(debug=True)
