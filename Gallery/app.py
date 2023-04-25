import os
from flask import Flask, render_template, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Length, Email
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from flask_uploads import UploadSet, IMAGES, configure_uploads

basedir = os.path.abspath(os.path.dirname(__file__))

UPLOAD_FOLDER = 'static/rsm'
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = \
    'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['UPLOADED_PHOTOS_DEST'] = UPLOAD_FOLDER

app.config['SECRET_KEY'] = 'thisissecretkey'
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
photos = UploadSet('photos', IMAGES)
configure_uploads(app, photos)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(80))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=4, max=80)])


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=4, max=80)])
    remember = BooleanField('remember me')


@app.route("/")
def first():
    return render_template("first.html")


@app.route("/home", methods=['GET', 'POST'])
@login_required
def Home():
    return render_template("home.html", name=current_user.username)


@app.route("/detail", methods=['GET', 'POST'])
def detay():
    return render_template("detaill.html", name=current_user.username)


@app.route("/resim", methods=['GET', 'POST'])
def resim():
    if request.method == 'POST' and 'photo' in request.files:
        mfile = request.files['photo']
        print(mfile.filename)
        mfile.save(os.path.join(app.config['UPLOADED_PHOTOS_DEST'], mfile.filename))
        current_user.photo_url = mfile.filename
        db.session.commit()
        return redirect(url_for('dashboard2', fname=mfile.filename))
    return render_template("rsm.html", name=current_user.username)


@app.route("/dashboard2/<string:fname>")
def dashboard2(fname):
    return render_template("home.html", fname=fname)


@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('Home'))
            return '<h1>Invalid username or password</h1>'

    return render_template("login.html", form=form)


@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return '<h1>New user has been created!</h1>'

    return render_template("register.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('first'))


if __name__ == "__main__":
    app.run(debug=True)
