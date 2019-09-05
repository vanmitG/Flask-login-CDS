from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = "KhoaTheBestDestroyer"
login = LoginManager(app)
login.login_view = "loginf"

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80))
    last_name = db.Column(db.String(80))
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128), nullable=False)
    created_date = db.Column(db.DateTime, default=datetime.now)
    updated_date = db.Column(db.DateTime, default=datetime.now)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


db.create_all()


@login.user_loader
def load_user(id):
    return User.query.get(int(id))


@app.route('/')
@login_required
def home():
    return render_template('layout.html')


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')


@app.route('/login', methods=['POST', 'GET'])
def loginf():
    if request.method == "POST":
        user = User.query.filter_by(email=request.form["email"]).first()
        if user is not None and user.check_password(request.form["password"]):
            # success
            login_user(user)
            flash(f'Yeah! Welcome, {user.email}', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Incorect username or password', 'danger')
            return redirect(url_for('loginf'))
    else:
        return render_template('login.html')


@app.route('/logout')
def logout():
    logout_user()
    flash('You are logged out, lets come back', 'info')
    return redirect(url_for('loginf'))


@app.route('/signup', methods=['POST', 'GET'])
def signup():
    if request.method == "POST":
        new_user = User(first_name=request.form["first_name"],
                        last_name=request.form["last_name"], email=request.form["email"])
        new_user.set_password(request.form["password"])
        db.session.add(new_user)
        db.session.commit()
        flash(
            f'Successfuly sign up {new_user.email}. Please Login!!!', 'success')
        return redirect(url_for('loginf'))
    else:
        flash('Please sign up!!!')
        return render_template('signup.html')


if __name__ == '__main__':
    app.run(debug=True)

# TODO disable this when running production because it does not let browser cache static content.
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
