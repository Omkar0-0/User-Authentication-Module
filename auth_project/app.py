from flask import Flask, render_template, request, redirect, url_for, session, flash
from models import db, User
from functools import wraps
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET', 'change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)


def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return wrapped


def create_tables():
    db.create_all()

if hasattr(app, 'before_first_request'):
    app.before_first_request(create_tables)
elif hasattr(app, 'before_serving'):
    app.before_serving(create_tables)
else:
    with app.app_context():
        create_tables()


@app.route('/')
def index():
    user = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
    return render_template('index.html', user=user)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']

        if not username or not email or not password:
            flash('Please fill all fields', 'warning')
            return redirect(url_for('register'))

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('User with that username or email already exists', 'danger')
            return redirect(url_for('register'))

        u = User(username=username, email=email)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        flash('Registration successful. Please sign in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form['identifier'].strip()
        password = request.form['password']

        user = User.query.filter((User.username == identifier) | (User.email == identifier)).first()
        if user and user.check_password(password):
            session.clear()
            session['user_id'] = user.id
            flash('Signed in successfully', 'success')
            return redirect(url_for('index'))
        flash('Invalid credentials', 'danger')
        return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'info')
    return redirect(url_for('index'))


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        current = request.form['current_password']
        new = request.form['new_password']
        confirm = request.form['confirm_password']
        if not user.check_password(current):
            flash('Current password incorrect', 'danger')
            return redirect(url_for('change_password'))
        if new != confirm:
            flash('New passwords do not match', 'warning')
            return redirect(url_for('change_password'))
        user.set_password(new)
        db.session.commit()
        flash('Password changed', 'success')
        return redirect(url_for('index'))
    return render_template('change_password.html', user=user)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        bio = request.form.get('bio', '').strip()
        user.full_name = full_name
        user.bio = bio
        db.session.commit()
        flash('Profile updated', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html', user=user)


if __name__ == '__main__':
    app.run(debug=True)
