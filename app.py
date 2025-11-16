import os
import sys
from datetime import datetime
from getpass import getpass

from flask import (
    Flask, render_template, request, redirect, url_for,
    send_from_directory, flash, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ----- CONFIG -----
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'ebooks')
ALLOWED_EXT = {'pdf'}
SECRET_KEY = os.environ.get('LAS_SECRET_KEY', 'replace_this_secret')

# ----- APP -----
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'las.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 80 * 1024 * 1024  # 80 MB
app.secret_key = SECRET_KEY

db = SQLAlchemy(app)

# ----- LOGIN -----
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# ----- MODELS -----
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(300), nullable=False)
    role = db.Column(db.String(20), default='student')  # 'student' or 'admin'
    created_on = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

class LoginHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(100))

    user = db.relationship('User')


class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), nullable=False)
    author = db.Column(db.String(200), nullable=True)
    year = db.Column(db.String(10), nullable=True)
    filename = db.Column(db.String(300), nullable=False)
    uploaded_on = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Book {self.title}>'

# ----- INITIAL SETUP (Flask 3 compatible) -----
with app.app_context():
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    db.create_all()

# ----- LOGIN HANDLERS -----
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(fn):
    """Decorator to restrict route to admin users."""
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Admin access required.', 'error')
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    return wrapper

# ----- HELPERS -----
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

# ----- ROUTES -----
@app.route('/')
def index():
    q = request.args.get('q', '').strip()
    if q:
        books = Book.query.filter(
            (Book.title.ilike(f'%{q}%')) | (Book.author.ilike(f'%{q}%'))
        ).order_by(Book.uploaded_on.desc()).all()
    else:
        books = Book.query.order_by(Book.uploaded_on.desc()).limit(50).all()
    return render_template('index.html', books=books, q=q)

@app.route('/book/<int:book_id>')
def book_detail(book_id):
    book = Book.query.get_or_404(book_id)
    return render_template('book.html', book=book)

@app.route('/ebooks/<path:filename>')
def serve_ebook(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ----- AUTH ROUTES -----
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            flash('Username and password are required.', 'error')
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash('Username already taken.', 'error')
            return redirect(url_for('register'))
        user = User(username=username, role='student')
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            flash('Invalid credentials.', 'error')
            return redirect(url_for('login'))
        login_user(user)
        flash('Logged in successfully.', 'success')
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'success')
    return redirect(url_for('index'))

# ----- ADMIN UPLOAD/DELETE (protected) -----
@app.route('/admin/upload', methods=['GET', 'POST'])
@admin_required
def upload_book():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        author = request.form.get('author', '').strip()
        year = request.form.get('year', '').strip()
        file = request.files.get('file')
        if not title or not file:
            flash('Title and PDF file are required.', 'error')
            return redirect(url_for('upload_book'))
        if not allowed_file(file.filename):
            flash('Only PDF files are allowed.', 'error')
            return redirect(url_for('upload_book'))
        filename = secure_filename(f"{int(datetime.utcnow().timestamp())}_{file.filename}")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        book = Book(title=title, author=author, year=year, filename=filename)
        db.session.add(book)
        db.session.commit()
        flash('Book uploaded successfully.', 'success')
        return redirect(url_for('index'))
    return render_template('upload.html')

@app.route('/admin/delete/<int:book_id>', methods=['POST'])
@admin_required
def delete_book(book_id):
    book = Book.query.get_or_404(book_id)
    try:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], book.filename))
    except Exception:
        pass
    db.session.delete(book)
    db.session.commit()
    flash('Book deleted.', 'success')
    return redirect(url_for('index'))

# ----- ADMIN CLI: create_admin -----
def create_admin_cli():
    username = input('Admin username: ').strip()
    if not username:
        print('Username required.')
        return
    if User.query.filter_by(username=username).first():
        print('User exists. Exiting.')
        return
    pw = getpass('Admin password: ')
    pw2 = getpass('Confirm password: ')
    if pw != pw2:
        print('Passwords do not match.')
        return
    admin = User(username=username, role='admin')
    admin.set_password(pw)
    db.session.add(admin)
    db.session.commit()
    print('Admin user created.')

# ----- RUN -----
if __name__ == '__main__':
    # allow: python app.py create_admin
    if len(sys.argv) > 1 and sys.argv[1] == 'create_admin':
        with app.app_context():
            create_admin_cli()
        sys.exit(0)

    # normal run
    app.run(debug=True)
