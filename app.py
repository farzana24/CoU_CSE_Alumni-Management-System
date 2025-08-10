from flask import Flask, render_template, request, abort, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_ 
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import time
from pytz import timezone
from functools import wraps
import random
import os

# Flask App Configuration
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/alumni_management'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# Database Setup
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Flask-Login Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Flask-Login User Loader
@login_manager.user_loader
def load_user(user_id):
    if user_id.startswith('admin_'):
        real_id = int(user_id.split('_')[1])
        admin = Admin.query.get(real_id)
        if admin:
            admin.type = 'admin'
            return admin
    elif user_id.startswith('teacher_'):
        real_id = int(user_id.split('_')[1])
        teacher = Teacher.query.get(real_id)
        if teacher:
            teacher.type = 'teacher'
            return teacher
    elif user_id.startswith('student_'):
        real_id = int(user_id.split('_')[1])
        student = Student.query.get(real_id)
        if student:
            student.type = 'student'
            return student
    else:
        user = User.query.get(int(user_id))
        if user:
            user.type = 'user'
            return user
    return None

def unauthorized_handler():
    if request.path.startswith('/admin'):
        flash('Please log in as admin first.', 'error')
        return redirect(url_for('admin_login'))
    elif request.path.startswith('/teacher'):
        flash('Please log in as teacher first.', 'error')
        return redirect(url_for('teacher_login'))
    elif request.path.startswith('/student'):
        flash('Please log in as student first.', 'error')
        return redirect(url_for('student_login'))
    flash('Please log in to access this page.', 'error')
    return redirect(url_for('login'))


# File Uploads
UPLOAD_FOLDER = 'static/uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

GALLERY_FOLDER = 'static/gallery/'
app.config['GALLERY_FOLDER'] = GALLERY_FOLDER


# Contact Model
class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), nullable=False)
    message = db.Column(db.Text, nullable=False)

# Alumni Details Model
class AlumniDetails(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)
    blood_group = db.Column(db.String(3), nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    cse_batch = db.Column(db.String(10), nullable=False)
    company_name = db.Column(db.String(150), nullable=False)
    position = db.Column(db.String(150), nullable=False)
    alumni_pic = db.Column(db.String(150), nullable=True)
    linkedin_url = db.Column(db.String(255), nullable=True)
    github_url = db.Column(db.String(255), nullable=True)
    research_gate_url = db.Column(db.String(255), nullable=True)
    google_scholar_url = db.Column(db.String(255), nullable=True)
    orcid_url = db.Column(db.String(255), nullable=True)
    personal_website = db.Column(db.String(255), nullable=True)
    
# User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    alumni_details = db.relationship('AlumniDetails', backref='user', uselist=False, cascade='all, delete-orphan')

class Admin(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_super_admin = db.Column(db.Boolean, default=False)
    last_login = db.Column(db.DateTime)
    def get_id(self):
        return f'admin_{self.id}'
    
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in as admin', 'error')
            return redirect(url_for('admin_login'))
        if not isinstance(current_user, Admin):
            logout_user()
            flash('Admin access required', 'error')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def teacher_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in as teacher', 'error')
            return redirect(url_for('teacher_login'))
        if not hasattr(current_user, 'type') or current_user.type != 'teacher':
            logout_user()
            flash('Teacher access required', 'error')
            return redirect(url_for('teacher_login'))
        return f(*args, **kwargs)
    return decorated_function

def student_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in as student', 'error')
            return redirect(url_for('student_login'))
        if not hasattr(current_user, 'type') or current_user.type != 'student':
            logout_user()
            flash('Student access required', 'error')
            return redirect(url_for('student_login'))
        return f(*args, **kwargs)
    return decorated_function

# News Model
class News(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(150), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=True)
    author_id = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=False)
    is_published = db.Column(db.Boolean, default=True)
    views = db.Column(db.Integer, default=0)
    author = db.relationship('Admin', backref=db.backref('news_posts', lazy=True))
    def __repr__(self):
        return f'<News {self.title}>'
    
    @property
    def formatted_date(self):
        bd_timezone = timezone('Asia/Dhaka')
        return self.created_at.astimezone(bd_timezone).strftime('%B %d, %Y %I:%M %p')
    
class JobOpportunity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    company = db.Column(db.String(200), nullable=False)
    location = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    requirements = db.Column(db.Text, nullable=False)
    salary_range = db.Column(db.String(100), nullable=True)
    employment_type = db.Column(db.String(50), nullable=False)  # Full-time, Part-time, Contract
    experience_level = db.Column(db.String(50), nullable=False)  # Entry, Mid, Senior
    apply_url = db.Column(db.String(500), nullable=True)
    contact_email = db.Column(db.String(150), nullable=True)
    deadline = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    posted_by_admin = db.Column(db.Boolean, default=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=True)
    alumni_id = db.Column(db.Integer, db.ForeignKey('alumni_details.id'), nullable=True)
    
    # Relationships
    admin = db.relationship('Admin', backref=db.backref('job_posts', lazy=True))
    alumni = db.relationship('AlumniDetails', backref=db.backref('job_posts', lazy=True))
    
    def __repr__(self):
        return f'<JobOpportunity {self.title} at {self.company}>'
    
    @property
    def formatted_date(self):
        bd_timezone = timezone('Asia/Dhaka')
        return self.created_at.astimezone(bd_timezone).strftime('%B %d, %Y')
    
    @property
    def formatted_deadline(self):
        if self.deadline:
            bd_timezone = timezone('Asia/Dhaka')
            return self.deadline.astimezone(bd_timezone).strftime('%B %d, %Y')
        return None
    
    @property
    def poster_name(self):
        if self.posted_by_admin and self.admin:
            return f"Admin: {self.admin.username}"
        elif self.alumni:
            return f"{self.alumni.first_name} {self.alumni.last_name}"
        return "Unknown"

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    event_date = db.Column(db.DateTime, nullable=False)
    location = db.Column(db.String(200), nullable=False)
    image = db.Column(db.String(150), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=True)
    max_participants = db.Column(db.Integer, nullable=True)
    registration_deadline = db.Column(db.DateTime, nullable=True)
    author_id = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=False)
    author = db.relationship('Admin', backref=db.backref('events', lazy=True))

    def __repr__(self):
        return f'<Event {self.title}>'

    @property
    def formatted_date(self):
        bd_timezone = timezone('Asia/Dhaka')
        return self.created_at.astimezone(bd_timezone).strftime('%B %d, %Y')

    @property
    def formatted_event_date(self):
        bd_timezone = timezone('Asia/Dhaka')
        return self.event_date.astimezone(bd_timezone).strftime('%B %d, %Y %I:%M %p')

    @property
    def formatted_registration_deadline(self):
        if self.registration_deadline:
            bd_timezone = timezone('Asia/Dhaka')
            return self.registration_deadline.astimezone(bd_timezone).strftime('%B %d, %Y %I:%M %p')
        return None

    @property
    def is_upcoming(self):
        return self.event_date > datetime.now()

    @property
    def can_register(self):
        if not self.registration_deadline:
            return True
        return datetime.now() < self.registration_deadline

class Teacher(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    name = db.Column(db.String(150), nullable=False)
    designation = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(100), default="Computer Science and Engineering")
    photo = db.Column(db.String(150), nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    bio = db.Column(db.Text, nullable=True)
    research_interests = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    def get_id(self):
        return f'teacher_{self.id}'

class Student(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    name = db.Column(db.String(150), nullable=False)
    student_id = db.Column(db.String(50), unique=True, nullable=False)
    batch = db.Column(db.String(10), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    photo = db.Column(db.String(150), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    def get_id(self):
        return f'student_{self.id}'

class Donation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    donor_name = db.Column(db.String(150), nullable=False)
    donor_email = db.Column(db.String(150), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class PasswordResetOTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), nullable=False)
    otp = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_type = db.Column(db.String(20), nullable=False)  # 'student', 'teacher', 'alumni'
    is_used = db.Column(db.Boolean, default=False)
    
    def is_expired(self):
        return datetime.utcnow() > self.created_at + timedelta(minutes=15)

# Home Route
@app.route("/")
def home():
    images = [f for f in os.listdir(UPLOAD_FOLDER) if f.endswith(('.png', '.jpg', '.jpeg', '.gif'))]
    return render_template('home.html', images=images)

# Login Route
@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username_or_email = request.form.get('emailOrUsername')
        password = request.form.get('password')
        

        # Check if user exists
        user = User.query.filter((User.username == username_or_email) | (User.email == username_or_email)).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully', 'success')
            return redirect(url_for('dashboard'))
        elif not user:
            flash('User not registered', 'error')
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Wrong password', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')

# Logout Route
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'warning')
    return redirect(url_for('login'))

@app.route("/teacher-login", methods=['GET', 'POST'])
def teacher_login():
    if current_user.is_authenticated and hasattr(current_user, 'type'):
        if current_user.type == 'teacher':
            return redirect(url_for('teacher_dashboard'))
        logout_user()

    if request.method == 'POST':
        username_or_email = request.form.get('email')
        password = request.form.get('password')

        teacher = Teacher.query.filter(
            (Teacher.username == username_or_email) | 
            (Teacher.email == username_or_email)
        ).first()

        if teacher and check_password_hash(teacher.password, password):
            login_user(teacher)
            flash('Logged in successfully as teacher', 'success')
            return redirect(url_for('teacher_dashboard'))
        else:
            flash('Invalid teacher credentials', 'error')

    return render_template('teacher_login.html')

@app.route("/student-login", methods=['GET', 'POST'])
def student_login():
    if current_user.is_authenticated and hasattr(current_user, 'type'):
        if current_user.type == 'student':
            return redirect(url_for('student_dashboard'))
        logout_user()

    if request.method == 'POST':
        username_or_email = request.form.get('studentId')
        password = request.form.get('password')

        student = Student.query.filter(
            (Student.username == username_or_email) | 
            (Student.email == username_or_email) |
            (Student.student_id == username_or_email)
        ).first()

        if student and check_password_hash(student.password, password):
            login_user(student)
            flash('Logged in successfully as student', 'success')
            return redirect(url_for('student_dashboard'))
        else:
            flash('Invalid student credentials', 'error')

    return render_template('student_login.html')
# Common forgot password route that redirects based on user type
@app.route("/forgot-password", methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user_type = request.form.get('user_type')
        
        # Validate user type
        if user_type not in ['student', 'teacher', 'alumni']:
            flash('Invalid user type', 'error')
            return redirect(url_for('forgot_password'))
        
        # Find user based on type
        user = None
        if user_type == 'student':
            user = Student.query.filter_by(email=email).first()
        elif user_type == 'teacher':
            user = Teacher.query.filter_by(email=email).first()
        elif user_type == 'alumni':
            user = User.query.filter_by(email=email).first()
        
        if not user:
            flash('No account found with that email', 'error')
            return redirect(url_for('forgot_password'))
        
        # Generate OTP (6 digits)
        otp = str(random.randint(100000, 999999))
        
        # Store OTP in database
        new_otp = PasswordResetOTP(
            email=email,
            otp=otp,
            user_type=user_type,
            is_used=False
        )
        db.session.add(new_otp)
        db.session.commit()
        
        # In a real app, you would send this via email
        # For this implementation, we'll print to console
        print(f"\n\nPassword reset OTP for {email} ({user_type}): {otp}\n\n")
        
        flash('OTP sent to console (simulated email)', 'info')
        session['reset_email'] = email
        session['reset_user_type'] = user_type
        return redirect(url_for('verify_otp'))
    
    return render_template('forgot_password.html')

# OTP verification route
@app.route("/verify-otp", methods=['GET', 'POST'])
def verify_otp():
    if 'reset_email' not in session or 'reset_user_type' not in session:
        flash('Please request password reset first', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        otp = request.form.get('otp')
        email = session['reset_email']
        user_type = session['reset_user_type']
        
        # Find the most recent valid OTP
        otp_record = PasswordResetOTP.query.filter_by(
            email=email,
            user_type=user_type,
            is_used=False
        ).order_by(PasswordResetOTP.created_at.desc()).first()
        
        if not otp_record or otp_record.otp != otp:
            flash('Invalid OTP', 'error')
            return redirect(url_for('verify_otp'))
        
        if otp_record.is_expired():
            flash('OTP has expired', 'error')
            return redirect(url_for('forgot_password'))
        
        # Mark OTP as used
        otp_record.is_used = True
        db.session.commit()
        
        # Store verification in session
        session['otp_verified'] = True
        return redirect(url_for('reset_password'))
    
    return render_template('verify_otp.html')

# Password reset route
@app.route("/reset-password", methods=['GET', 'POST'])
def reset_password():
    if 'reset_email' not in session or 'reset_user_type' not in session:
        flash('Please request password reset first', 'error')
        return redirect(url_for('forgot_password'))
    
    if 'otp_verified' not in session or not session['otp_verified']:
        flash('Please verify OTP first', 'error')
        return redirect(url_for('verify_otp'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('reset_password'))
        
        # Validate password strength
        if (not any(char.isupper() for char in password) or
           not any(char.islower() for char in password) or
           not any(char.isdigit() for char in password) or
           not any(char in '!@#$%^&*()_+-=[]{}|;:,.<>?/' for char in password) or
           len(password) < 8):
            flash('Password must contain at least one uppercase, one lowercase, one number, one special character, and be at least 8 characters long', 'error')
            return redirect(url_for('reset_password'))
        
        # Update password based on user type
        email = session['reset_email']
        user_type = session['reset_user_type']
        
        if user_type == 'student':
            user = Student.query.filter_by(email=email).first()
            login_route = 'student_login'
        elif user_type == 'teacher':
            user = Teacher.query.filter_by(email=email).first()
            login_route = 'teacher_login'
        elif user_type == 'alumni':
            user = User.query.filter_by(email=email).first()
            login_route = 'login'
        
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('forgot_password'))
        
        # Update password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        user.password = hashed_password
        db.session.commit()
        
        # Clear session
        session.pop('reset_email', None)
        session.pop('reset_user_type', None)
        session.pop('otp_verified', None)
        
        flash('Password updated successfully! Please login with your new password', 'success')
        return redirect(url_for(login_route))
    
    return render_template('reset_password.html')

# Dashboard Route
@app.route("/dashboard")
@login_required
def dashboard():
    if not current_user.alumni_details:
        flash('Please complete your profile first', 'warning')
        return redirect(url_for('user_details'))
    return render_template('dashboard.html', alumni_details=current_user.alumni_details)

@app.route("/teacher/dashboard")
@login_required
def teacher_dashboard():
    if not hasattr(current_user, 'type') or current_user.type != 'teacher':
        flash('Teacher access required', 'error')
        return redirect(url_for('teacher_login'))
    return render_template('teacher_dashboard.html', teacher=current_user)

@app.route("/teacher/edit-profile", methods=['GET', 'POST'])
@login_required
@teacher_required
def edit_teacher_profile():
    if request.method == 'POST':
        try:
            # Verify current password
            current_password = request.form.get('current_password')
            if not check_password_hash(current_user.password, current_password):
                flash('Current password is incorrect', 'error')
                return redirect(url_for('teacher_dashboard'))

            # Update profile information
            current_user.name = request.form.get('name')
            current_user.designation = request.form.get('designation')
            current_user.department = request.form.get('department')
            current_user.phone = request.form.get('phone')
            current_user.email = request.form.get('email')
            current_user.research_interests = request.form.get('research_interests')
            current_user.bio = request.form.get('bio')

            # Handle photo upload
            if 'photo' in request.files:
                file = request.files['photo']
                if file and allowed_file(file.filename):
                    # Delete old photo if exists
                    if current_user.photo:
                        old_photo_path = os.path.join('static', 'teachers', current_user.photo)
                        if os.path.exists(old_photo_path):
                            os.remove(old_photo_path)
                    
                    # Save new photo
                    filename = secure_filename(f"teacher_{current_user.id}_{int(time.time())}.{file.filename.rsplit('.', 1)[1].lower()}")
                    file.save(os.path.join('static', 'teachers', filename))
                    current_user.photo = filename

            db.session.commit()
            flash('Profile updated successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating profile: {str(e)}', 'error')
        
        return redirect(url_for('teacher_dashboard'))
    
    return redirect(url_for('teacher_dashboard'))

@app.route("/student/dashboard")
@login_required
def student_dashboard():
    if not hasattr(current_user, 'type') or current_user.type != 'student':
        flash('Student access required', 'error')
        return redirect(url_for('student_login'))
    return render_template('student_dashboard.html', student=current_user)

@app.route("/student/edit-profile", methods=['GET', 'POST'])
@login_required
def edit_student_profile():
    """Allow a logged-in student to edit basic profile fields and photo."""
    if not hasattr(current_user, 'type') or current_user.type != 'student':
        flash('Student access required', 'error')
        return redirect(url_for('student_login'))

    student = current_user  # alias

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        batch = request.form.get('batch', '').strip()
        phone = request.form.get('phone', '').strip()

        if name:
            student.name = name
        if batch:
            student.batch = batch
        student.phone = phone if phone else None

        # Handle photo upload
        file = request.files.get('photo')
        if file and file.filename and allowed_file(file.filename):
            ext = file.filename.rsplit('.', 1)[1].lower()
            filename = secure_filename(f"student_{student.id}.{ext}")
            upload_dir = os.path.join('static', 'student')
            os.makedirs(upload_dir, exist_ok=True)
            path = os.path.join(upload_dir, filename)
            file.save(path)
            student.photo = filename

        try:
            db.session.commit()
            flash('Profile updated successfully', 'success')
            return redirect(url_for('student_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Error updating profile', 'error')

    return render_template('edit_student_profile.html', student=student)

@app.route("/student/privacy-security", methods=['GET', 'POST'])
@login_required
def student_privacy_security():
    if not hasattr(current_user, 'type') or current_user.type != 'student':
        flash('Student access required', 'error')
        return redirect(url_for('student_login'))

    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not check_password_hash(current_user.password, current_password):
            flash('Current password is incorrect', 'error')
            return redirect(url_for('student_privacy_security'))

        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return redirect(url_for('student_privacy_security'))

        current_user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
        db.session.commit()
        flash('Password updated successfully', 'success')
        return redirect(url_for('student_dashboard'))

    return render_template('student_privacy_security.html')

@app.route("/student/delete-profile", methods=['GET', 'POST'])
@login_required
def delete_student_profile():
    if not hasattr(current_user, 'type') or current_user.type != 'student':
        flash('Student access required', 'error')
        return redirect(url_for('student_login'))

    if request.method == 'POST':
        try:
            # Delete profile photo if exists
            if current_user.photo:
                photo_path = os.path.join('static', 'student', current_user.photo)
                if os.path.exists(photo_path):
                    os.remove(photo_path)
            
            # Delete student record
            db.session.delete(current_user)
            db.session.commit()
            logout_user()
            flash('Your account has been permanently deleted', 'info')
            return redirect(url_for('home'))
        except Exception as e:
            db.session.rollback()
            flash('Error deleting profile', 'error')
    
    return render_template('confirm_delete_student.html')

@app.route("/teacher-logout")
@login_required
def teacher_logout():
    if hasattr(current_user, 'type') and current_user.type == 'teacher':
        logout_user()
        flash('Teacher logged out successfully', 'info')
    return redirect(url_for('teacher_login'))

@app.route("/student-logout")
@login_required
def student_logout():
    if hasattr(current_user, 'type') and current_user.type == 'student':
        logout_user()
        flash('Student logged out successfully', 'info')
    return redirect(url_for('student_login'))

@app.route("/admin")
@login_required
@admin_required
def admin():
    return redirect(url_for('admin_dashboard'))

@app.route("/admin/dashboard")
@login_required
@admin_required
def admin_dashboard():
    # Get page parameter from request
    page = request.args.get('page', 1, type=int)
    
    # Query data needed for dashboard stats
    users = User.query.all()
    contacts = Contact.query.all()
    
    # Paginate alumni instead of getting all at once
    alumni_pagination = AlumniDetails.query.order_by(
        AlumniDetails.id.desc()  # Order by newest first
    ).paginate(page=page, per_page=5, error_out=False)
    
    # Get total count for stats
    alumni_count = AlumniDetails.query.count()
    
    # Only fetch admin list for super admins
    admin_list = []
    if current_user.is_super_admin:
        admin_list = Admin.query.filter(Admin.id != current_user.id).all()
    donations = Donation.query.order_by(Donation.created_at.desc()).all()   
    return render_template('admin_dashboard.html', 
                         users=users, 
                         alumni_count=alumni_count,
                         alumni_pagination=alumni_pagination,
                         contacts=contacts,
                         donations=donations,
                         admin_list=admin_list)

# Admin Panel Route
@app.route("/admin-login", methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated and hasattr(current_user, 'type'):
        if current_user.type == 'admin':
            return redirect(url_for('admin_dashboard'))
        logout_user()

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        admin = Admin.query.filter_by(username=username).first()
        
        if admin and check_password_hash(admin.password, password):
            admin.last_login = datetime.now(timezone('Asia/Dhaka'))
            db.session.commit()
            login_user(admin)
            admin.type = 'admin'  # Set type after login
            flash('Logged in successfully as admin', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials', 'error')
            
    return render_template('admin_login.html')

@app.route("/add-admin", methods=['POST'])
@login_required
@admin_required
def add_admin():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Only super admins can create other super admins
        is_super_admin = False
        if current_user.is_super_admin and request.form.get('is_super_admin'):
            is_super_admin = True
        
        # Validation
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('admin_dashboard'))
        
        # Check if admin already exists
        if Admin.query.filter((Admin.username == username) | (Admin.email == email)).first():
            flash('Admin with that username or email already exists', 'error')
            return redirect(url_for('admin_dashboard'))
        
        # Create new admin user
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_admin = Admin(
            username=username,
            email=email,
            password=hashed_password,
            is_super_admin=is_super_admin
        )
        
        try:
            db.session.add(new_admin)
            db.session.commit()
            flash('New admin created successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating admin: {str(e)}', 'error')
        
        return redirect(url_for('admin_dashboard'))
    
@app.route("/admin/delete-admin/<int:id>", methods=['POST'])
@login_required
@admin_required
def delete_admin(id):
    # Check if current user is a super admin
    if not current_user.is_super_admin:
        flash('You do not have permission to delete administrators', 'error')
        return redirect(url_for('admin_dashboard'))
    
    # Prevent self-deletion
    if current_user.id == id:
        flash('You cannot delete your own account', 'error')
        return redirect(url_for('admin_dashboard'))
    
    admin = Admin.query.get_or_404(id)
    
    try:
        db.session.delete(admin)
        db.session.commit()
        flash(f'Admin {admin.username} deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting admin: {str(e)}', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route("/add-news", methods=['POST'])
@login_required
@admin_required
def add_news():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        is_published = True if request.form.get('is_published') else False
        
        try:
            news = News(
                title=title,
                content=content,
                author_id=current_user.id,
                is_published=is_published
            )
            
            # Handle image upload
            if 'image' in request.files:
                file = request.files['image']
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    # Create news directory if it doesn't exist
                    news_upload_path = os.path.join('static', 'news')
                    if not os.path.exists(news_upload_path):
                        os.makedirs(news_upload_path)
                    file.save(os.path.join(news_upload_path, filename))
                    news.image = filename
            
            db.session.add(news)
            db.session.commit()
            flash('News added successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Error adding news: ' + str(e), 'error')
            print(f"Error: {e}")
            
    return redirect(url_for('news'))

@app.route("/edit-news/<int:id>", methods=['POST'])
@login_required
@admin_required
def edit_news(id):
    news = News.query.get_or_404(id)
    
    try:
        news.title = request.form.get('title')
        # Only update content if it's not empty
        if request.form.get('content'):
            news.content = request.form.get('content')
        news.is_published = True if request.form.get('is_published') else False
        news.updated_at = datetime.utcnow()
        
        if 'image' in request.files and request.files['image'].filename:
            file = request.files['image']
            if file and allowed_file(file.filename):
                # Delete old image if exists
                if news.image:
                    old_image_path = os.path.join('static', 'news', news.image)
                    if os.path.exists(old_image_path):
                        os.remove(old_image_path)
                
                filename = secure_filename(file.filename)
                file.save(os.path.join('static', 'news', filename))
                news.image = filename
        
        db.session.commit()
        flash('News updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error updating news.', 'error')
        print(f"Error: {e}")
        
    return redirect(url_for('news'))

@app.route("/delete-news/<int:id>", methods=['POST'])
@login_required
@admin_required
def delete_news(id):
    news = News.query.get_or_404(id)
    
    try:
        # Delete image if exists
        if news.image:
            image_path = os.path.join('static', 'news', news.image)
            if os.path.exists(image_path):
                os.remove(image_path)
        
        db.session.delete(news)
        db.session.commit()
        flash('News deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting news.', 'error')
        print(f"Error: {e}")
        
    return redirect(url_for('news'))

@app.route("/admin_add_event")
@login_required
@admin_required
def admin_add_event():
    return "add event"

@app.route("/admin/delete-alumni/<int:id>", methods=['POST'])
@login_required
@admin_required
def admin_delete_alumni(id):
    alumni = AlumniDetails.query.get_or_404(id)
    user = User.query.get(alumni.user_id)
    
    try:
        # Delete alumni photo if it exists
        if alumni.alumni_pic:
            photo_path = os.path.join(app.root_path, 'static', 'alumni', alumni.alumni_pic)
            if os.path.exists(photo_path):
                os.remove(photo_path)
        
        # Delete alumni details first (due to foreign key constraint)
        db.session.delete(alumni)
        
        # Delete user if exists
        if user:
            db.session.delete(user)
            
        db.session.commit()
        flash('Alumni profile and associated data deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting alumni profile', 'error')
        print(f"Error: {e}")
        
    return redirect(url_for('admin_dashboard'))

@app.route("/admin/delete-contact/<int:id>", methods=['POST'])
@login_required
@admin_required
def admin_delete_contact(id):
    contact = Contact.query.get_or_404(id)
    try:
        db.session.delete(contact)
        db.session.commit()
        flash('Contact message deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting contact message', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route("/admin-logout")
@login_required
@admin_required
def admin_logout():
    logout_user()
    flash('Admin logged out successfully', 'info')
    return redirect(url_for('admin_login'))


@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirmed_password = request.form.get('confirmPassword')

        # Check if username or email already exists
        user = User.query.filter((User.username == username) | (User.email == email)).first()
        if user:
            flash('Username or email already exists', 'error')
            return redirect(url_for('signup'))

        # Validate password
        if password != confirmed_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('signup'))

        if (not any(char.isupper() for char in password) or
            not any(char.islower() for char in password) or
            not any(char.isdigit() for char in password) or
            not any(char in '!@#$%^&*()_+-=[]{}|;:,.<>?/' for char in password) or
            len(password) < 8):
            flash('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character', 'error')
            return redirect(url_for('signup'))

        # Hash password and create new user
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        # Log in the user immediately after signup
        login_user(new_user)

        flash('Signup successful! Please fill in your details.', 'success')
        return redirect(url_for('user_details'))

    return render_template('signup.html')

@app.route("/teacher-signup-step1", methods=['GET', 'POST'])
def teacher_signup_step1():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Validation
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('teacher_signup_step1'))

        # Check if email already exists with a password
        existing_teacher = Teacher.query.filter_by(email=email).first()
        
        if existing_teacher and existing_teacher.password:
            flash('Email already registered', 'error')
            return redirect(url_for('teacher_signup_step1'))

        # If teacher exists but has no password (incomplete registration)
        if existing_teacher:
            try:
                existing_teacher.password = generate_password_hash(password, method='pbkdf2:sha256')
                db.session.commit()
                session['teacher_signup_id'] = existing_teacher.id
                return redirect(url_for('teacher_signup_step2'))
            except Exception as e:
                db.session.rollback()
                flash('Error updating teacher record', 'error')
                return redirect(url_for('teacher_signup_step1'))
        
        # If new teacher, store in session and proceed to step 2
        session['teacher_temp_data'] = {
            'email': email,
            'password': generate_password_hash(password, method='pbkdf2:sha256')
        }
        return redirect(url_for('teacher_signup_step2'))

    return render_template('teacher_signup_step1.html')

@app.route("/teacher-signup-step2", methods=['GET', 'POST'])
def teacher_signup_step2():
    # Check if we have either a teacher ID or temp data
    teacher_id = session.get('teacher_signup_id')
    temp_data = session.get('teacher_temp_data')
    
    if not teacher_id and not temp_data:
        return redirect(url_for('teacher_signup_step1'))

    if request.method == 'POST':
        try:
            # Get all form data
            username = request.form.get('username')
            name = request.form.get('name')
            designation = request.form.get('designation')
            department = request.form.get('department')
            phone = request.form.get('phone')
            bio = request.form.get('bio')
            research_interests = request.form.get('research_interests')
            
            if teacher_id:
                # Update existing teacher record
                teacher = Teacher.query.get(teacher_id)
                if not teacher:
                    flash('Teacher not found', 'error')
                    return redirect(url_for('teacher_signup_step1'))
                
                teacher.username = username
                teacher.name = name
                teacher.designation = designation
                teacher.department = department
                teacher.phone = phone
                teacher.bio = bio
                teacher.research_interests = research_interests
            else:
                # Create new teacher record
                teacher = Teacher(
                    username=username,
                    email=temp_data['email'],
                    password=temp_data['password'],
                    name=name,
                    designation=designation,
                    department=department,
                    phone=phone,
                    bio=bio,
                    research_interests=research_interests
                )
                db.session.add(teacher)
            
            # Handle photo upload
            if 'photo' in request.files:
                file = request.files['photo']
                if file and allowed_file(file.filename):
                    filename = secure_filename(f"teacher_{username}_{int(time.time())}.{file.filename.rsplit('.', 1)[1].lower()}")
                    file.save(os.path.join('static', 'teachers', filename))
                    teacher.photo = filename
            
            db.session.commit()
            
            # Clear session data
            session.pop('teacher_signup_id', None)
            session.pop('teacher_temp_data', None)
            
            flash('Teacher registration completed successfully!', 'success')
            return redirect(url_for('teacher_login'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error completing registration: {str(e)}', 'error')
            print(f"Error: {e}")

    return render_template('teacher_signup_step2.html')


@app.route("/student-signup", methods=['GET', 'POST'])
def student_signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        name = request.form.get('name')
        student_id = request.form.get('student_id')
        batch = request.form.get('batch')
        phone = request.form.get('phone')

        # Validation
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('student_signup'))

        # Check if username, email or student_id already exists
        if Student.query.filter(
            (Student.username == username) | 
            (Student.email == email) |
            (Student.student_id == student_id)
        ).first():
            flash('Username, email or student ID already exists', 'error')
            return redirect(url_for('student_signup'))

        # Hash password and create new student
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_student = Student(
            username=username,
            email=email,
            password=hashed_password,
            name=name,
            student_id=student_id,
            batch=batch,
            phone=phone
        )

        db.session.add(new_student)
        db.session.commit()

        flash('Student account created successfully!', 'success')
        return redirect(url_for('student_login'))

    return render_template('student_signup.html')

# User Details Route
@app.route("/user_details", methods=['GET', 'POST'])
@login_required
def user_details():
    if current_user.alumni_details:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        date_of_birth = request.form.get('date_of_birth')
        blood_group = request.form.get('blood_group')
        gender = request.form.get('gender')
        cse_batch = request.form.get('cse_batch')
        company_name = request.form.get('company_name')
        position = request.form.get('position')
        alumni_pic = request.files['alumni_pic']
        linkedin_url = request.form.get('linkedin_url')
        github_url = request.form.get('github_url')
        research_gate_url = request.form.get('research_gate_url')
        google_scholar_url = request.form.get('google_scholar_url')
        orcid_url = request.form.get('orcid_url')
        personal_website = request.form.get('personal_website')

        if alumni_pic and allowed_file(alumni_pic.filename):
            file_ext = alumni_pic.filename.rsplit('.', 1)[1].lower()
            pic_filename = f"{current_user.username}.{file_ext}"
            pic_path = os.path.join('static/alumni', pic_filename)


            if os.path.exists(pic_path):
                os.remove(pic_path)
                
            alumni_pic.save(pic_path)
        else:
            pic_filename = None

        new_details = AlumniDetails(
            user_id=current_user.id,
            first_name=first_name,
            last_name=last_name,
            date_of_birth=date_of_birth,
            blood_group=blood_group,
            gender=gender,
            cse_batch=cse_batch,
            company_name=company_name,
            position=position,
            alumni_pic=pic_filename,
            linkedin_url=linkedin_url,
            github_url=github_url,
            research_gate_url=research_gate_url,
            google_scholar_url=google_scholar_url,
            orcid_url=orcid_url,
            personal_website=personal_website
        )
        
        db.session.add(new_details)
        db.session.commit()
        flash('Your details have been saved successfully', 'success')
        return redirect(url_for('dashboard'))

    return render_template('user_details.html')


@app.route("/edit_profile", methods=['GET', 'POST'])
@login_required
def edit_profile():
    alumni_details = AlumniDetails.query.filter_by(user_id=current_user.id).first()
    if request.method == 'POST':
        # Get form data
        alumni_details.first_name = request.form.get('first_name')
        alumni_details.last_name = request.form.get('last_name')
        alumni_details.date_of_birth = request.form.get('date_of_birth')
        alumni_details.blood_group = request.form.get('blood_group')
        alumni_details.gender = request.form.get('gender')
        alumni_details.cse_batch = request.form.get('cse_batch')
        alumni_details.company_name = request.form.get('company_name')
        alumni_details.position = request.form.get('position')
        alumni_details.linkedin_url = request.form.get('linkedin_url')
        alumni_details.github_url = request.form.get('github_url')
        alumni_details.research_gate_url = request.form.get('research_gate_url')
        alumni_details.google_scholar_url = request.form.get('google_scholar_url')
        alumni_details.orcid_url = request.form.get('orcid_url')
        alumni_details.personal_website = request.form.get('personal_website')

        # Handle profile picture update
        if 'alumni_pic' in request.files:
            alumni_pic = request.files['alumni_pic']
            if alumni_pic and allowed_file(alumni_pic.filename):
                if alumni_details.alumni_pic:
                    old_pic_path = os.path.join('static/alumni', alumni_details.alumni_pic)
                    if os.path.exists(old_pic_path):
                        os.remove(old_pic_path)
                file_ext = alumni_pic.filename.rsplit('.', 1)[1].lower()
                pic_filename = f"{current_user.username}.{file_ext}"
                pic_path = os.path.join('static/alumni', pic_filename)
                alumni_pic.save(pic_path)
                alumni_details.alumni_pic = pic_filename

        db.session.commit()
        flash('Profile updated successfully', 'success')
        return redirect(url_for('dashboard'))

    return render_template('edit_profile.html', alumni_details=alumni_details)

@app.route("/delete_profile", methods=['POST'])
@login_required
def delete_profile():
    user = User.query.get(current_user.id)
    alumni_details = AlumniDetails.query.filter_by(user_id=current_user.id).first()
    if alumni_details:
        # Delete profile picture if exists
        if alumni_details.alumni_pic:
            pic_path = os.path.join('static/alumni', alumni_details.alumni_pic)
            if os.path.exists(pic_path):
                os.remove(pic_path)
        
        db.session.delete(alumni_details)
    if user:
        logout_user()
        db.session.delete(user)
    
    # Commit all changes
    db.session.commit()
    flash('Your account has been permanently deleted', 'error')
    return redirect(url_for('signup'))

# Other Routes
@app.route("/about")
def about():
    return render_template('about.html')

@app.route("/gallery")
def gallery():
    images = [f for f in os.listdir(GALLERY_FOLDER) if f.endswith(('.png', '.jpg', '.jpeg', '.gif'))]
    return render_template('gallery.html', images=images)

@app.route("/news")
def news():
    page = request.args.get('page', 1, type=int)
    pagination = News.query.order_by(News.created_at.desc()).paginate(page=page, per_page=6, error_out=False)   
    news_list = pagination.items
    return render_template('news.html', news=news_list,pagination=pagination)

@app.route("/teachers")
def teachers():
    search_query = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    
    # Base query
    query = Teacher.query
    
    # Apply search filter if search term is provided
    if search_query:
        query = query.filter(
            or_(
                Teacher.name.ilike(f'%{search_query}%'),
                Teacher.designation.ilike(f'%{search_query}%'),
                Teacher.department.ilike(f'%{search_query}%'),
                Teacher.email.ilike(f'%{search_query}%')
            )
        )
    
    # Apply pagination - 6 teachers per page
    pagination = query.order_by(Teacher.created_at).paginate(page=page, per_page=6, error_out=False)
    teachers_list = pagination.items
    
    return render_template('teachers.html', teachers=teachers_list, pagination=pagination)

@app.route("/admin/teachers", methods=['GET', 'POST'])
@login_required
@admin_required
def admin_teachers():
    teachers_list = Teacher.query.all()
    
    if request.method == 'POST':
        try:
            name = request.form.get('name')
            designation = request.form.get('designation')
            department = request.form.get('department', 'Computer Science and Engineering')
            phone = request.form.get('phone')
            email = request.form.get('email')
            bio = request.form.get('bio')
            research_interests = request.form.get('research_interests')
            
            teacher = Teacher(
                name=name,
                designation=designation,
                department=department,
                phone=phone,
                email=email,
                bio=bio,
                research_interests=research_interests
            )
            
            # Handle photo upload
            if 'photo' in request.files:
                file = request.files['photo']
                if file and allowed_file(file.filename):
                    filename = secure_filename(f"teacher_{name.replace(' ', '_')}_{int(time.time())}.{file.filename.rsplit('.', 1)[1].lower()}")
                    
                    # Create teachers directory if it doesn't exist
                    teachers_folder = os.path.join('static', 'teachers')
                    if not os.path.exists(teachers_folder):
                        os.makedirs(teachers_folder)
                        
                    file.save(os.path.join(teachers_folder, filename))
                    teacher.photo = filename
            
            db.session.add(teacher)
            db.session.commit()
            flash('Teacher added successfully!', 'success')
            return redirect(url_for('teachers'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding teacher: {str(e)}', 'error')
            
    return render_template('teachers.html', teachers=teachers_list)

# Edit teacher route
@app.route("/admin/edit-teacher/<int:id>", methods=['POST'])
@login_required
@admin_required
def edit_teacher(id):
    teacher = Teacher.query.get_or_404(id)
    
    try:
        teacher.name = request.form.get('name')
        teacher.designation = request.form.get('designation')
        teacher.department = request.form.get('department')
        teacher.phone = request.form.get('phone')
        teacher.email = request.form.get('email')
        teacher.bio = request.form.get('bio')
        teacher.research_interests = request.form.get('research_interests')
        
        # Handle photo update
        if 'photo' in request.files and request.files['photo'].filename != '':
            file = request.files['photo']
            if file and allowed_file(file.filename):
                # Delete old photo if it exists
                if teacher.photo:
                    old_photo_path = os.path.join('static', 'teachers', teacher.photo)
                    if os.path.exists(old_photo_path):
                        os.remove(old_photo_path)
                
                # Save new photo
                filename = secure_filename(f"teacher_{teacher.name.replace(' ', '_')}_{int(time.time())}.{file.filename.rsplit('.', 1)[1].lower()}")
                file.save(os.path.join('static', 'teachers', filename))
                teacher.photo = filename
        
        db.session.commit()
        flash('Teacher information updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating teacher: {str(e)}', 'error')
    
    return redirect(url_for('teachers'))

# Delete teacher route
@app.route("/admin/delete-teacher/<int:id>", methods=['POST'])
@login_required
@admin_required
def delete_teacher(id):
    teacher = Teacher.query.get_or_404(id)
    
    try:
        # Delete photo if it exists
        if teacher.photo:
            photo_path = os.path.join('static', 'teachers', teacher.photo)
            if os.path.exists(photo_path):
                os.remove(photo_path)
        
        db.session.delete(teacher)
        db.session.commit()
        flash('Teacher deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting teacher: {str(e)}', 'error')
    
    return redirect(url_for('teachers'))




@app.route("/contact", methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')
        
        new_contact = Contact(name=name, email=email, message=message)
        db.session.add(new_contact)
        db.session.commit()
        
        flash('Your message has been sent successfully', 'success')
        return redirect(url_for('contact'))
    
    return render_template('contact.html')

@app.route("/alumni-list")
def alumni_list():
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search', '')
    sort_by = request.args.get('sort_by', 'name')  # default sort by name

    # Create base query
    query = AlumniDetails.query.join(User)
    
    # Apply search filter if search term is provided
    if search_query:
        query = query.filter(
            or_(
                AlumniDetails.first_name.ilike(f'%{search_query}%'),
                AlumniDetails.last_name.ilike(f'%{search_query}%'),
                AlumniDetails.cse_batch.ilike(f'%{search_query}%'),
                AlumniDetails.company_name.ilike(f'%{search_query}%'),
                AlumniDetails.position.ilike(f'%{search_query}%')
            )
        )
     # Apply sorting
    if sort_by == 'batch':
        query = query.order_by(AlumniDetails.cse_batch.asc(), AlumniDetails.first_name.asc())
    else:
        query = query.order_by(AlumniDetails.first_name.asc(), AlumniDetails.last_name.asc())


    # Apply pagination
    pagination = query.paginate(page=page, per_page=4, error_out=False)
    alumni = pagination.items
    
    return render_template('alumni_list.html', alumni=alumni, pagination=pagination)

@app.route("/job-opportunities", methods=['GET'])
def job_opportunities():
    page = request.args.get('page', 1, type=int)
    pagination = JobOpportunity.query.filter_by(is_active=True)\
        .order_by(JobOpportunity.created_at.desc())\
        .paginate(page=page, per_page=5, error_out=False)
    jobs = pagination.items
    return render_template('job_opportunities.html', jobs=jobs, pagination=pagination)

@app.route("/add-job", methods=['POST'])
@login_required
def add_job():
    try:
        job = JobOpportunity(
            title=request.form.get('title'),
            company=request.form.get('company'),
            location=request.form.get('location'),
            description=request.form.get('description'),
            requirements=request.form.get('requirements'),
            salary_range=request.form.get('salary_range'),
            employment_type=request.form.get('employment_type'),
            experience_level=request.form.get('experience_level'),
            apply_url=request.form.get('apply_url'),
            contact_email=request.form.get('contact_email'),
            deadline=datetime.strptime(request.form.get('deadline'), '%Y-%m-%d') if request.form.get('deadline') else None,
            is_active=True
        )
        
        # Set the appropriate poster (admin or alumni)
        if isinstance(current_user, Admin):
            job.posted_by_admin = True
            job.admin_id = current_user.id
        else:
            job.posted_by_admin = False
            job.alumni_id = current_user.alumni_details.id
            
        db.session.add(job)
        db.session.commit()
        flash('Job opportunity added successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error adding job opportunity.', 'error')
        print(f"Error: {e}")
        
    return redirect(url_for('job_opportunities'))

@app.route("/edit-job/<int:id>", methods=['POST'])
@login_required
def edit_job(id):
    job = JobOpportunity.query.get_or_404(id)
    
    # Check if user has permission to edit
    if not (current_user.type == 'admin' or 
            (not job.posted_by_admin and 
             hasattr(current_user, 'alumni_details') and 
             current_user.alumni_details.id == job.alumni_id)):
        flash('You do not have permission to edit this job posting.', 'error')
        return redirect(url_for('job_opportunities'))
    
    try:
        job.title = request.form.get('title')
        job.company = request.form.get('company')
        job.location = request.form.get('location')
        job.description = request.form.get('description')
        job.requirements = request.form.get('requirements')
        job.salary_range = request.form.get('salary_range')
        job.employment_type = request.form.get('employment_type')
        job.experience_level = request.form.get('experience_level')
        job.apply_url = request.form.get('apply_url')
        job.contact_email = request.form.get('contact_email')
        job.deadline = datetime.strptime(request.form.get('deadline'), '%Y-%m-%d') if request.form.get('deadline') else None
        job.updated_at = datetime.utcnow()
        
        db.session.commit()
        flash('Job opportunity updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error updating job opportunity.', 'error')
        print(f"Error: {e}")
        
    return redirect(url_for('job_opportunities'))

@app.route("/delete-job/<int:id>", methods=['POST'])
@login_required
def delete_job(id):
    job = JobOpportunity.query.get_or_404(id)
    
    # Check if user has permission to delete
    if not (isinstance(current_user, Admin) or 
            (hasattr(current_user, 'alumni_details') and 
             current_user.alumni_details.id == job.alumni_id)):
        abort(403)
    
    try:
        db.session.delete(job)
        db.session.commit()
        flash('Job opportunity deleted successfully!', 'warning')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting job opportunity.', 'error')
        print(f"Error: {e}")
        
    return redirect(url_for('job_opportunities'))

@app.route("/event-list")
def event_list():
    page = request.args.get('page', 1, type=int)
    pagination = Event.query.order_by(Event.event_date.desc()).paginate(page=page, per_page=6, error_out=False)
    events = pagination.items
    return render_template('event_list.html', events=events, pagination=pagination)



@app.route("/events")
def events():
    """Show all events to all users and visitors"""
    page = request.args.get('page', 1, type=int)
    pagination = Event.query.order_by(Event.event_date.desc()).paginate(page=page, per_page=6, error_out=False)
    events = pagination.items
    return render_template('event_list.html', events=events, pagination=pagination)

@app.route("/add-event", methods=['POST'])
@login_required
def add_event():
    if current_user.type != 'admin':
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('events'))

    try:
        title = request.form.get('title')
        description = request.form.get('description')
        event_date = datetime.strptime(request.form.get('event_date'), '%Y-%m-%d')
        event_time = datetime.strptime(request.form.get('event_time'), '%H:%M').time()
        event_datetime = datetime.combine(event_date, event_time)
        location = request.form.get('location')
        max_participants = request.form.get('max_participants')
        registration_deadline_date = request.form.get('registration_deadline_date')
        registration_deadline_time = request.form.get('registration_deadline_time')
        registration_deadline = None

        if registration_deadline_date and registration_deadline_time:
            registration_deadline = datetime.combine(
                datetime.strptime(registration_deadline_date, '%Y-%m-%d'),
                datetime.strptime(registration_deadline_time, '%H:%M').time()
            )

        image = None
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join('static', 'events', filename))
                image = filename

        event = Event(
            title=title,
            description=description,
            event_date=event_datetime,
            location=location,
            max_participants=max_participants,
            registration_deadline=registration_deadline,
            image=image,
            author_id=current_user.id
        )

        db.session.add(event)
        db.session.commit()
        flash('Event added successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error adding event.', 'danger')
        print(f"Error: {e}")

    return redirect(url_for('events'))


@app.route("/edit-event/<int:id>", methods=['POST'])
@login_required
@admin_required
def edit_event(id):
    event = Event.query.get_or_404(id)
    
    try:
        event.title = request.form.get('title')
        event.description = request.form.get('description')
        event.event_date = datetime.strptime(f"{request.form.get('event_date')} {request.form.get('event_time')}", '%Y-%m-%d %H:%M')
        event.location = request.form.get('location')
        event.max_participants = request.form.get('max_participants')
        event.is_published = True if request.form.get('is_published') else False
        
        if request.form.get('registration_deadline_date') and request.form.get('registration_deadline_time'):
            event.registration_deadline = datetime.strptime(
                f"{request.form.get('registration_deadline_date')} {request.form.get('registration_deadline_time')}", 
                '%Y-%m-%d %H:%M'
            )
        
        if 'image' in request.files and request.files['image'].filename:
            file = request.files['image']
            if file and allowed_file(file.filename):
                if event.image:
                    old_image_path = os.path.join('static', 'events', event.image)
                    if os.path.exists(old_image_path):
                        os.remove(old_image_path)
                        
                filename = secure_filename(file.filename)
                file.save(os.path.join('static', 'events', filename))
                event.image = filename
        
        event.updated_at = datetime.utcnow()
        db.session.commit()
        flash('Event updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error updating event.', 'error')
        print(f"Error: {e}")
        
    return redirect(url_for('events'))

@app.route("/delete-event/<int:id>", methods=['POST'])
@login_required
@admin_required
def delete_event(id):
    event = Event.query.get_or_404(id)
    
    try:
        if event.image:
            image_path = os.path.join('static', 'events', event.image)
            if os.path.exists(image_path):
                os.remove(image_path)
                
        db.session.delete(event)
        db.session.commit()
        flash('Event deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting event.', 'error')
        print(f"Error: {e}")
        
    return redirect(url_for('events'))

@app.route("/donate", methods=['GET', 'POST'])
@login_required
def donate():
    if not current_user.alumni_details:
        flash('Only alumni can donate.', 'error')
        return redirect(url_for('dashboard'))

    total_donations = db.session.query(db.func.sum(Donation.amount)).filter(
        Donation.donor_email == current_user.email
    ).scalar() or 0

    # Get donation history
    donation_history = Donation.query.filter(
        Donation.donor_email == current_user.email
    ).order_by(Donation.created_at.desc()).all()

    if request.method == 'POST':
        name = request.form.get('name')
        amount = request.form.get('amount')
        description = request.form.get('description')

        # Prepare data for SSLCommerz
        post_data = {
            'store_id': 'cou688dd1fde6706',
            'store_passwd': 'cou688dd1fde6706@ssl',
            'total_amount': amount,
            'currency': 'BDT',
            'tran_id': f'donate_{int(time.time())}',
            'success_url': url_for('donate_success', _external=True),
            'fail_url': url_for('donate_fail', _external=True),
            'cancel_url': url_for('donate_cancel', _external=True),
            'cus_name': name,
            'cus_email': current_user.email,
            'cus_add1': 'Comilla University',
            'cus_city': 'Cumilla',
            'cus_country': 'Bangladesh',
            'cus_phone': 'N/A',
            'value_a': description,
            'shipping_method': 'NO',
            'product_name': 'Donation',
            'product_category': 'Donation',
            'product_profile': 'general',
        }

        import requests
        sslcz_url = "https://sandbox.sslcommerz.com/gwprocess/v4/api.php"
        response = requests.post(sslcz_url, data=post_data)
        res_data = response.json()
        if res_data.get('status') == 'SUCCESS':
            return redirect(res_data['GatewayPageURL'])
        else:
            flash('Payment gateway error. Please try again later.', 'error')
            return redirect(url_for('donate'))

    
    return render_template('donate.html', 
                         total_donations=total_donations,
                         donation_history=donation_history)

@app.route("/donate/success", methods=['GET', 'POST'])
@login_required
def donate_success():
    #print("DEBUG: request.values =", dict(request.values))
    description = request.values.get('value_a')
    amount = request.values.get('amount')
    # Use logged-in user's info
    name = f"{current_user.alumni_details.first_name} {current_user.alumni_details.last_name}" if current_user.alumni_details else current_user.username
    email = current_user.email

    if amount and name:
        try:
            donation = Donation(
                donor_name=name,
                donor_email=email,
                amount=float(amount),
                description=description
            )
            db.session.add(donation)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print("DB ERROR:", e)

    flash('Thank you for your donation!', 'success')
    return redirect(url_for('dashboard'))

@app.route("/donate/fail", methods=['GET', 'POST'])
def donate_fail():
    flash('Payment failed. Please try again.', 'error')
    return redirect(url_for('donate'))

@app.route("/donate/cancel", methods=['GET', 'POST'])
def donate_cancel():
    flash('Payment cancelled.', 'warning')
    return redirect(url_for('donate'))

@app.route("/blog")
def blog():
    return render_template('blog.html')

# Run the App
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
