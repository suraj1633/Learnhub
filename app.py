from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime
from functools import wraps
import traceback
from sqlalchemy import select, func
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_jwt_extended import (
    JWTManager,
    jwt_required,
    create_access_token,
    get_jwt_identity,
    set_access_cookies,
    unset_jwt_cookies
)


app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()
app.config['JWT_SECRET_KEY'] = os.urandom(24).hex()  # Change this to a real secret in production
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['JWT_COOKIE_CSRF_PROTECT'] = True
app.config['JWT_CSRF_CHECK_FORM'] = True
jwt = JWTManager(app)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:mysql%40123@localhost/learnhub'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Flask-Login setup
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# File upload configuration
UPLOAD_FOLDER = 'static/images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload directories exist
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pics'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'course_thumbnails'), exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Database Models
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    user_type = db.Column(db.String(20), nullable=False)  # 'student' or 'teacher'
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    bio = db.Column(db.Text)
    profile_pic = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    courses_teaching = db.relationship('Course', backref='instructor', foreign_keys='Course.teacher_id')
    enrollments = db.relationship('Enrollment', back_populates='student', foreign_keys='Enrollment.student_id')
    reviews = db.relationship('Review', backref='author', foreign_keys='Review.student_id')
    testimonials = db.relationship('Testimonial', backref='author', foreign_keys='Testimonial.user_id')

    def get_id(self):
        return str(self.user_id)

class Course(db.Model):
    __tablename__ = 'courses'
    course_id = db.Column(db.Integer, primary_key=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    thumbnail_url = db.Column(db.String(255))
    trailer_url = db.Column(db.String(255))
    category = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Enrollment(db.Model):
    __tablename__ = 'enrollments'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('courses.course_id'), nullable=False)
    progress = db.Column(db.Integer, default=0)
    completed = db.Column(db.Boolean, default=False)
    enrolled_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    student = db.relationship('User', back_populates='enrollments', foreign_keys=[student_id])
    course = db.relationship('Course', backref='enrollments')

class Review(db.Model):
    __tablename__ = 'reviews'
    review_id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('courses.course_id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class CourseContent(db.Model):
    __tablename__ = 'course_content'
    content_id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey('courses.course_id'), nullable=False)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    content_type = db.Column(db.String(20), nullable=False)  # 'video', 'document', 'quiz'
    url = db.Column(db.String(255))
    position = db.Column(db.Integer, nullable=False)

class Testimonial(db.Model):
    __tablename__ = 'testimonials'
    testimonial_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Main routes
@app.route('/')
def home():
    return render_template('main/home.html')

@app.route('/about')
def about():
    return render_template('main/about.html')

@app.route('/contact')
def contact():
    return render_template('main/contact.html')

@app.route('/courses')
def courses():
    courses = db.session.execute(select(Course).join(User)).scalars().all()
    return render_template('main/courses.html', courses=courses)

@app.route('/teachers')
def teachers():
    teachers = db.session.execute(
        select(User).where(User.user_type == 'teacher')
    ).scalars().all()
    return render_template('main/teachers.html', teachers=teachers)

@app.route('/testimonials')
def testimonials():
    testimonials = db.session.execute(
        select(Testimonial).join(User)
    ).scalars().all()
    return render_template('main/testimonials.html', testimonials=testimonials)

# Auth routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = db.session.execute(
            select(User).where(User.email == email)
        ).scalar_one_or_none()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            access_token = create_access_token(identity=user.user_id)
            response = make_response(redirect(url_for('student_dashboard' if user.user_type == 'student' else 'teacher_dashboard')))
            set_access_cookies(response, access_token)
            flash('Logged in successfully!', 'success')
            return response
        else:
            flash('Invalid email or password', 'danger')
    
    return render_template('auth/login.html')

@app.route('/logout')
@login_required
def logout():
    response = make_response(redirect(url_for('home')))
    logout_user()
    unset_jwt_cookies(response)
    flash('You have been logged out', 'success')
    return response

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            user_type = request.form.get('user_type')
            
            if not all([username, email, password, user_type]):
                flash('All fields are required', 'danger')
                return redirect(url_for('register'))
            
            # Check if user already exists
            existing_user = db.session.execute(
                select(User).where((User.username == username) | (User.email == email))
            ).scalar_one_or_none()
            
            if existing_user:
                flash('Username or email already exists', 'danger')
                return redirect(url_for('register'))
            
            hashed_password = generate_password_hash(password)
            
            new_user = User(
                username=username,
                email=email,
                password_hash=hashed_password,
                user_type=user_type
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            print(f"Error during registration: {str(e)}")
            print(traceback.format_exc())
            flash('Registration failed. Please try again.', 'danger')
    
    return render_template('auth/register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# Student dashboard routes
@app.route('/student/dashboard')
@login_required
@jwt_required()  # Add this to existing login_required routes
def student_dashboard():
    if current_user.user_type != 'student':
        return redirect(url_for('home'))

    enrolled_courses = db.session.execute(
        select(Enrollment)
        .join(Course)
        .where(Enrollment.student_id == current_user.user_id)
    ).scalars().all()

    completed_courses = sum(1 for enrollment in enrolled_courses if enrollment.completed)

    return render_template(
        'dashboard/student/home.html',
        enrolled_courses=enrolled_courses,
        completed_courses=completed_courses
    )

@app.route('/student/courses')
@login_required
def student_courses():
    if current_user.user_type != 'student':
        return redirect(url_for('home'))
        
    enrolled_courses = db.session.execute(
        select(Course, Enrollment)
        .join(Enrollment, Course.course_id == Enrollment.course_id)
        .where(Enrollment.student_id == current_user.user_id)
    ).all()
    
    return render_template('dashboard/student/courses.html', enrolled_courses=enrolled_courses)

@app.route('/student/profile', methods=['GET', 'POST'])
@login_required
def student_profile():
    if current_user.user_type != 'student':
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        current_user.first_name = request.form.get('first_name')
        current_user.last_name = request.form.get('last_name')
        current_user.bio = request.form.get('bio')
        
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"user_{current_user.user_id}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pics', filename))
                profile_pic = f"images/profile_pics/{filename}"
                
                if current_user.profile_pic and os.path.exists(os.path.join('static', current_user.profile_pic)):
                    os.remove(os.path.join('static', current_user.profile_pic))
                
                current_user.profile_pic = profile_pic
        
        try:
            db.session.commit()
            flash('Profile updated successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Failed to update profile.', 'danger')
        
        return redirect(url_for('student_profile'))
    
    return render_template('dashboard/student/edit_profile.html')

# Teacher dashboard routes
@app.route('/teacher/dashboard')
@login_required
def teacher_dashboard():
    if current_user.user_type != 'teacher':
        return redirect(url_for('home'))
    
    return render_template('dashboard/teacher/home.html')

@app.route('/teacher/courses')
@login_required
def teacher_courses():
    if current_user.user_type != 'teacher':
        return redirect(url_for('home'))
        
    courses = db.session.execute(
        select(Course)
        .where(Course.teacher_id == current_user.user_id)
    ).scalars().all()
    return render_template('dashboard/teacher/manage_courses.html', courses=courses)

@app.route('/teacher/courses/add', methods=['GET', 'POST'])
@login_required
def add_course():
    if current_user.user_type != 'teacher':
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        try:
            title = request.form.get('title')
            description = request.form.get('description')
            price = request.form.get('price')
            category = request.form.get('category')
            
            if not all([title, description, price, category]):
                flash('All fields are required', 'danger')
                return redirect(url_for('add_course'))
            
            thumbnail_url = None
            if 'thumbnail' in request.files:
                file = request.files['thumbnail']
                if file and allowed_file(file.filename):
                    filename = secure_filename(f"course_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}")
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'course_thumbnails', filename)
                    file.save(filepath)
                    thumbnail_url = f"images/course_thumbnails/{filename}"
            
            new_course = Course(
                teacher_id=current_user.user_id,
                title=title,
                description=description,
                price=float(price),
                thumbnail_url=thumbnail_url,
                category=category
            )
            
            db.session.add(new_course)
            db.session.commit()
            
            flash('Course added successfully!', 'success')
            return redirect(url_for('teacher_courses'))
            
        except ValueError:
            db.session.rollback()
            flash('Invalid price format', 'danger')
        except Exception as e:
            db.session.rollback()
            print(f"Error adding course: {str(e)}")
            print(traceback.format_exc())
            flash('Failed to add course. Please try again.', 'danger')
    
    return render_template('dashboard/teacher/add_course.html')

# Course viewing route
@app.route('/course/<int:course_id>')
def view_course(course_id):
    course = db.session.get(Course, course_id)
    if not course:
        abort(404)
    
    content = db.session.execute(
        select(CourseContent)
        .where(CourseContent.course_id == course_id)
        .order_by(CourseContent.position)
    ).scalars().all()
    
    reviews = db.session.execute(
        select(Review)
        .join(User)
        .where(Review.course_id == course_id)
        .order_by(Review.created_at.desc())
    ).scalars().all()
    
    avg_rating = db.session.execute(
        select(func.avg(Review.rating))
        .where(Review.course_id == course_id)
    ).scalar() or 0
    
    return render_template('main/course_detail.html',
                         course=course,
                         content=content,
                         reviews=reviews,
                         avg_rating=round(avg_rating, 1))


@app.route('/course/<int:course_id>/enroll', methods=['POST'])
@login_required
def enroll_course(course_id):
    if current_user.user_type != 'student':
        flash('Only students can enroll in courses', 'danger')
        return redirect(url_for('view_course', course_id=course_id))
    
    # Check if already enrolled
    existing_enrollment = db.session.execute(
        select(Enrollment)
        .where(Enrollment.student_id == current_user.user_id)
        .where(Enrollment.course_id == course_id)
    ).scalar_one_or_none()
    
    if existing_enrollment:
        flash('You are already enrolled in this course', 'info')
        return redirect(url_for('view_course', course_id=course_id))
    
    try:
        new_enrollment = Enrollment(
            student_id=current_user.user_id,
            course_id=course_id
        )
        db.session.add(new_enrollment)
        db.session.commit()
        flash('Successfully enrolled in the course!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Failed to enroll in the course', 'danger')
        print(f"Error enrolling in course: {str(e)}")
    
    return redirect(url_for('view_course', course_id=course_id))

@app.route('/course/<int:course_id>/review', methods=['GET', 'POST'])
@login_required
def add_review(course_id):
    if current_user.user_type != 'student':
        flash('Only students can submit reviews', 'danger')
        return redirect(url_for('view_course', course_id=course_id))
    
    # Check if user is enrolled in the course
    is_enrolled = db.session.execute(
        select(Enrollment)
        .where(Enrollment.student_id == current_user.user_id)
        .where(Enrollment.course_id == course_id)
    ).scalar_one_or_none()
    
    if not is_enrolled:
        flash('You must enroll in the course before submitting a review', 'warning')
        return redirect(url_for('view_course', course_id=course_id))
    
    # Check if already reviewed
    existing_review = db.session.execute(
        select(Review)
        .where(Review.student_id == current_user.user_id)
        .where(Review.course_id == course_id)
    ).scalar_one_or_none()
    
    if existing_review:
        flash('You have already reviewed this course', 'info')
        return redirect(url_for('view_course', course_id=course_id))
    
    if request.method == 'POST':
        try:
            rating = int(request.form.get('rating'))
            comment = request.form.get('comment', '').strip()
            
            if not (1 <= rating <= 5):
                flash('Invalid rating value', 'danger')
                return redirect(url_for('add_review', course_id=course_id))
            
            new_review = Review(
                student_id=current_user.user_id,
                course_id=course_id,
                rating=rating,
                comment=comment if comment else None
            )
            
            db.session.add(new_review)
            db.session.commit()
            flash('Thank you for your review!', 'success')
            return redirect(url_for('view_course', course_id=course_id))
            
        except ValueError:
            flash('Invalid rating value', 'danger')
        except Exception as e:
            db.session.rollback()
            flash('Failed to submit review. Please try again.', 'danger')
            print(f"Error submitting review: {str(e)}")
    
    return render_template('main/add_review.html', course_id=course_id)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)