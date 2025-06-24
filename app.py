from flask import Flask, render_template, request, redirect, url_for, flash, abort, make_response, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import traceback
from sqlalchemy import select, func
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_jwt_extended import (
    JWTManager,
    jwt_required,
    create_access_token,
    set_access_cookies,
    unset_jwt_cookies
)
from utils.text_utils import capitalize_first, capitalize_name
from routes.teacher_forms import teacher_forms_bp
from functools import wraps
from sqlalchemy.orm import joinedload

app = Flask(__name__)
csrf = CSRFProtect(app)

# Configuration
app.config['SECRET_KEY'] = os.urandom(24).hex()
app.config['JWT_SECRET_KEY'] = os.urandom(24).hex()
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = False
app.config['JWT_COOKIE_CSRF_PROTECT'] = True
app.config['JWT_CSRF_CHECK_FORM'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Suraj*12@localhost/learnhub'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Initialize extensions
jwt = JWTManager(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Ensure upload directories exist
os.makedirs(os.path.join('static', 'images', 'profile_pics'), exist_ok=True)
os.makedirs(os.path.join('static', 'images', 'course_thumbnails'), exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Database Models
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    user_type = db.Column(db.String(20), nullable=False)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    bio = db.Column(db.Text)
    profile_pic = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    courses_teaching = db.relationship('Course', back_populates='teacher', foreign_keys='Course.teacher_id')
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
    is_published = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    teacher = db.relationship('User', back_populates='courses_teaching', foreign_keys=[teacher_id])
    reviews = db.relationship('Review', backref='course', lazy='dynamic')
    enrollments = db.relationship('Enrollment', back_populates='course', lazy=True)
    content = db.relationship('CourseContent', backref='course', order_by='CourseContent.position', lazy=True)

class Enrollment(db.Model):
    __tablename__ = 'enrollments'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('courses.course_id'), nullable=False)
    progress = db.Column(db.Integer, default=0)
    completed = db.Column(db.Boolean, default=False)
    enrolled_at = db.Column(db.DateTime, default=datetime.utcnow)
    student = db.relationship('User', back_populates='enrollments', foreign_keys=[student_id])
    course = db.relationship('Course', back_populates='enrollments')

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
    content_type = db.Column(db.String(20), nullable=False)
    url = db.Column(db.String(255))
    position = db.Column(db.Integer, nullable=False)

class UserVideoProgress(db.Model):
    __tablename__ = 'user_video_progress'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    content_id = db.Column(db.Integer, db.ForeignKey('course_content.content_id'), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    progress = db.Column(db.Integer, default=0)  # Store progress as percentage
    last_watched = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='video_progress')
    content = db.relationship('CourseContent', backref='progress_records')

    def __init__(self, user_id, content_id, completed=False, progress=0):
        self.user_id = user_id
        self.content_id = content_id
        self.completed = completed
        self.progress = progress
        self.last_watched = datetime.utcnow()

class Testimonial(db.Model):
    __tablename__ = 'testimonials'
    testimonial_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.after_request
def inject_csrf_token(response):
    response.set_cookie('csrf_token', generate_csrf())
    return response

# Main routes
@app.route('/')
def home():
    # Get featured courses (courses with highest ratings and most enrollments)
    featured_courses = db.session.execute(
        select(Course)
        .outerjoin(Enrollment, Course.course_id == Enrollment.course_id)
        .outerjoin(Review, Course.course_id == Review.course_id)
        .group_by(Course.course_id)
        .options(
            joinedload(Course.teacher),
            joinedload(Course.enrollments),
            joinedload(Course.content)
        )
        .order_by(
            func.coalesce(func.avg(Review.rating), 0).desc(),
            func.count(Enrollment.id).desc()
        )
        .limit(6)
    ).scalars().unique().all()

    # Load reviews for each course
    for course in featured_courses:
        course.reviews = course.reviews.all()

    # Get testimonials from students
    testimonials = db.session.execute(
        select(Review)
        .join(User, Review.student_id == User.user_id)
        .join(Course, Review.course_id == Course.course_id)
        .where(Review.rating >= 4)  # Only show positive reviews
        .order_by(func.random())  # Randomly select testimonials
        .options(
            joinedload(Review.author),
            joinedload(Review.course)
        )
        .limit(3)
    ).scalars().unique().all()

    return render_template('main/home.html',
                         featured_courses=featured_courses,
                         testimonials=testimonials)

@app.route('/about')
def about():
    return render_template('main/about.html')

@app.route('/contact')
def contact():
    return render_template('main/contact.html')

@app.route('/get-csrf')
def get_csrf():
    return jsonify({'csrf_token': generate_csrf()})

@app.route('/courses')
def courses():
    courses = db.session.execute(select(Course).join(User)).scalars().all()
    for course in courses:
        course.reviews_list = course.reviews.all()
    return render_template('main/courses.html', courses=courses)

@app.route('/teachers')
def teachers():
    teachers = db.session.execute(
        select(User)
        .where(User.user_type == 'teacher')
        .order_by(User.created_at.desc())
    ).scalars().all()
    return render_template('main/teachers.html', teachers=teachers)

@app.route('/testimonials')
def testimonials():
    testimonials = db.session.execute(
        select(Review)
        .join(User)
        .where(Review.rating >= 4)  # Only show positive testimonials
        .order_by(Review.created_at.desc())
        .limit(6)
    ).scalars().all()
    return render_template('main/testimonials.html', testimonials=testimonials)

@app.route('/teachers/<int:teacher_id>')
def public_teacher_profile(teacher_id):
    teacher = db.session.get(User, teacher_id)
    if not teacher or teacher.user_type != 'teacher':
        abort(404)
    courses = db.session.execute(
        select(Course).where(Course.teacher_id == teacher_id)
    ).scalars().all()
    total_students = sum(len(course.enrollments) for course in courses)
    total_reviews = sum(course.reviews.count() for course in courses)
    avg_rating = 0
    all_ratings = []
    for course in courses:
        all_ratings += [review.rating for review in course.reviews]
    if all_ratings:
        avg_rating = round(sum(all_ratings) / len(all_ratings), 1)
    return render_template('main/teacher_profile.html',
        teacher=teacher,
        courses=courses,
        total_students=total_students,
        total_reviews=total_reviews,
        avg_rating=avg_rating
    )

# Auth routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = db.session.execute(select(User).where(User.email == email)).scalar_one_or_none()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            access_token = create_access_token(identity=str(user.user_id))
            response = make_response(redirect(url_for('student_dashboard' if user.user_type == 'student' else 'teacher_dashboard')))
            set_access_cookies(response, access_token)
            return response
        flash('Invalid email or password', 'danger')
    return render_template('auth/login.html')

@app.route('/logout')
@login_required
def logout():
    response = make_response(redirect(url_for('home')))
    logout_user()
    unset_jwt_cookies(response)
    return response

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')  # Added this line
            user_type = request.form.get('user_type')
            
            # Add password confirmation check
            if password != confirm_password:
                flash('Passwords do not match', 'danger')
                return redirect(url_for('register'))
            
            if not all([username, email, password, user_type]):
                flash('All fields are required', 'danger')
                return redirect(url_for('register'))
            
            existing_user = db.session.execute(
                select(User).where((User.username == username) | (User.email == email))
            ).first()
            
            if existing_user:
                flash('Username or email already exists', 'danger')
                return redirect(url_for('register'))
            
            new_user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
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

# Student dashboard routes
@app.route('/student/dashboard')
@login_required
def student_dashboard():
    if current_user.user_type != 'student':
        return redirect(url_for('home'))
    
    # Get enrolled courses with course and teacher information
    enrollments = db.session.execute(
        select(Enrollment, Course, User)
        .join(Course, Enrollment.course_id == Course.course_id)
        .join(User, Course.teacher_id == User.user_id)
        .where(Enrollment.student_id == current_user.user_id)
    ).all()
    
    # Calculate completed courses
    completed_courses = sum(1 for enrollment, _, _ in enrollments if enrollment.completed)
    
    # Get reviews for each course
    course_reviews = {}
    for enrollment, course, _ in enrollments:
        # Execute the reviews query since it's a dynamic relationship
        reviews = course.reviews.all()
        course_reviews[course.course_id] = reviews
    
    return render_template('dashboard/student/home.html', 
                         enrollments=enrollments,
                         completed_courses=completed_courses,
                         course_reviews=course_reviews)

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
        try:
            current_user.first_name = request.form.get('first_name')
            current_user.last_name = request.form.get('last_name')
            current_user.bio = request.form.get('bio')
            
            if 'profile_pic' in request.files:
                file = request.files['profile_pic']
                if file and allowed_file(file.filename):
                    filename = secure_filename(f"profile_{current_user.user_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}")
                    file.save(os.path.join('static', 'images', 'profile_pics', filename))
                    # Delete old profile picture if it exists
                    if current_user.profile_pic:
                        old_path = os.path.join('static', current_user.profile_pic)
                        if os.path.exists(old_path):
                            os.remove(old_path)
                    current_user.profile_pic = f"images/profile_pics/{filename}"
            
            # Handle password change
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            if current_password and new_password and confirm_password:
                if not check_password_hash(current_user.password_hash, current_password):
                    flash('Current password is incorrect', 'danger')
                    return redirect(url_for('student_profile'))
                
                if new_password != confirm_password:
                    flash('New passwords do not match', 'danger')
                    return redirect(url_for('student_profile'))
                
                current_user.password_hash = generate_password_hash(new_password)
            
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('student_profile'))
        except Exception as e:
            db.session.rollback()
            flash('Failed to update profile', 'danger')
            print(f"Error updating profile: {str(e)}")
    
    # Get student's statistics
    enrollments = db.session.execute(
        select(Enrollment).where(Enrollment.student_id == current_user.user_id)
    ).scalars().all()
    
    total_courses = len(enrollments)
    completed_courses = sum(1 for e in enrollments if e.progress == 100)
    in_progress_courses = total_courses - completed_courses
    avg_progress = sum(e.progress for e in enrollments) / total_courses if total_courses > 0 else 0
    
    return render_template('dashboard/student/profile.html',
        stats={
            'total_courses': total_courses,
            'completed_courses': completed_courses,
            'in_progress_courses': in_progress_courses,
            'avg_progress': round(avg_progress, 1)
        }
    )

# Teacher dashboard routes
@app.route('/teacher/dashboard')
@login_required
def teacher_dashboard():
    if current_user.user_type != 'teacher':
        return redirect(url_for('home'))
    
    # Get all courses by this teacher
    courses = db.session.execute(
        select(Course).where(Course.teacher_id == current_user.user_id)
    ).scalars().all()
    
    # Calculate total students, earnings, and ratings for each course
    total_students = 0
    total_earnings = 0
    
    for course in courses:
        # Get enrollments for this course
        enrollments = db.session.execute(
            select(Enrollment).where(Enrollment.course_id == course.course_id)
        ).scalars().all()
        
        # Get reviews and calculate average rating for this course
        reviews = db.session.execute(
            select(Review).where(Review.course_id == course.course_id)
        ).scalars().all()
        
        # Calculate average rating
        if reviews:
            total_rating = sum(review.rating for review in reviews)
            course.average_rating = total_rating / len(reviews)
        else:
            course.average_rating = 0
            
        course.reviews = reviews
        total_students += len(enrollments)
        total_earnings += course.price * len(enrollments)
    
    stats = {
        'total_courses': len(courses),
        'total_students': total_students,
        'total_earnings': total_earnings,
        'courses': courses
    }
    
    return render_template('dashboard/teacher/home.html', stats=stats)

@app.route('/teacher/manage_courses')
@login_required
def manage_courses():
    if current_user.user_type != 'teacher':
        return redirect(url_for('home'))
    courses = Course.query.filter_by(teacher_id=current_user.user_id).all()
    return render_template('dashboard/teacher/manage_courses.html', courses=courses)

@app.route('/teacher/create_course', methods=['GET', 'POST'])
@login_required
def create_course():
    if current_user.user_type != 'teacher':
        return redirect(url_for('home'))
    if request.method == 'POST':
        try:
            title = request.form.get('title')
            description = request.form.get('description')
            price = float(request.form.get('price'))
            category = request.form.get('category')
            
            # Capitalize the first letter of the title
            title = capitalize_first(title)
            
            course = Course(
                teacher_id=current_user.user_id,
                title=title,
                description=description,
                price=price,
                category=category
            )
            
            if 'thumbnail' in request.files:
                file = request.files['thumbnail']
                if file and allowed_file(file.filename):
                    filename = secure_filename(f"course_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}")
                    file.save(os.path.join('static', 'images', 'course_thumbnails', filename))
                    course.thumbnail_url = f"images/course_thumbnails/{filename}"
            
            db.session.add(course)
            db.session.commit()
            flash('Course created successfully!', 'success')
            return redirect(url_for('manage_courses'))
        except Exception as e:
            db.session.rollback()
            flash('Failed to create course.', 'danger')
            print(f"Error creating course: {str(e)}")
    
    return render_template('dashboard/teacher/create_course.html')

@app.route('/teacher/course_content/<int:course_id>', methods=['GET', 'POST'])
@login_required
def course_content(course_id):
    if current_user.user_type != 'teacher':
        return redirect(url_for('home'))
    course = Course.query.get_or_404(course_id)
    if course.teacher_id != current_user.user_id:
        abort(403)
    return render_template('dashboard/teacher/course_content.html', course=course)

@app.route('/teacher/settings', methods=['GET', 'POST'])
@login_required
def teacher_settings():
    if current_user.user_type != 'teacher':
        return redirect(url_for('home'))
    return render_template('dashboard/teacher/settings.html')

# Course routes
@app.route('/course/<int:course_id>')
def view_course(course_id):
    course = db.session.get(Course, course_id)
    if not course:
        abort(404)
    
    content = db.session.execute(
        select(CourseContent).where(CourseContent.course_id == course_id).order_by(CourseContent.position)
    ).scalars().all()
    
    reviews = db.session.execute(
        select(Review).join(User).where(Review.course_id == course_id).order_by(Review.created_at.desc())
    ).scalars().all()
    
    avg_rating = db.session.execute(
        select(func.avg(Review.rating)).where(Review.course_id == course_id)
    ).scalar() or 0
    
    enrollment = None
    if current_user.is_authenticated and current_user.user_type == 'student':
        enrollment = db.session.execute(
            select(Enrollment)
            .where(Enrollment.student_id == current_user.user_id)
            .where(Enrollment.course_id == course_id)
        ).scalar_one_or_none()
    
    return render_template('main/course_detail.html',
        course=course,
        content=content,
        reviews=reviews,
        avg_rating=round(avg_rating, 1),
        enrollment=enrollment
    )

@app.route('/course/<int:course_id>/enroll', methods=['POST'])
@login_required
def enroll_course(course_id):
    if current_user.user_type != 'student':
        flash('Only students can enroll in courses', 'danger')
        return redirect(url_for('view_course', course_id=course_id))
    
    existing = db.session.execute(
        select(Enrollment)
        .where(Enrollment.student_id == current_user.user_id)
        .where(Enrollment.course_id == course_id)
    ).scalar_one_or_none()
    
    if existing:
        flash('You are already enrolled in this course', 'info')
        return redirect(url_for('view_course', course_id=course_id))
    
    try:
        db.session.add(Enrollment(
            student_id=current_user.user_id,
            course_id=course_id
        ))
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
    
    is_enrolled = db.session.execute(
        select(Enrollment)
        .where(Enrollment.student_id == current_user.user_id)
        .where(Enrollment.course_id == course_id)
    ).scalar_one_or_none()
    
    if not is_enrolled:
        flash('You must enroll in the course before submitting a review', 'warning')
        return redirect(url_for('view_course', course_id=course_id))
    
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
            
            db.session.add(Review(
                student_id=current_user.user_id,
                course_id=course_id,
                rating=rating,
                comment=comment if comment else None
            ))
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

# Content management routes
@app.route('/course/<int:course_id>/content/<int:content_id>/progress', methods=['POST'])
@login_required
def update_content_progress(course_id, content_id):
    enrollment = db.session.execute(
        select(Enrollment)
        .where(Enrollment.student_id == current_user.user_id)
        .where(Enrollment.course_id == course_id)
    ).scalar_one_or_none()
    
    if not enrollment:
        return jsonify({'success': False, 'error': 'Not enrolled'}), 403
    
    try:
        progress_data = request.json.get('progress', 0)
        
        progress = db.session.execute(
            select(UserVideoProgress)
            .where(UserVideoProgress.user_id == current_user.user_id)
            .where(UserVideoProgress.content_id == content_id)
        ).scalar_one_or_none()
        
        if not progress:
            progress = UserVideoProgress(
                user_id=current_user.user_id,
                content_id=content_id,
                progress=progress_data
            )
            db.session.add(progress)
        else:
            progress.progress = max(progress.progress, progress_data)  # Only update if new progress is higher
            progress.last_watched = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'progress': progress.progress
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/course/<int:course_id>/content/<int:content_id>/complete', methods=['POST'])
@login_required
def mark_content_completed(course_id, content_id):
    enrollment = db.session.execute(
        select(Enrollment)
        .where(Enrollment.student_id == current_user.user_id)
        .where(Enrollment.course_id == course_id)
    ).scalar_one_or_none()
    
    if not enrollment:
        return jsonify({'success': False, 'error': 'Not enrolled'}), 403
    
    try:
        progress = db.session.execute(
            select(UserVideoProgress)
            .where(UserVideoProgress.user_id == current_user.user_id)
            .where(UserVideoProgress.content_id == content_id)
        ).scalar_one_or_none()
        
        if not progress:
            progress = UserVideoProgress(
                user_id=current_user.user_id,
                content_id=content_id,
                completed=True,
                progress=100
            )
            db.session.add(progress)
        else:
            progress.completed = True
            progress.progress = 100
            progress.last_watched = datetime.utcnow()
        
        # Update overall course progress
        all_content = db.session.execute(
            select(CourseContent).where(CourseContent.course_id == course_id)
        ).scalars().all()
        
        completed_count = db.session.execute(
            select(func.count(UserVideoProgress.id))
            .join(CourseContent)
            .where(UserVideoProgress.user_id == current_user.user_id)
            .where(CourseContent.course_id == course_id)
            .where(UserVideoProgress.completed == True)
        ).scalar()
        
        enrollment.progress = int((completed_count / len(all_content)) * 100) if all_content else 0
        
        # Check if course is completed
        if enrollment.progress == 100:
            enrollment.completed = True
            enrollment.completion_date = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'progress': enrollment.progress,
            'completed': enrollment.completed
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/course/<int:course_id>/content/<int:content_id>')
@login_required
def view_course_content(course_id, content_id):
    enrollment = db.session.execute(
        select(Enrollment)
        .where(Enrollment.student_id == current_user.user_id)
        .where(Enrollment.course_id == course_id)
    ).scalar_one_or_none()
    
    if not enrollment:
        flash('You need to enroll in this course first', 'warning')
        return redirect(url_for('view_course', course_id=course_id))
    
    content = db.session.get(CourseContent, content_id)
    if not content or content.course_id != course_id:
        abort(404)
    
    all_content = db.session.execute(
        select(CourseContent)
        .where(CourseContent.course_id == course_id)
        .order_by(CourseContent.position)
    ).scalars().all()
    
    # Get progress for current content
    progress = db.session.execute(
        select(UserVideoProgress)
        .where(UserVideoProgress.user_id == current_user.user_id)
        .where(UserVideoProgress.content_id == content_id)
    ).scalar_one_or_none()
    
    # Get progress for all content items
    for item in all_content:
        item_progress = db.session.execute(
            select(UserVideoProgress)
            .where(UserVideoProgress.user_id == current_user.user_id)
            .where(UserVideoProgress.content_id == item.content_id)
        ).scalar_one_or_none()
        if item_progress:
            item.progress_records = [item_progress]
    
    return render_template('course/video_player.html',
        course_id=course_id,
        content=content,
        all_content=all_content,
        progress=progress
    )

@app.route('/teacher/courses/<int:course_id>/content', methods=['GET', 'POST'])
@login_required
def manage_course_content(course_id):
    if current_user.user_type != 'teacher':
        return redirect(url_for('home'))
    
    course = db.session.get(Course, course_id)
    if not course or course.teacher_id != current_user.user_id:
        abort(404)
    
    if request.method == 'POST':
        if 'reorder' in request.form:
            try:
                order = request.form.getlist('content_order[]')
                for idx, content_id in enumerate(order, start=1):
                    content = db.session.get(CourseContent, content_id)
                    if content:
                        content.position = idx
                db.session.commit()
                flash('Content reordered successfully!', 'success')
            except Exception as e:
                db.session.rollback()
                flash('Failed to reorder content', 'danger')
        elif 'delete' in request.form:
            try:
                content_id = request.form.get('content_id')
                content = db.session.get(CourseContent, content_id)
                if content:
                    db.session.delete(content)
                    db.session.commit()
                    flash('Content deleted successfully!', 'success')
            except Exception as e:
                db.session.rollback()
                flash('Failed to delete content', 'danger')
        return redirect(url_for('manage_course_content', course_id=course_id))
    
    content_items = db.session.execute(
        select(CourseContent)
        .where(CourseContent.course_id == course_id)
        .order_by(CourseContent.position)
    ).scalars().all()
    
    return render_template('dashboard/teacher/manage_content.html',
        course=course,
        content_items=content_items
    )

@app.route('/teacher/courses/<int:course_id>/content/add', methods=['GET', 'POST'])
@login_required
def add_course_content(course_id):
    if current_user.user_type != 'teacher':
        return redirect(url_for('home'))
    
    course = db.session.get(Course, course_id)
    if not course or course.teacher_id != current_user.user_id:
        abort(404)
    
    if request.method == 'POST':
        try:
            title = request.form.get('title')
            content_type = request.form.get('content_type')
            url = request.form.get('url')
            description = request.form.get('description', '')
            
            if not all([title, content_type, url]):
                flash('Title, type, and URL are required', 'danger')
                return redirect(url_for('add_course_content', course_id=course_id))
            
            max_position = db.session.execute(
                select(func.max(CourseContent.position))
                .where(CourseContent.course_id == course_id)
            ).scalar() or 0
            
            db.session.add(CourseContent(
                course_id=course_id,
                title=title,
                description=description,
                content_type=content_type,
                url=url,
                position=max_position + 1
            ))
            db.session.commit()
            flash('Content added successfully!', 'success')
            return redirect(url_for('manage_course_content', course_id=course_id))
        except Exception as e:
            db.session.rollback()
            flash('Failed to add content', 'danger')
            print(f"Error adding content: {str(e)}")
    
    return render_template('dashboard/teacher/add_content.html', course=course)

@app.route('/teacher/profile', methods=['GET', 'POST'])
@login_required
def teacher_profile():
    if current_user.user_type != 'teacher':
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        try:
            current_user.first_name = request.form.get('first_name')
            current_user.last_name = request.form.get('last_name')
            current_user.bio = request.form.get('bio')
            
            if 'profile_pic' in request.files:
                file = request.files['profile_pic']
                if file and allowed_file(file.filename):
                    filename = secure_filename(f"profile_{current_user.user_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}")
                    file.save(os.path.join('static', 'images', 'profile_pics', filename))
                    # Delete old profile picture if it exists
                    if current_user.profile_pic:
                        old_path = os.path.join('static', current_user.profile_pic)
                        if os.path.exists(old_path):
                            os.remove(old_path)
                    current_user.profile_pic = f"images/profile_pics/{filename}"
            
            # Handle password change
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            if current_password and new_password and confirm_password:
                if not check_password_hash(current_user.password_hash, current_password):
                    flash('Current password is incorrect', 'danger')
                    return redirect(url_for('teacher_profile'))
                
                if new_password != confirm_password:
                    flash('New passwords do not match', 'danger')
                    return redirect(url_for('teacher_profile'))
                
                current_user.password_hash = generate_password_hash(new_password)
            
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('teacher_profile'))
        except Exception as e:
            db.session.rollback()
            flash('Failed to update profile', 'danger')
            print(f"Error updating profile: {str(e)}")
    
    # Get teacher's statistics
    courses = db.session.execute(
        select(Course).where(Course.teacher_id == current_user.user_id)
    ).scalars().all()
    
    total_students = db.session.execute(
        select(func.count(Enrollment.id))
        .join(Course)
        .where(Course.teacher_id == current_user.user_id)
    ).scalar() or 0
    
    total_reviews = db.session.execute(
        select(func.count(Review.review_id))
        .join(Course)
        .where(Course.teacher_id == current_user.user_id)
    ).scalar() or 0
    
    avg_rating = db.session.execute(
        select(func.avg(Review.rating))
        .join(Course)
        .where(Course.teacher_id == current_user.user_id)
    ).scalar() or 0
    
    return render_template('dashboard/teacher/profile.html',
        stats={
            'total_courses': len(courses),
            'total_students': total_students,
            'total_reviews': total_reviews,
            'avg_rating': round(avg_rating, 1)
        }
    )

@app.route('/teacher/earnings')
@login_required
def teacher_earnings():
    if current_user.user_type != 'teacher':
        return redirect(url_for('home'))
    
    # Get all courses by this teacher
    courses = db.session.execute(
        select(Course).where(Course.teacher_id == current_user.user_id)
    ).scalars().all()
    
    # Calculate earnings per course and total
    course_earnings = []
    total_earnings = 0
    total_students = 0
    
    for course in courses:
        enrollments = db.session.execute(
            select(Enrollment).where(Enrollment.course_id == course.course_id)
        ).scalars().all()
        
        course_student_count = len(enrollments)
        course_total = course.price * course_student_count
        
        course_earnings.append({
            'course': course,
            'student_count': course_student_count,
            'total': course_total
        })
        
        total_earnings += course_total
        total_students += course_student_count
    
    return render_template('dashboard/teacher/earnings.html',
        course_earnings=course_earnings,
        total_earnings=total_earnings,
        total_students=total_students
    )

@app.route('/teacher/edit_course/<int:course_id>', methods=['GET', 'POST'])
@login_required
def edit_course(course_id):
    if current_user.user_type != 'teacher':
        return redirect(url_for('home'))
    
    course = Course.query.get_or_404(course_id)
    if course.teacher_id != current_user.user_id:
        abort(403)
    
    if request.method == 'POST':
        try:
            course.title = request.form.get('title')
            course.description = request.form.get('description')
            course.price = float(request.form.get('price'))
            course.category = request.form.get('category')
            
            # Capitalize the first letter of the title
            course.title = capitalize_first(course.title)
            
            if 'thumbnail' in request.files:
                file = request.files['thumbnail']
                if file and allowed_file(file.filename):
                    filename = secure_filename(f"course_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}")
                    file.save(os.path.join('static', 'images', 'course_thumbnails', filename))
                    # Delete old thumbnail if it exists
                    if course.thumbnail_url:
                        old_path = os.path.join('static', course.thumbnail_url)
                        if os.path.exists(old_path):
                            os.remove(old_path)
                    course.thumbnail_url = f"images/course_thumbnails/{filename}"
            
            db.session.commit()
            flash('Course updated successfully!', 'success')
            return redirect(url_for('manage_courses'))
        except Exception as e:
            db.session.rollback()
            flash('Failed to update course.', 'danger')
            print(f"Error updating course: {str(e)}")
    
    return render_template('dashboard/teacher/edit_course.html', course=course)

def teacher_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.user_type != 'teacher':
            flash('You must be a teacher to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/teacher/courses/<course_id>/delete', methods=['POST'])
@login_required
@teacher_required
def delete_course(course_id):
    course = Course.query.get_or_404(course_id)
    
    # Ensure the course belongs to the current teacher
    if course.teacher_id != current_user.user_id:
        flash('You do not have permission to delete this course.', 'error')
        return redirect(url_for('teacher_dashboard'))
    
    try:
        # Delete course thumbnail if it exists
        if course.thumbnail_url:
            thumbnail_path = os.path.join('static', course.thumbnail_url)
            if os.path.exists(thumbnail_path):
                os.remove(thumbnail_path)

        # Delete all associated data in the correct order to maintain referential integrity
        # Delete course content
        CourseContent.query.filter_by(course_id=course_id).delete()
        
        # Delete enrollments
        Enrollment.query.filter_by(course_id=course_id).delete()
        
        # Delete reviews
        Review.query.filter_by(course_id=course_id).delete()
        
        # Finally delete the course itself
        db.session.delete(course)
        db.session.commit()
        
        flash('Course has been permanently deleted.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while deleting the course.', 'error')
        app.logger.error(f"Error deleting course {course_id}: {str(e)}")
    
    return redirect(url_for('teacher_dashboard'))

def init_db():
    with app.app_context():
        # Drop the user_video_progress table
        UserVideoProgress.__table__.drop(db.engine, checkfirst=True)
        # Create all tables
        db.create_all()

# Register blueprints
app.register_blueprint(teacher_forms_bp, url_prefix='/teacher')

# Add template filters
@app.template_filter('capitalize_first')
def capitalize_first_filter(text):
    return capitalize_first(text)

@app.template_filter('capitalize_name')
def capitalize_name_filter(text):
    if text:
        return ' '.join(word.capitalize() for word in text.split())
    return ''

@app.template_filter('avg')
def avg_filter(lst):
    if not lst:
        return 0
    return sum(lst) / len(lst)

if __name__ == '__main__':
    init_db()  # Initialize/update database tables
    app.run(debug=True)