import os
from flask import Flask, render_template, request, redirect, url_for, flash, abort, make_response, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect, generate_csrf
from datetime import datetime
import traceback
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
from utils.mongo_utils import db
from bson.objectid import ObjectId
from pymongo.errors import ServerSelectionTimeoutError
import secrets

app = Flask(__name__)
csrf = CSRFProtect(app)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = False
app.config['JWT_COOKIE_CSRF_PROTECT'] = True
app.config['JWT_CSRF_CHECK_FORM'] = True
app.config['UPLOAD_FOLDER'] = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

jwt = JWTManager(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

os.makedirs(os.path.join('static', 'images', 'profile_pics'), exist_ok=True)
os.makedirs(os.path.join('static', 'images', 'course_thumbnails'), exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Custom User class for Flask-Login
class UserObj(UserMixin):
    def __init__(self, user_doc):
        self.user_doc = user_doc
        self.id = str(user_doc.get('_id'))
        self.user_id = user_doc.get('user_id', self.id)
        self.username = user_doc.get('username')
        self.email = user_doc.get('email')
        self.password_hash = user_doc.get('password_hash')
        self.user_type = user_doc.get('user_type')
        self.first_name = user_doc.get('first_name')
        self.last_name = user_doc.get('last_name')
        self.bio = user_doc.get('bio')
        self.profile_pic = user_doc.get('profile_pic')
        self.created_at = user_doc.get('created_at')
    def get_id(self):
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    user = db['users'].find_one({'_id': ObjectId(user_id)})
    if user:
        return UserObj(user)
    return None

@app.after_request
def inject_csrf_token(response):
    response.set_cookie('csrf_token', generate_csrf())
    return response

@app.route('/')
def home():
    # Featured courses: highest ratings and most enrollments
    courses = list(db['courses'].find({'is_published': True}))
    for course in courses:
        course['teacher'] = db['users'].find_one({'user_id': course['teacher_id']})
        course['enrollments'] = list(db['enrollments'].find({'course_id': course['course_id']}))
        course['reviews'] = list(db['reviews'].find({'course_id': course['course_id']}))
        course['avg_rating'] = (sum(r['rating'] for r in course['reviews']) / len(course['reviews'])) if course['reviews'] else 0
    # Sort by avg_rating and enrollments
    featured_courses = sorted(courses, key=lambda c: (-c['avg_rating'], -len(c['enrollments'])))[:6]
    testimonials = list(db['reviews'].find({'rating': {'$gte': 4}}))
    for t in testimonials:
        t['author'] = db['users'].find_one({'user_id': t['student_id']})
        t['course'] = db['courses'].find_one({'course_id': t['course_id']})
    return render_template('main/home.html', featured_courses=featured_courses, testimonials=testimonials[:3])

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
    courses = list(db['courses'].find())
    for course in courses:
        course['course_id'] = course.get('course_id', str(course.get('_id')))
        course['reviews_list'] = list(db['reviews'].find({'course_id': course['course_id']}))
        # Add teacher info for template
        course['teacher'] = db['users'].find_one({'user_id': course['teacher_id']})
        # Add avg_rating for template
        if course['reviews_list']:
            course['avg_rating'] = sum(r['rating'] for r in course['reviews_list']) / len(course['reviews_list'])
        else:
            course['avg_rating'] = 0
    return render_template('main/courses.html', courses=courses)

@app.route('/teachers')
def teachers():
    teachers = list(db['users'].find({'user_type': 'teacher'}))
    for teacher in teachers:
        # Ensure user_id is present (fallback to _id if missing)
        teacher['user_id'] = teacher.get('user_id', str(teacher.get('_id')))
        # Add courses_teaching for template
        teacher['courses_teaching'] = list(db['courses'].find({'teacher_id': teacher['user_id']}))
        # For each course, add enrollments as a list for template
        for course in teacher['courses_teaching']:
            course['course_id'] = course.get('course_id', str(course.get('_id')))
            course['enrollments'] = list(db['enrollments'].find({'course_id': course['course_id']}))
    return render_template('main/teachers.html', teachers=teachers)

@app.route('/testimonials')
def testimonials():
    testimonials = list(db['reviews'].find({'rating': {'$gte': 4}}).sort('created_at', -1).limit(6))
    return render_template('main/testimonials.html', testimonials=testimonials)

@app.route('/teachers/<teacher_id>')
def public_teacher_profile(teacher_id):
    # teacher_id is now a string, can be user_id or str(_id)
    teacher = db['users'].find_one({'user_id': teacher_id, 'user_type': 'teacher'})
    if not teacher:
        # fallback to _id if user_id not found
        try:
            teacher = db['users'].find_one({'_id': ObjectId(teacher_id), 'user_type': 'teacher'})
        except Exception:
            teacher = None
    if not teacher:
        abort(404)
    courses = list(db['courses'].find({'teacher_id': teacher.get('user_id', str(teacher.get('_id')))}))
    for c in courses:
        c['course_id'] = c.get('course_id', str(c.get('_id')))
        c['reviews_list'] = list(db['reviews'].find({'course_id': c['course_id']}))
        if c['reviews_list']:
            c['avg_rating'] = sum(r['rating'] for r in c['reviews_list']) / len(c['reviews_list'])
        else:
            c['avg_rating'] = 0
    total_students = sum(db['enrollments'].count_documents({'course_id': c['course_id']}) for c in courses)
    all_reviews = [r for c in courses for r in db['reviews'].find({'course_id': c['course_id']})]
    total_reviews = len(all_reviews)
    avg_rating = round(sum(r.get('rating', 0) for r in all_reviews) / total_reviews, 1) if total_reviews else 0
    return render_template('main/teacher_profile.html', teacher=teacher, courses=courses, total_students=total_students, total_reviews=total_reviews, avg_rating=avg_rating)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = db['users'].find_one({'email': email})
        if user and check_password_hash(user['password_hash'], password):
            login_user(UserObj(user))
            access_token = create_access_token(identity=str(user.get('_id')))
            response = make_response(redirect(url_for('student_dashboard' if user['user_type'] == 'student' else 'teacher_dashboard')))
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
            confirm_password = request.form.get('confirm_password')
            user_type = request.form.get('user_type')
            if password != confirm_password:
                flash('Passwords do not match', 'danger')
                return redirect(url_for('register'))
            if not all([username, email, password, user_type]):
                flash('All fields are required', 'danger')
                return redirect(url_for('register'))
            existing_user = db['users'].find_one({'$or': [{'username': username}, {'email': email}]})
            if existing_user:
                flash('Username or email already exists', 'danger')
                return redirect(url_for('register'))
            user_doc = {
                'username': username,
                'email': email,
                'password_hash': generate_password_hash(password),
                'user_type': user_type,
                'created_at': datetime.utcnow()
            }
            db['users'].insert_one(user_doc)
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
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
    enrollments_cursor = db['enrollments'].find({'student_id': current_user.user_id})
    enrollments = list(enrollments_cursor)

    # Build list of (enrollment, course, teacher) tuples
    enrollment_tuples = []
    for enrollment in enrollments:
        course = db['courses'].find_one({'course_id': enrollment['course_id']})
        if not course:
            try:
                course = db['courses'].find_one({'_id': ObjectId(enrollment['course_id'])})
            except Exception:
                course = None
        teacher = db['users'].find_one({'user_id': course['teacher_id']}) if course else None
        if course:
            # Enrich course dict for template
            course['course_id'] = course.get('course_id', str(course.get('_id')))
            course['thumbnail_url'] = course.get('thumbnail_url', None)
            course['teacher'] = teacher
            course['title'] = course.get('title', '')
            course['category'] = course.get('category', '')
            course['price'] = course.get('price', 0)
        enrollment_tuples.append((enrollment, course, teacher))

    # Calculate completed courses
    completed_courses = sum(1 for e in enrollments if e.get('completed'))

    # Get reviews for each course
    course_reviews = {}
    for enrollment in enrollments:
        course_id = enrollment['course_id']
        course_reviews[course_id] = list(db['reviews'].find({'course_id': course_id}))

    # Add avg_rating to each course in enrollment_tuples
    for _, course, _ in enrollment_tuples:
        if course:
            reviews = course_reviews.get(course['course_id'], [])
            course['reviews_list'] = reviews
            if reviews:
                course['avg_rating'] = sum(r['rating'] for r in reviews) / len(reviews)
            else:
                course['avg_rating'] = 0

    return render_template('dashboard/student/home.html', 
                         enrollments=enrollment_tuples,
                         completed_courses=completed_courses,
                         course_reviews=course_reviews)

@app.route('/student/courses')
@login_required
def student_courses():
    if current_user.user_type != 'student':
        return redirect(url_for('home'))
    enrollments = list(db['enrollments'].find({'student_id': current_user.user_id}))
    enrolled_courses = []
    for enrollment in enrollments:
        course = db['courses'].find_one({'course_id': enrollment.get('course_id')})
        if not course:
            course = db['courses'].find_one({'_id': ObjectId(enrollment.get('course_id'))})
        if course:
            # Add teacher info for template
            course['teacher'] = db['users'].find_one({'user_id': course['teacher_id']})
            course['course_id'] = course.get('course_id', str(course.get('_id')))
            reviews = list(db['reviews'].find({'course_id': course['course_id']}))
            course['reviews_list'] = reviews
            if reviews:
                course['avg_rating'] = sum(r['rating'] for r in reviews) / len(reviews)
            else:
                course['avg_rating'] = 0
            enrolled_courses.append((course, enrollment))
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
            
            db['users'].update_one({'_id': ObjectId(current_user.user_id)}, {'$set': {
                'first_name': current_user.first_name,
                'last_name': current_user.last_name,
                'bio': current_user.bio,
                'profile_pic': current_user.profile_pic,
                'password_hash': current_user.password_hash
            }})
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('student_profile'))
        except Exception as e:
            flash('Failed to update profile', 'danger')
            print(f"Error updating profile: {str(e)}")
    
    # Get student's statistics
    enrollments_cursor = db['enrollments'].find({'student_id': current_user.user_id})
    enrollments = list(enrollments_cursor)

    total_courses = len(enrollments)
    completed_courses = sum(1 for e in enrollments if e.get('progress', 0) == 100)
    in_progress_courses = total_courses - completed_courses
    avg_progress = sum(e.get('progress', 0) for e in enrollments) / total_courses if total_courses > 0 else 0
    
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
    courses_cursor = db['courses'].find({'teacher_id': current_user.user_id})
    courses = list(courses_cursor)
    
    for course in courses:
        course['course_id'] = course.get('course_id', str(course.get('_id')))
    
    # Calculate total students, earnings, and ratings for each course
    total_students = 0
    total_earnings = 0
    
    for course in courses:
        # Get enrollments for this course
        enrollments = db['enrollments'].find({'course_id': course['course_id']})
        
        # Get reviews and calculate average rating for this course
        reviews_cursor = db['reviews'].find({'course_id': course['course_id']})
        reviews = list(reviews_cursor)
        
        # Calculate average rating
        if reviews:
            total_rating = sum(r['rating'] for r in reviews)
            course['average_rating'] = total_rating / len(reviews)
        else:
            course['average_rating'] = 0
        
        course['reviews'] = reviews
        total_students += len(list(enrollments))
        total_earnings += course['price'] * len(list(enrollments))
    
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
    courses = list(db['courses'].find({'teacher_id': current_user.user_id}))
    for course in courses:
        # Ensure course_id is present (fallback to _id if missing)
        course['course_id'] = course.get('course_id', str(course.get('_id')))
        # Optionally, add enrolled_students for template
        course['enrolled_students'] = db['enrollments'].count_documents({'course_id': course['course_id']})
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
            
            course_doc = {
                'teacher_id': current_user.user_id,
                'title': title,
                'description': description,
                'price': price,
                'category': category,
                'is_published': False,
                'created_at': datetime.utcnow()
            }
            
            if 'thumbnail' in request.files:
                file = request.files['thumbnail']
                if file and allowed_file(file.filename):
                    filename = secure_filename(f"course_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}")
                    file.save(os.path.join('static', 'images', 'course_thumbnails', filename))
                    course_doc['thumbnail_url'] = f"images/course_thumbnails/{filename}"
            
            db['courses'].insert_one(course_doc)
            flash('Course created successfully!', 'success')
            return redirect(url_for('manage_courses'))
        except Exception as e:
            flash('Failed to create course.', 'danger')
            print(f"Error creating course: {str(e)}")
    
    return render_template('dashboard/teacher/create_course.html')

@app.route('/teacher/course_content/<int:course_id>', methods=['GET', 'POST'])
@login_required
def course_content(course_id):
    if current_user.user_type != 'teacher':
        return redirect(url_for('home'))
    course = db['courses'].find_one({'course_id': course_id})
    if course['teacher_id'] != current_user.user_id:
        abort(403)
    return render_template('dashboard/teacher/course_content.html', course=course)

@app.route('/teacher/settings', methods=['GET', 'POST'])
@login_required
def teacher_settings():
    if current_user.user_type != 'teacher':
        return redirect(url_for('home'))
    return render_template('dashboard/teacher/settings.html')

# Course routes
@app.route('/course/<course_id>')
def view_course(course_id):
    # Try to find by int course_id, then fallback to _id
    course = db['courses'].find_one({'course_id': course_id})
    if not course:
        try:
            course = db['courses'].find_one({'_id': ObjectId(course_id)})
        except Exception:
            course = None
    if not course:
        abort(404)
    # Ensure course_id is always set
    course['course_id'] = course.get('course_id', str(course.get('_id')))
    # Add instructor info
    course['instructor'] = db['users'].find_one({'user_id': course['teacher_id']})
    # Add is_enrolled for current user
    is_enrolled = False
    if current_user.is_authenticated and current_user.user_type == 'student':
        is_enrolled = db['enrollments'].find_one({'student_id': current_user.user_id, 'course_id': course['course_id']} ) is not None
    course['is_enrolled'] = is_enrolled
    # Fetch reviews and attach author info
    reviews = list(db['reviews'].find({'course_id': course['course_id']}))
    for review in reviews:
        review['author'] = db['users'].find_one({'user_id': review['student_id']})
    course['reviews'] = reviews
    # Calculate avg_rating
    if reviews:
        course['avg_rating'] = sum(r['rating'] for r in reviews) / len(reviews)
    else:
        course['avg_rating'] = 0
    # Fetch first content_id for Continue Learning button
    first_content = db['course_content'].find_one({'course_id': course['course_id']}, sort=[('position', 1)])
    first_content_id = first_content['content_id'] if first_content else None
    return render_template('course/course_details.html', course=course, first_content_id=first_content_id)

@app.route('/course/<course_id>/enroll', methods=['POST'])
@login_required
def enroll_course(course_id):
    if current_user.user_type != 'student':
        flash('Only students can enroll in courses', 'danger')
        return redirect(url_for('view_course', course_id=course_id))
    
    # Try to find by int course_id, then fallback to string
    lookup_id = course_id
    try:
        lookup_id = int(course_id)
    except (ValueError, TypeError):
        pass
    existing = db['enrollments'].find_one({'student_id': current_user.user_id, 'course_id': lookup_id})
    
    if existing:
        flash('You are already enrolled in this course', 'info')
        return redirect(url_for('view_course', course_id=course_id))
    
    try:
        db['enrollments'].insert_one({
            'student_id': current_user.user_id,
            'course_id': lookup_id
        })
        flash('Successfully enrolled in the course!', 'success')
    except Exception as e:
        flash('Failed to enroll in the course', 'danger')
        print(f"Error enrolling in course: {str(e)}")
    return redirect(url_for('view_course', course_id=course_id))

@app.route('/course/<course_id>/review', methods=['GET', 'POST'])
@login_required
def add_review(course_id):
    course = db['courses'].find_one({'course_id': course_id})
    if not course:
        try:
            course = db['courses'].find_one({'_id': ObjectId(course_id)})
        except Exception:
            course = None
    if not course:
        abort(404)
    # Only students who are enrolled can review
    enrollment = db['enrollments'].find_one({'student_id': current_user.user_id, 'course_id': course.get('course_id', str(course.get('_id')))})
    if not enrollment:
        flash('You must be enrolled to review this course.', 'warning')
        return redirect(url_for('view_course', course_id=course_id))
    if request.method == 'POST':
        rating = int(request.form.get('rating', 0))
        comment = request.form.get('comment', '').strip()
        if not (1 <= rating <= 5):
            flash('Rating must be between 1 and 5.', 'danger')
            return redirect(url_for('view_course', course_id=course_id))
        review_doc = {
            'course_id': course.get('course_id', str(course.get('_id'))),
            'student_id': current_user.user_id,
            'rating': rating,
            'comment': comment,
            'created_at': datetime.utcnow()
        }
        db['reviews'].insert_one(review_doc)
        flash('Review submitted!', 'success')
        return redirect(url_for('view_course', course_id=course_id))
    return redirect(url_for('view_course', course_id=course_id))

# Content management routes
@app.route('/course/<course_id>/content/<content_id>/progress', methods=['POST'])
@login_required
def update_content_progress(course_id, content_id):
    enrollment = db['enrollments'].find_one({'student_id': current_user.user_id, 'course_id': course_id})
    
    if not enrollment:
        return jsonify({'success': False, 'error': 'Not enrolled'}), 403
    
    try:
        progress_data = request.json.get('progress', 0)
        progress = db['user_video_progress'].find_one({'user_id': current_user.user_id, 'content_id': content_id})
        if not progress:
            db['user_video_progress'].insert_one({
                'user_id': current_user.user_id,
                'content_id': content_id,
                'progress': progress_data,
                'course_id': course_id
            })
        else:
            db['user_video_progress'].update_one({'_id': progress['_id']}, {'$set': {'progress': max(progress.get('progress', 0), progress_data)}})
        return jsonify({'success': True, 'progress': progress_data})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/course/<course_id>/content/<content_id>/complete', methods=['POST'])
@login_required
def mark_content_completed(course_id, content_id):
    enrollment = db['enrollments'].find_one({'student_id': current_user.user_id, 'course_id': course_id})
    
    if not enrollment:
        return jsonify({'success': False, 'error': 'Not enrolled'}), 403
    
    try:
        progress = db['user_video_progress'].find_one({'user_id': current_user.user_id, 'content_id': content_id})
        if not progress:
            db['user_video_progress'].insert_one({
                'user_id': current_user.user_id,
                'content_id': content_id,
                'completed': True,
                'progress': 100,
                'course_id': course_id
            })
        else:
            db['user_video_progress'].update_one({'_id': progress['_id']}, {'$set': {'completed': True, 'progress': 100}})
        # Update overall course progress
        all_content = list(db['course_content'].find({'course_id': course_id}))
        completed_count = db['user_video_progress'].count_documents({'user_id': current_user.user_id, 'course_id': course_id, 'completed': True})
        enrollment_progress = int((completed_count / len(all_content)) * 100) if all_content else 0
        # Check if course is completed
        if enrollment_progress == 100:
            db['enrollments'].update_one({'_id': enrollment['_id']}, {'$set': {'completed': True, 'completion_date': datetime.utcnow()}})
        db['enrollments'].update_one({'_id': enrollment['_id']}, {'$set': {'progress': enrollment_progress}})
        return jsonify({'success': True, 'progress': enrollment_progress, 'completed': enrollment_progress == 100})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/course/<course_id>/content/<content_id>')
@login_required
def view_course_content(course_id, content_id):
    enrollment = db['enrollments'].find_one({'student_id': current_user.user_id, 'course_id': course_id})
    
    if not enrollment:
        flash('You need to enroll in this course first', 'warning')
        return redirect(url_for('view_course', course_id=course_id))
    
    content = db['course_content'].find_one({'course_id': course_id, 'content_id': content_id})
    if not content or content['course_id'] != course_id:
        abort(404)
    
    all_content = list(db['course_content'].find({'course_id': course_id}).sort('position'))
    
    # Get progress for current content
    progress = db['user_video_progress'].find_one({'user_id': current_user.user_id, 'content_id': content_id})
    
    # Get progress for all content items
    for item in all_content:
        item_progress = db['user_video_progress'].find_one({'user_id': current_user.user_id, 'content_id': item['content_id']})
        if item_progress:
            item['progress_records'] = [item_progress]
    
    return render_template('course/video_player.html',
        course_id=course_id,
        content=content,
        all_content=all_content,
        progress=progress
    )

@app.route('/teacher/courses/<course_id>/content', methods=['GET', 'POST'])
@login_required
def manage_course_content(course_id):
    if current_user.user_type != 'teacher':
        return redirect(url_for('home'))
    
    course = None
    try:
        int_course_id = int(course_id)
        course = db['courses'].find_one({'course_id': int_course_id})
    except (ValueError, TypeError):
        pass
    if not course:
        try:
            course = db['courses'].find_one({'_id': ObjectId(course_id)})
        except Exception:
            course = None
    if not course or course['teacher_id'] != current_user.user_id:
        abort(404)
    
    # Ensure course_id is always set for the template
    course['course_id'] = course.get('course_id', str(course.get('_id')))

    lookup_id = course.get('course_id', str(course.get('_id')))
    content_items = list(db['course_content'].find({'course_id': lookup_id}).sort('position'))
    
    if request.method == 'POST':
        if 'delete' in request.form:
            try:
                content_id = request.form.get('content_id')
                # Always use string course_id and content_id for deletion
                db['course_content'].delete_one({'course_id': str(course['course_id']), 'content_id': str(content_id)})
            except Exception as e:
                print(f"[ERROR] Failed to delete content: {e}")
            return redirect(url_for('manage_course_content', course_id=course['course_id']))
        elif 'reorder' in request.form:
            try:
                order = request.form.getlist('content_order[]')
                for idx, content_id in enumerate(order, start=1):
                    content = db['course_content'].find_one({'course_id': str(course['course_id']), 'content_id': str(content_id)})
                    if content:
                        db['course_content'].update_one({'course_id': str(course['course_id']), 'content_id': str(content_id)}, {'$set': {'position': idx}})
                return redirect(url_for('manage_course_content', course_id=course['course_id']))
            except Exception as e:
                print(f"[ERROR] Failed to reorder content: {e}")
                return redirect(url_for('manage_course_content', course_id=course['course_id']))
        return redirect(url_for('manage_course_content', course_id=course['course_id']))
    
    return render_template('dashboard/teacher/manage_content.html',
        course=course,
        content_items=content_items
    )

@app.route('/teacher/courses/<course_id>/content/add', methods=['GET', 'POST'])
@login_required
def add_course_content(course_id):
    if current_user.user_type != 'teacher':
        return redirect(url_for('home'))
    
    course = None
    try:
        int_course_id = int(course_id)
        course = db['courses'].find_one({'course_id': int_course_id})
    except (ValueError, TypeError):
        pass
    if not course:
        try:
            course = db['courses'].find_one({'_id': ObjectId(course_id)})
        except Exception:
            course = None
    if not course or course['teacher_id'] != current_user.user_id:
        abort(404)

    # Ensure course_id is always set for the template
    course['course_id'] = course.get('course_id', str(course.get('_id')))

    if request.method == 'POST':
        try:
            title = request.form.get('title')
            content_type = request.form.get('content_type')
            url = request.form.get('url')
            description = request.form.get('description', '')
            
            if not all([title, content_type, url]):
                return jsonify({'success': False, 'error': 'Title, type, and URL are required'}), 400
            
            # Safely get max_position
            last_content = db['course_content'].find_one(sort=[('position', -1)])
            max_position = last_content['position'] if last_content and 'position' in last_content else 0
            
            db['course_content'].insert_one({
                'course_id': course['course_id'],
                'content_id': str(ObjectId()),
                'title': title,
                'description': description,
                'content_type': content_type,
                'url': url,
                'position': max_position + 1
            })
            # Redirect to manage content after successful add
            return redirect(url_for('manage_course_content', course_id=course['course_id']))
        except Exception as e:
            return jsonify({'success': False, 'error': 'Failed to add content'}), 500
    
    return render_template('dashboard/teacher/add_content.html', course=course)

@app.route('/teacher/courses/<course_id>/content/<content_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_course_content(course_id, content_id):
    if current_user.user_type != 'teacher':
        return redirect(url_for('home'))

    # Find the course and content
    course = None
    try:
        int_course_id = int(course_id)
        course = db['courses'].find_one({'course_id': int_course_id})
    except (ValueError, TypeError):
        pass
    if not course:
        try:
            course = db['courses'].find_one({'_id': ObjectId(course_id)})
        except Exception:
            course = None
    if not course or course['teacher_id'] != current_user.user_id:
        abort(404)
    course['course_id'] = course.get('course_id', str(course.get('_id')))

    content = db['course_content'].find_one({'course_id': course['course_id'], 'content_id': content_id})
    if not content:
        abort(404)

    if request.method == 'POST':
        title = request.form.get('title')
        content_type = request.form.get('content_type')
        url = request.form.get('url')
        description = request.form.get('description', '')
        db['course_content'].update_one(
            {'course_id': course['course_id'], 'content_id': content_id},
            {'$set': {
                'title': title,
                'content_type': content_type,
                'url': url,
                'description': description
            }}
        )
        return redirect(url_for('manage_course_content', course_id=course['course_id']))

    return render_template('dashboard/teacher/add_content.html', course=course, content=content)

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
            
            db['users'].update_one({'_id': ObjectId(current_user.user_id)}, {'$set': {
                'first_name': current_user.first_name,
                'last_name': current_user.last_name,
                'bio': current_user.bio,
                'profile_pic': current_user.profile_pic,
                'password_hash': current_user.password_hash
            }})
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('teacher_profile'))
        except Exception as e:
            flash('Failed to update profile', 'danger')
            print(f"Error updating profile: {str(e)}")
    
    # Get teacher's statistics
    courses = list(db['courses'].find({'teacher_id': current_user.user_id}))
    for course in courses:
        course['course_id'] = course.get('course_id', str(course.get('_id')))
    total_students = db['enrollments'].count_documents({'course_id': {'$in': [c['course_id'] for c in courses]}})
    total_reviews = db['reviews'].count_documents({'course_id': {'$in': [c['course_id'] for c in courses]}})
    ratings = [r.get('rating', 0) for r in db['reviews'].find({'course_id': {'$in': [c['course_id'] for c in courses]}})]
    total_reviews = len(ratings)
    avg_rating = sum(ratings) / total_reviews if total_reviews > 0 else 0
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
    courses = list(db['courses'].find({'teacher_id': current_user.user_id}))
    for course in courses:
        course['course_id'] = course.get('course_id', str(course.get('_id')))
    course_earnings = []
    total_earnings = 0
    total_students = 0
    for course in courses:
        enrollments = db['enrollments'].find({'course_id': course['course_id']})
        course_student_count = len(list(enrollments))
        course_total = course['price'] * course_student_count
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

@app.route('/teacher/edit_course/<course_id>', methods=['GET', 'POST'])
@login_required
def edit_course(course_id):
    if current_user.user_type != 'teacher':
        return redirect(url_for('home'))
    
    course = None
    try:
        int_course_id = int(course_id)
        course = db['courses'].find_one({'course_id': int_course_id})
    except (ValueError, TypeError):
        pass
    if not course:
        try:
            course = db['courses'].find_one({'_id': ObjectId(course_id)})
        except Exception:
            course = None
    if course['teacher_id'] != current_user.user_id:
        abort(403)
    
    if request.method == 'POST':
        try:
            course['title'] = request.form.get('title')
            course['description'] = request.form.get('description')
            course['price'] = float(request.form.get('price'))
            course['category'] = request.form.get('category')
            
            # Capitalize the first letter of the title
            course['title'] = capitalize_first(course['title'])
            
            if 'thumbnail' in request.files:
                file = request.files['thumbnail']
                if file and allowed_file(file.filename):
                    filename = secure_filename(f"course_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}")
                    file.save(os.path.join('static', 'images', 'course_thumbnails', filename))
                    # Delete old thumbnail if it exists
                    if course.get('thumbnail_url'):
                        old_path = os.path.join('static', course['thumbnail_url'])
                        if os.path.exists(old_path):
                            os.remove(old_path)
                    course['thumbnail_url'] = f"images/course_thumbnails/{filename}"
            
            db['courses'].update_one({'_id': ObjectId(course['_id'])}, {'$set': {
                'title': course['title'],
                'description': course['description'],
                'price': course['price'],
                'category': course['category'],
                'thumbnail_url': course['thumbnail_url']
            }})
            flash('Course updated successfully!', 'success')
            return redirect(url_for('manage_courses'))
        except Exception as e:
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
    # Try to find by course_id (str or int), then fallback to _id
    course = db['courses'].find_one({'course_id': course_id})
    if not course:
        try:
            int_course_id = int(course_id)
            course = db['courses'].find_one({'course_id': int_course_id})
        except (ValueError, TypeError):
            pass
    if not course:
        try:
            course = db['courses'].find_one({'_id': ObjectId(course_id)})
        except Exception:
            course = None

    if not course:
        flash('Course not found.', 'error')
        return redirect(url_for('teacher_dashboard'))

    # Ensure the course belongs to the current teacher
    if course['teacher_id'] != current_user.user_id:
        flash('You do not have permission to delete this course.', 'error')
        return redirect(url_for('teacher_dashboard'))

    try:
        # Use the actual course_id for all related deletes
        actual_course_id = course.get('course_id', str(course.get('_id')))

        # Delete course thumbnail if it exists
        if course.get('thumbnail_url'):
            thumbnail_path = os.path.join('static', course['thumbnail_url'])
            if os.path.exists(thumbnail_path):
                os.remove(thumbnail_path)

        # Delete all associated data
        db['course_content'].delete_many({'course_id': actual_course_id})
        db['enrollments'].delete_many({'course_id': actual_course_id})
        db['reviews'].delete_many({'course_id': actual_course_id})
        # If you have user progress or other related collections, add them here:
        # db['user_video_progress'].delete_many({'course_id': actual_course_id})

        # Finally delete the course itself
        db['courses'].delete_one({'_id': ObjectId(course['_id'])})

        flash('Course has been permanently deleted.', 'success')
    except Exception as e:
        flash('An error occurred while deleting the course.', 'error')
        app.logger.error(f"Error deleting course {course_id}: {str(e)}")
    
    return redirect(url_for('teacher_dashboard'))

def init_db():
    try:
        with app.app_context():
            db['user_video_progress'].drop()
            db['users'].create_index([('username', 1)], unique=True)
            db['users'].create_index([('email', 1)], unique=True)
            db['courses'].create_index([('teacher_id', 1)])
            db['enrollments'].create_index([('student_id', 1), ('course_id', 1)])
            db['reviews'].create_index([('student_id', 1), ('course_id', 1)])
            db['course_content'].create_index([('course_id', 1)])
    except ServerSelectionTimeoutError as e:
        print("[MongoDB Connection Error]", e)
        print("Check your Atlas cluster, network, and connection string.")
        exit(1)

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