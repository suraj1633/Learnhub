from flask import Blueprint, request, redirect, url_for, flash, current_app
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename
from utils.text_utils import capitalize_first, capitalize_name
import os

teacher_forms_bp = Blueprint('teacher_forms', __name__)

@teacher_forms_bp.route('/create-course', methods=['POST'])
@login_required
def create_course():
    if request.method == 'POST':
        # Get form data with proper capitalization
        title = capitalize_first(request.form.get('title', '').strip())
        description = capitalize_first(request.form.get('description', '').strip())
        category = capitalize_first(request.form.get('category', '').strip())
        price = float(request.form.get('price', 0))
        
        # Create new course
        course = Course(
            title=title,
            description=description,
            category=category,
            price=price,
            teacher_id=current_user.id
        )

        # Handle thumbnail upload
        if 'thumbnail' in request.files:
            file = request.files['thumbnail']
            if file and allowed_file(file.filename):
                try:
                    filename = secure_filename(file.filename)
                    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], 'images', 'profile_pics', filename)
                    file.save(filepath)
                    course.thumbnail_url = f"images/profile_pics/{filename}"
                except Exception as e:
                    flash('Error uploading thumbnail.', 'error')

        db.session.add(course)
        db.session.commit()
        flash('Course created successfully!', 'success')
        return redirect(url_for('teacher.manage_course', course_id=course.id))

@teacher_forms_bp.route('/edit-course/<int:course_id>', methods=['POST'])
@login_required
def edit_course(course_id):
    course = Course.query.get_or_404(course_id)
    
    if course.teacher_id != current_user.id:
        flash('You do not have permission to edit this course.', 'error')
        return redirect(url_for('teacher.dashboard'))

    # Get form data with proper capitalization
    title = capitalize_first(request.form.get('title', '').strip())
    description = capitalize_first(request.form.get('description', '').strip())
    category = capitalize_first(request.form.get('category', '').strip())
    price = float(request.form.get('price', 0))

    # Update course information
    course.title = title
    course.description = description
    course.category = category
    course.price = price

    # Handle thumbnail update
    if 'thumbnail' in request.files:
        file = request.files['thumbnail']
        if file and allowed_file(file.filename):
            try:
                filename = secure_filename(file.filename)
                filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], 'images', 'profile_pics', filename)
                file.save(filepath)
                course.thumbnail_url = f"images/profile_pics/{filename}"
            except Exception as e:
                flash('Error uploading thumbnail.', 'error')

    db.session.commit()
    flash('Course updated successfully!', 'success')
    return redirect(url_for('teacher.manage_course', course_id=course_id))

@teacher_forms_bp.route('/add-content/<int:course_id>', methods=['POST'])
@login_required
def add_course_content(course_id):
    course = Course.query.get_or_404(course_id)
    
    if course.teacher_id != current_user.id:
        flash('You do not have permission to add content to this course.', 'error')
        return redirect(url_for('teacher.dashboard'))

    # Get form data with proper capitalization
    title = capitalize_first(request.form.get('title', '').strip())
    description = capitalize_first(request.form.get('description', '').strip())
    content_type = request.form.get('type')
    
    # Create new content
    content = CourseContent(
        title=title,
        description=description,
        content_type=content_type,
        course_id=course_id
    )

    db.session.add(content)
    db.session.commit()
    flash('Content added successfully!', 'success')
    return redirect(url_for('teacher.manage_course_content', course_id=course_id))

@teacher_forms_bp.route('/edit-content/<int:content_id>', methods=['POST'])
@login_required
def edit_course_content(content_id):
    content = CourseContent.query.get_or_404(content_id)
    course = Course.query.get(content.course_id)
    
    if course.teacher_id != current_user.id:
        flash('You do not have permission to edit this content.', 'error')
        return redirect(url_for('teacher.dashboard'))

    # Get form data with proper capitalization
    title = capitalize_first(request.form.get('title', '').strip())
    description = capitalize_first(request.form.get('description', '').strip())
    
    # Update content
    content.title = title
    content.description = description

    db.session.commit()
    flash('Content updated successfully!', 'success')
    return redirect(url_for('teacher.manage_course_content', course_id=content.course_id)) 