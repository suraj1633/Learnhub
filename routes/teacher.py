from flask import Blueprint, render_template, request, redirect, url_for, flash
from utils.text_utils import capitalize_first, capitalize_name
import os
from werkzeug.utils import secure_filename
from flask_login import login_required
from flask_sqlalchemy import SQLAlchemy

teacher_bp = Blueprint('teacher', __name__)
db = SQLAlchemy()

@teacher_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        # Get form data
        first_name = capitalize_name(request.form.get('first_name', '').strip())
        last_name = capitalize_name(request.form.get('last_name', '').strip())
        bio = capitalize_first(request.form.get('bio', '').strip())
        
        # Update user information
        current_user.first_name = first_name
        current_user.last_name = last_name
        current_user.bio = bio

        # Handle profile picture upload if provided
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and allowed_file(file.filename):
                try:
                    filename = secure_filename(file.filename)
                    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], 'images', 'profile_pics', filename)
                    file.save(filepath)
                    current_user.profile_pic = f"images/profile_pics/{filename}"
                except Exception as e:
                    flash('Error uploading profile picture.', 'error')

        # Handle password change if provided
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if current_password and new_password and confirm_password:
            if not current_user.check_password(current_password):
                flash('Current password is incorrect.', 'error')
            elif new_password != confirm_password:
                flash('New passwords do not match.', 'error')
            else:
                current_user.set_password(new_password)
                flash('Password updated successfully.', 'success')

        db.session.commit()
        flash('Profile updated successfully.', 'success')
        return redirect(url_for('teacher.profile'))

    return render_template('dashboard/teacher/profile.html') 