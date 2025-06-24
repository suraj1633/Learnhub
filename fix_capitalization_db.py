from app import db, User, Course
from utils.text_utils import capitalize_first, capitalize_name

def fix_user_capitalization():
    users = User.query.all()
    for user in users:
        user.username = capitalize_first(user.username)
        user.first_name = capitalize_name(user.first_name)
        user.last_name = capitalize_name(user.last_name)
        user.bio = capitalize_first(user.bio)
    db.session.commit()
    print(f"Updated {len(users)} users.")

def fix_course_capitalization():
    courses = Course.query.all()
    for course in courses:
        course.title = capitalize_first(course.title)
        course.description = capitalize_first(course.description)
        course.category = capitalize_first(course.category)
    db.session.commit()
    print(f"Updated {len(courses)} courses.")

if __name__ == "__main__":
    fix_user_capitalization()
    fix_course_capitalization()
    print("Capitalization fix complete.") 