from app import app, db  # Replace with your actual app file/module

'''
with app.app_context():
    try:
        db.engine.connect()
        print("Database connection successful!")
    except Exception as e:
        print(f"Database connection failed: {e}")
'''
 # Make sure to import app and db properly
from sqlalchemy import inspect

with app.app_context():
    inspector = inspect(db.engine)
    print(inspector.get_table_names())