# LearnHub

LearnHub is a modern, full-featured online learning platform for students and teachers. It allows teachers to create and manage courses, upload video and document content, and track student progress. Students can browse, enroll in, and complete courses, as well as leave reviews and manage their profiles.

## Features

- User authentication (Student & Teacher roles)
- Teacher dashboard for course creation, management, and earnings
- Student dashboard for enrolled courses, progress tracking, and profile management
- Video and document content delivery with progress tracking
- Course reviews and ratings
- Responsive, modern UI with dark mode support
- Secure file uploads for course thumbnails and profile pictures
- Admin features for managing users and content (optional)

## Tech Stack

- **Backend:** Flask (Python), SQLAlchemy (MySQL by default)
- **Frontend:** Jinja2 templates, HTML5, CSS3, JavaScript
- **Database:** MySQL (default), easy to adapt to MongoDB Atlas or other DBs
- **Authentication:** Flask-Login
- **File Uploads:** Flask, Werkzeug

## Getting Started

### Prerequisites
- Python 3.8+
- pip
- MySQL (or MongoDB Atlas if you adapt the backend)
- Node.js & npm (for frontend asset management, optional)

### Installation
1. **Clone the repository:**
   ```bash
   git clone https://github.com/suraj1633/Learnhub.git
   cd LearnHub
   ```
2. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
3. **Set up the database:**
   - Create a MySQL database named `learnhub` (or update the URI in `app.py`/`config.py`).
   - Run migrations (if using Alembic):
     ```bash
     flask db upgrade
     ```
4. **Run the app:**
   ```bash
   python app.py
   ```
5. **Access the site:**
   Open [http://localhost:5000](http://localhost:5000) in your browser.

### File Structure
```
learnhub2/
  app.py
  config.py
  requirements.txt
  static/
  templates/
  routes/
  utils/
  ...
```

## Usage
- Register as a student or teacher
- Teachers can create, edit, and delete courses
- Students can browse, enroll, and complete courses
- Both can manage their profiles

## Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

