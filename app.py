from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os
from functools import wraps
from datetime import datetime, timedelta

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your_secret_key')
app.permanent_session_lifetime = timedelta(minutes=30)

# MongoDB Setup
try:
    client = MongoClient(os.getenv("MONGO_URI"))
    db = client['campusApp']
    users = db['users']
    students = db['students']
    activities = db['activities']
    events = db['events']
except Exception as e:
    print(f"MongoDB Connection Error: {e}")

    @app.route("/error")
    def error():
        return render_template('error.html', message="Database connection failed.")
    
    exit(1)

# Auth Decorator
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            flash("You need to log in first.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# Activity Logger
def log_activity(action, user_name, role):
    activities.insert_one({
        'user_name': user_name,
        'role': role,
        'action': action,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })

@app.route('/')
def home():
    return redirect(url_for('login'))

# Admin-only Signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'user' not in session or session['user']['role'] != 'admin':
        flash("Unauthorized access.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        role = request.form['role']

        if users.find_one({'email': email}):
            flash('User already exists.')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password)
        users.insert_one({'name': name, 'email': email, 'password': hashed_password, 'role': role})

        if role == 'student':
            students.insert_one({
                'name': name,
                'email': email,
                'grades': {},
                'attendance': {}
            })

        log_activity('Registered a new user', name, role)
        flash('User registered successfully.')
        return redirect(url_for('admin_dashboard'))

    return render_template('signup.html')

# Login for all roles
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']

        user = users.find_one({'email': email})
        print(f"Login attempt: {email}, User Found: {user is not None}")  # Debug line

        if user and check_password_hash(user['password'], password):
            session.permanent = True
            session['user'] = {
                'email': user['email'],
                'role': user['role'],
                'name': user['name']
            }
            return redirect(url_for(f"{user['role']}_dashboard"))

        flash('Invalid email or password.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.')
    return redirect(url_for('login'))

# Admin Dashboard
@app.route('/admin')
@login_required
def admin_dashboard():
    if session['user']['role'] != 'admin':
        flash("Unauthorized access.")
        return redirect(url_for('login'))

    recent_activities = activities.find().sort('timestamp', -1).limit(5)
    return render_template('admin_dashboard.html', activities=recent_activities)

# Student Dashboard
@app.route('/student_dashboard')
@login_required
def student_dashboard():
    user = session.get('user', {})
    student = students.find_one({'email': user.get('email')})

    if not student:
        flash("Student record not found.")
        return redirect(url_for('login'))

    grades = student.get('grades', {})
    attendance_dict = student.get('attendance', {})
    subjects = list(grades.keys())
    grades_values = list(grades.values())
    attendance = [attendance_dict.get(sub, 0) for sub in subjects]

    return render_template('student_dashboard.html',
                           grades=grades,
                           subjects=subjects,
                           grades_values=grades_values,
                           attendance=attendance)

# Faculty Dashboard
@app.route('/faculty_dashboard')
@login_required
def faculty_dashboard():
    if session['user']['role'] not in ['faculty', 'admin']:
        flash("Unauthorized access.")
        return redirect(url_for('login'))

    all_students = list(students.find())
    return render_template('faculty_dashboard.html', students=all_students)

# Update Student Record
@app.route('/update_student_record', methods=['POST'])
@login_required
def update_student_record():
    if session['user']['role'] not in ['faculty', 'admin']:
        flash("Unauthorized access.")
        return redirect(url_for('login'))

    student_email = request.form['student_email'].strip().lower()
    subject = request.form['subject'].strip()
    attendance_value = int(request.form['attendance'].strip())

    try:
        grade = int(request.form['grade'])
    except ValueError:
        flash("Invalid grade entered.")
        return redirect(url_for('faculty_dashboard'))

    student = students.find_one({'email': student_email})
    if not student:
        flash("Student not found.")
        return redirect(url_for('faculty_dashboard'))

    update_fields = {
        f"grades.{subject}": grade,
        f"attendance.{subject}": attendance_value
    }

    students.update_one({'email': student_email}, {'$set': update_fields})
    log_activity(f"Updated {subject} for {student_email}", session['user']['name'], session['user']['role'])
    flash("Student record updated.")
    return redirect(url_for('faculty_dashboard'))

# Staff Dashboard
@app.route('/staff_dashboard')
@login_required
def staff_dashboard():
    if session['user']['role'] not in ['staff', 'admin']:
        flash("Unauthorized access.")
        return redirect(url_for('login'))

    event_list = events.find().sort("timestamp", -1)
    notification_list = activities.find().sort("timestamp", -1)
    return render_template('staff_dashboard.html', events=event_list, notifications=notification_list)

# Create Event
@app.route('/create_event', methods=['POST'])
@login_required
def create_event():
    if session['user']['role'] != 'staff':
        flash("Unauthorized access.")
        return redirect(url_for('login'))

    title = request.form['title'].strip()
    date = request.form['date'].strip()
    event_type = request.form['event_type']

    if title and date:
        events.insert_one({
            'title': title,
            'date': date,
            'event_type': event_type,
            'created_by': session['user']['name'],
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        log_activity('Created a new event', session['user']['name'], session['user']['role'])

    return redirect(url_for('staff_dashboard'))

# Send Notification
@app.route('/send_notification', methods=['POST'])
@login_required
def send_notification():
    if session['user']['role'] != 'staff':
        flash("Unauthorized access.")
        return redirect(url_for('login'))

    notification_text = request.form['notification_text'].strip()
    if notification_text:
        activities.insert_one({
            'user_name': session['user']['name'],
            'role': session['user']['role'],
            'action': f"Notification: {notification_text}",
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        log_activity('Sent a notification', session['user']['name'], session['user']['role'])

    return redirect(url_for('staff_dashboard'))

# View All Users - Admin Only
@app.route('/view_users')
@login_required
def view_users():
    if session['user']['role'] != 'admin':
        flash("Unauthorized access.")
        return redirect(url_for('login'))

    query = request.args.get('search', '').strip()
    if query:
        found_users = users.find({
            '$or': [
                {'name': {'$regex': query, '$options': 'i'}},
                {'email': {'$regex': query, '$options': 'i'}}
            ]
        })
    else:
        found_users = users.find()

    return render_template('view_users.html', users=found_users)

# Optional: API Routes
@app.route('/get_events')
@login_required
def get_events():
    return jsonify(list(events.find().sort('timestamp', -1).limit(20)))

@app.route('/get_notifications')
@login_required
def get_notifications():
    return jsonify(list(activities.find().sort('timestamp', -1).limit(1)))

# View Student Profile
@app.route('/view_student/<email>')
@login_required
def view_student(email):
    if session['user']['role'] not in ['admin', 'faculty', 'staff']:
        flash("Unauthorized access.")
        return redirect(url_for('login'))

    student = students.find_one({'email': email})
    if not student:
        flash("Student not found.")
        return redirect(url_for(f"{session['user']['role']}_dashboard"))

    grades = student.get('grades', {})
    attendance_dict = student.get('attendance', {})
    subjects = list(grades.keys())
    grades_values = list(grades.values())
    attendance = [attendance_dict.get(sub, 0) for sub in subjects]

    return render_template('student_dashboard.html',
                           grades=grades,
                           subjects=subjects,
                           grades_values=grades_values,
                           attendance=attendance,
                           is_viewing=True,
                           student_name=student.get('name', 'Student'))

# Search Student
@app.route('/search_student')
@login_required
def search_student():
    if session['user']['role'] not in ['admin', 'faculty', 'staff']:
        flash("Unauthorized access.")
        return redirect(url_for('login'))

    query = request.args.get('query', '').strip()
    if not query:
        flash("Please enter a name or email to search.")
        return redirect(url_for(f"{session['user']['role']}_dashboard"))

    student = students.find_one({
        '$or': [
            {'name': {'$regex': query, '$options': 'i'}},
            {'email': {'$regex': query, '$options': 'i'}}
        ]
    })

    if student:
        return redirect(url_for('view_student', email=student['email']))
    else:
        flash("Student not found.")
        return redirect(url_for(f"{session['user']['role']}_dashboard"))

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
