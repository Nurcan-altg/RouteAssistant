import os
import requests
import smtplib
import ssl
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import time, datetime, timedelta
from flask_apscheduler import APScheduler
from functools import wraps

# --- 1. APPLICATION AND CONFIGURATION ---
HERE_API_KEY = 'ytgGZ-wUPNBeMVp42gQS3v1khDLt3JULvgxNtIN58CM'      # HERE Developer Portal'dan aldığın API anahtarı
SENDER_EMAIL = 'altugnurcan01@gmail.com' # Gönderici Gmail adresi
SENDER_PASSWORD = 'nehcituobfvumhum'   # Gmail'den aldığın 16 haneli uygulama şifresi


basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'this-should-be-a-very-secret-key'
db = SQLAlchemy(app)

# --- 2. DATABASE MODELS ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    locations = db.relationship('Location', backref='owner', lazy=True, cascade="all, delete-orphan")
    routes = db.relationship('Route', backref='owner', lazy=True, cascade="all, delete-orphan")

class Location(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Route(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    departure_time = db.Column(db.Time, nullable=False)
    alert_threshold = db.Column(db.Integer, nullable=False, default=20)
    transport_mode = db.Column(db.String(20), nullable=False, default='car')
    start_location_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=False)
    end_location_id = db.Column(db.Integer, db.ForeignKey('location.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    start_location = db.relationship('Location', primaryjoin='Route.start_location_id == Location.id', lazy='joined')
    end_location = db.relationship('Location', primaryjoin='Route.end_location_id == Location.id', lazy='joined')

# --- 3. HELPER FUNCTIONS ---
def send_alert_email(recipient_email, subject, message_body):
    port = 465; smtp_server = "smtp.gmail.com"; context = ssl.create_default_context()
    email_message = f"Subject: {subject}\n\n{message_body}".encode('utf-8')
    try:
        with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, recipient_email, email_message)
            print(f"Alert email sent successfully to: {recipient_email}")
    except Exception as e:
        print(f"Error sending email: {e}")

def check_routes_and_send_alerts():
    print(f"Check time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Checking routes...")
    with app.app_context():
        routes_to_check = Route.query.all()
        now_time = datetime.now().time()
        for route in routes_to_check:
            time_diff_seconds = (datetime.combine(datetime.today(), route.departure_time) - datetime.combine(datetime.today(), now_time)).total_seconds()
            if 0 <= time_diff_seconds <= 1800:
                print(f"-> Processing route '{route.name}' ({route.transport_mode})...")
                start_loc, end_loc = route.start_location, route.end_location
                url = (f"https://router.hereapi.com/v8/routes?transportMode={route.transport_mode}"
                       f"&origin={start_loc.latitude},{start_loc.longitude}"
                       f"&destination={end_loc.latitude},{end_loc.longitude}&return=summary&apikey={HERE_API_KEY}")
                try:
                    data = requests.get(url).json()
                    if 'routes' in data and data['routes']:
                        summary = data['routes'][0]['sections'][0]['summary']
                        duration = summary['duration']
                        if route.transport_mode == 'car':
                            base_duration = summary['baseDuration']
                            delay_percentage = ((duration - base_duration) / base_duration) * 100 if base_duration > 0 else 0
                            print(f"   Delay: {delay_percentage:.1f}% (Threshold: {route.alert_threshold}%)")
                            if delay_percentage > route.alert_threshold:
                                subject = "RouteAssistant Traffic Alert"
                                message_body = (f"Hello {route.owner.username},\n\n"
                                               f"Traffic on your route '{route.name}' is {delay_percentage:.0f}% heavier than usual.\n"
                                               f"The journey, which normally takes {base_duration//60} minutes, will now take approximately {duration//60} minutes.\n\n"
                                               f"RouteAssistant")
                                send_alert_email(route.owner.email, subject, message_body)
                        else:
                            subject = "RouteAssistant Departure Reminder"
                            message_body = (f"Hello {route.owner.username},\n\n"
                                           f"It's almost time for your journey on the '{route.name}' ({route.transport_mode}) route.\n"
                                           f"The estimated travel time is approximately {duration//60} minutes.\n\n"
                                           f"Have a great trip!\nRouteAssistant")
                            send_alert_email(route.owner.email, subject, message_body)
                except Exception as e:
                    print(f"Error during API request or analysis: {e}")

# --- 4. AUTHORIZATION & CONTEXT ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session: return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if user.role != 'admin':
            flash('You are not authorized to access this page.', 'danger'); return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.context_processor
def inject_user():
    if 'user_id' in session: return dict(current_user=User.query.get(session['user_id']))
    return dict(current_user=None)

# --- 5. WEBPAGE ROUTES ---
@app.route('/')
def home():
    if 'user_id' in session: return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username, email, password = request.form['username'], request.form['email'], request.form['password']
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('This username or email is already in use.', 'danger'); return redirect(url_for('register'))
        new_user = User(username=username, email=email, password_hash=generate_password_hash(password))
        db.session.add(new_user); db.session.commit()
        flash('You have registered successfully! Please log in.', 'success'); return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email, password = request.form['email'], request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id; flash('Login successful!', 'success'); return redirect(url_for('dashboard'))
        else: flash('Login failed. Please check your email and password.', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: 
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    locations_objects = user.locations
    locations_for_json = [{'id': loc.id, 'name': loc.name, 'latitude': loc.latitude, 'longitude': loc.longitude} for loc in locations_objects]
    routes = Route.query.filter_by(user_id=session['user_id']).all()
    # THE FIX IS HERE: Added 'routes=routes' to the return statement
    return render_template('dashboard.html', current_user=user, locations=locations_objects, locations_json=locations_for_json, routes=routes)

@app.route('/add_location', methods=['POST'])
def add_location():
    if 'user_id' not in session: return redirect(url_for('login'))
    location_name, latitude, longitude = request.form['location_name'], request.form['latitude'], request.form['longitude']
    if not all([location_name, latitude, longitude]):
        flash('Location name and a point from the map are required.', 'danger'); return redirect(url_for('dashboard'))
    new_location = Location(name=location_name, latitude=float(latitude), longitude=float(longitude), owner=User.query.get(session['user_id']))
    db.session.add(new_location); db.session.commit()
    flash(f'Location "{location_name}" has been added successfully.', 'success'); return redirect(url_for('dashboard'))

@app.route('/add_route', methods=['POST'])
def add_route():
    if 'user_id' not in session: return redirect(url_for('login'))
    try:
        route_name = request.form['route_name']
        start_id = request.form['start_location_id']
        end_id = request.form['end_location_id']
        transport_mode = request.form['transport_mode']
        dep_time_str = request.form['departure_time']
        threshold = request.form['alert_threshold']
        if start_id == end_id:
            flash('Start and end locations cannot be the same.', 'danger'); return redirect(url_for('dashboard'))
        departure_time_obj = datetime.strptime(dep_time_str, '%H:%M').time()
        new_route = Route(name=route_name, start_location_id=int(start_id), end_location_id=int(end_id), 
                          departure_time=departure_time_obj, alert_threshold=int(threshold), 
                          transport_mode=transport_mode, user_id=session['user_id'])
        db.session.add(new_route)
        db.session.commit()
        flash(f'Route "{route_name}" has been created successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        print(f"ERROR: An issue occurred while adding a route: {e}")
        flash('An unexpected error occurred while creating the route.', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/edit_location/<int:location_id>', methods=['GET', 'POST'])
def edit_location(location_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    location_to_edit = Location.query.filter_by(id=location_id, user_id=session['user_id']).first_or_404()
    if request.method == 'POST':
        location_to_edit.name = request.form['location_name']
        db.session.commit()
        flash('Location name has been updated successfully.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('edit_location.html', location=location_to_edit)

@app.route('/edit_route/<int:route_id>', methods=['GET', 'POST'])
def edit_route(route_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    route_to_edit = Route.query.filter_by(id=route_id, user_id=session['user_id']).first_or_404()
    if request.method == 'POST':
        route_to_edit.name = request.form['route_name']
        route_to_edit.start_location_id = int(request.form['start_location_id'])
        route_to_edit.end_location_id = int(request.form['end_location_id'])
        route_to_edit.transport_mode = request.form['transport_mode']
        route_to_edit.departure_time = datetime.strptime(request.form['departure_time'], '%H:%M').time()
        route_to_edit.alert_threshold = int(request.form['alert_threshold'])
        db.session.commit()
        flash('Route has been updated successfully.', 'success')
        return redirect(url_for('dashboard'))
    user_locations = Location.query.filter_by(user_id=session['user_id']).all()
    return render_template('edit_route.html', route=route_to_edit, locations=user_locations)

@app.route('/delete_location/<int:location_id>', methods=['POST'])
def delete_location(location_id):
    if 'user_id' not in session:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': 'Please log in.'}), 401
        return redirect(url_for('login'))
    location_to_delete = Location.query.filter_by(id=location_id, user_id=session['user_id']).first()
    if location_to_delete:
        Route.query.filter((Route.start_location_id == location_id) | (Route.end_location_id == location_id)).delete()
        db.session.delete(location_to_delete); db.session.commit()
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': True, 'message': 'Location and its associated routes have been deleted successfully.'})
        flash('Location and its associated routes have been deleted successfully.', 'success')
    else:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': 'Location not found or you do not have permission to delete it.'}), 404
        flash('Location not found or you do not have permission to delete it.', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/delete_route/<int:route_id>', methods=['POST'])
def delete_route(route_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    route_to_delete = Route.query.filter_by(id=route_id, user_id=session['user_id']).first()
    if route_to_delete:
        db.session.delete(route_to_delete); db.session.commit()
        flash('Route has been deleted successfully.', 'success')
    else: flash('Route not found or you do not have permission to delete it.', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session: return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        current_password, new_password, confirm_password = request.form['current_password'], request.form['new_password'], request.form['confirm_password']
        if not check_password_hash(user.password_hash, current_password):
            flash('Your current password is incorrect!', 'danger'); return redirect(url_for('profile'))
        if new_password != confirm_password:
            flash('New passwords do not match!', 'danger'); return redirect(url_for('profile'))
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        flash('Your password has been updated successfully.', 'success'); return redirect(url_for('dashboard'))
    return render_template('profile.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/admin')
@admin_required
def admin_dashboard():
    all_users = User.query.order_by(User.id).all()
    stats = {'total_users': User.query.count(),'total_locations': Location.query.count(),'total_routes': Route.query.count()}
    return render_template('admin/admin_dashboard.html', users=all_users, stats=stats)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    user_to_delete = User.query.get(user_id)
    if user_to_delete and user_to_delete.role != 'admin':
        db.session.delete(user_to_delete); db.session.commit()
        flash(f"User '{user_to_delete.username}' and all their data have been deleted successfully.", 'success')
    else: flash("User not found or you cannot delete an admin.", 'danger')
    return redirect(url_for('admin_dashboard'))

# --- 6. SCHEDULER INITIALIZATION ---
scheduler = APScheduler()
scheduler.add_job(id='Scheduled Route Check', func=check_routes_and_send_alerts, trigger='interval', minutes=1)
scheduler.init_app(app)
scheduler.start()

# --- 7. MAIN BLOCK TO RUN THE APP ---
if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
