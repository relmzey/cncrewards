import os
import json
import random
import string
import hashlib
import requests
from datetime import datetime, timedelta
from threading import Timer
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pymongo import MongoClient
from bson.objectid import ObjectId

# Load configuration
with open('config.json', 'r') as f:
    config = json.load(f)

with open('timer.json', 'r') as f:
    timer_config = json.load(f)

with open('links.json', 'r') as f:
    links_config = json.load(f)

with open('access.json', 'r') as f:
    access_config = json.load(f)

app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET')
if not app.secret_key:
    raise ValueError("SESSION_SECRET environment variable must be set for security")

# Add Cache-Control headers to prevent caching issues
@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# MongoDB setup
MONGODB_URI = "mongodb+srv://ceres:officaldatabase@cluster0.pzpbqrv.mongodb.net/?retryWrites=true&w=majority"
client = MongoClient(MONGODB_URI)
db = client.kprp_rewards

# Collections
users_collection = db.users
purchases_collection = db.purchases
dynamic_routes_collection = db.dynamic_routes
user_timers_collection = db.user_timers
ip_tracking_collection = db.ip_tracking
user_cooldowns_collection = db.user_cooldowns

# Webhook URL for logging
WEBHOOK_URL = "https://discord.com/api/webhooks/1411026048836960378/nM-CVwOxcYo4nFlRJ6DlD_CeoaeEoePYzZw_FpgpV6QVZUoMEUXrV--OoMTvRM_bDKaP"

def init_db():
    # Create indexes for better performance
    users_collection.create_index("username", unique=True)
    users_collection.create_index("email", unique=True)
    purchases_collection.create_index("user_id")

    # Drop old unique index on route_path if it exists and recreate as non-unique
    try:
        dynamic_routes_collection.drop_index("route_path_1")
    except:
        pass

    dynamic_routes_collection.create_index("route_path")
    dynamic_routes_collection.create_index("link_type")
    dynamic_routes_collection.create_index([("link_type", 1), ("expires_at", 1)])

    user_timers_collection.create_index("user_id")
    user_timers_collection.create_index([("user_id", 1), ("link_type", 1)])
    
    # Drop old unique index on user_id if it exists and recreate as non-unique
    try:
        user_cooldowns_collection.drop_index("user_id_1")
    except:
        pass
    
    user_cooldowns_collection.create_index("user_id")
    user_cooldowns_collection.create_index([("user_id", 1), ("link_type", 1)])
    ip_tracking_collection.create_index("ip_address", unique=True)

class User(UserMixin):
    def __init__(self, id, username, email, balance, is_verified):
        self.id = str(id)
        self.username = username
        self.email = email
        self.balance = balance
        self.is_verified = is_verified

@login_manager.user_loader
def load_user(user_id):
    user_data = users_collection.find_one({"_id": ObjectId(user_id)})
    if user_data:
        return User(user_data['_id'], user_data['username'], user_data['email'], 
                   user_data['balance'], user_data['is_verified'])
    return None

def generate_code():
    return ''.join(random.choices(string.digits, k=6))

def generate_route():
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

def send_webhook_log(title, description, color=0x00ff00, fields=None):
    """Send webhook notification to Discord"""
    try:
        webhook_data = {
            "embeds": [{
                "title": title,
                "description": description,
                "color": color,
                "timestamp": datetime.now().isoformat(),
                "fields": fields or []
            }]
        }
        requests.post(WEBHOOK_URL, json=webhook_data)
    except Exception as e:
        print(f"Webhook error: {e}")

def send_email(to_email, subject, content):
    """Send email using SMTP (Gmail) - simple alternative to SendGrid"""
    try:
        smtp_server = "smtp.gmail.com"
        smtp_port = 587
        sender_email = "kprprewards@gmail.com"
        sender_password = "gzgg cjes oumt wkpl"

        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = to_email
        msg['Subject'] = subject

        msg.attach(MIMEText(content, 'plain'))

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        text = msg.as_string()
        server.sendmail(sender_email, to_email, text)
        server.quit()

        print(f"Email sent successfully to {to_email}")
        return True

    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def send_webhook(webhook_url, data):
    try:
        requests.post(webhook_url, json=data)
    except Exception as e:
        print(f"Webhook error: {e}")

def get_device_info(user_agent):
    """Extract device information from user agent"""
    ua = user_agent.lower()
    if 'mobile' in ua or 'android' in ua or 'iphone' in ua:
        if 'android' in ua:
            return '📱 Android Mobile'
        elif 'iphone' in ua or 'ipad' in ua:
            return '📱 iOS Mobile'
        else:
            return '📱 Mobile Device'
    elif 'windows' in ua:
        return '💻 Windows PC'
    elif 'mac' in ua:
        return '💻 Mac'
    elif 'linux' in ua:
        return '💻 Linux'
    else:
        return '🖥️ Unknown Device'

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html', config=config)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        user_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', ''))
        if ',' in user_ip:
            user_ip = user_ip.split(',')[0].strip()

        user_agent = request.headers.get('User-Agent', 'Unknown')
        device_info = get_device_info(user_agent)

        # Check if user exists
        if users_collection.find_one({"$or": [{"username": username}, {"email": email}]}):
            flash('Username or email already exists!')
            return render_template('register.html', config=config)

        # Check if IP already has an account
        existing_ip = ip_tracking_collection.find_one({"ip_address": user_ip})
        if existing_ip:
            # Send webhook for alt account attempt
            send_webhook_log(
                "🚨 Alt Account Attempt Detected",
                f"Someone tried to create another account from an existing IP",
                0xff0000,
                [
                    {"name": "Attempted Username", "value": username, "inline": True},
                    {"name": "Attempted Email", "value": email, "inline": True},
                    {"name": "IP Address", "value": user_ip, "inline": True},
                    {"name": "Device", "value": device_info, "inline": False},
                    {"name": "Original Account Created", "value": existing_ip['account_created_at'].strftime('%Y-%m-%d %H:%M:%S'), "inline": True}
                ]
            )
            flash('Only one account per IP address is allowed!')
            return render_template('register.html', config=config)

        verification_code = generate_code()
        password_hash = generate_password_hash(password)

        subject = f"Welcome to {config['app_name']} - Verify Your Account"
        content = f"""
Dear {username},

Welcome to {config['app_name']}! We're excited to have you join our community of coin earners.

To complete your account setup and start earning coins, please verify your email address using the code below:

Verification Code: {verification_code}

What you can do next:
• Complete tasks to earn coins
• Redeem coins for amazing rewards
• Track your earnings and purchases

If you didn't create this account, please ignore this email.

Best regards,
The {config['app_name']} Team
Created by {config['created_by']}
YouTube: {config['youtube_channel']}
        """
        email_sent = send_email(email, subject, content)

        if email_sent:
            users_collection.insert_one({
                "username": username,
                "email": email,
                "password_hash": password_hash,
                "balance": 0,
                "is_verified": False,
                "verification_code": verification_code,
                "reset_code": None,
                "created_at": datetime.now()
            })
            ip_tracking_collection.insert_one({
                "ip_address": user_ip,
                "username": username,
                "account_created_at": datetime.now()
            })
            
            # Send webhook for new registration
            send_webhook_log(
                "👤 New User Registration",
                f"A new user has registered!",
                0x00ff00,
                [
                    {"name": "Username", "value": username, "inline": True},
                    {"name": "Email", "value": email, "inline": True},
                    {"name": "IP Address", "value": user_ip, "inline": True},
                    {"name": "Device", "value": device_info, "inline": True},
                    {"name": "Status", "value": "Pending Email Verification", "inline": True}
                ]
            )
            
            flash('Registration successful! Please check your email for verification code.')
            return redirect(url_for('verify_email', email=email))
        else:
            flash('Registration failed: Could not send verification email. Please contact support.')
            return render_template('register.html', config=config)

    return render_template('register.html', config=config)

@app.route('/verify_email/<email>')
def verify_email(email):
    return render_template('verify_email.html', email=email, config=config)

@app.route('/verify_code', methods=['POST'])
def verify_code():
    email = request.form['email']
    code = request.form['code']

    user = users_collection.find_one({"email": email, "verification_code": code})

    if user:
        users_collection.update_one(
            {"email": email},
            {"$set": {"is_verified": True}, "$unset": {"verification_code": ""}}
        )

        user_data = users_collection.find_one({"email": email})
        user_obj = User(user_data['_id'], user_data['username'], user_data['email'], 
                       user_data['balance'], user_data['is_verified'])
        login_user(user_obj)
        flash('Email verified successfully! Welcome to your dashboard.')
        return redirect(url_for('dashboard'))
    else:
        flash('Invalid verification code!')
        return redirect(url_for('verify_email', email=email))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', ''))
        if ',' in user_ip:
            user_ip = user_ip.split(',')[0].strip()

        user_agent = request.headers.get('User-Agent', 'Unknown')
        device_info = get_device_info(user_agent)

        user_data = users_collection.find_one({"username": username})

        if user_data and check_password_hash(user_data['password_hash'], password):
            if user_data['is_verified']:
                user = User(user_data['_id'], user_data['username'], user_data['email'], 
                           user_data['balance'], user_data['is_verified'])
                login_user(user)
                
                # Send webhook for successful login
                send_webhook_log(
                    "🔓 User Login",
                    f"User **{username}** logged in successfully",
                    0x3498db,
                    [
                        {"name": "Username", "value": username, "inline": True},
                        {"name": "Balance", "value": f"{user_data['balance']} coins", "inline": True},
                        {"name": "IP Address", "value": user_ip, "inline": True},
                        {"name": "Device", "value": device_info, "inline": True}
                    ]
                )
                
                return redirect(url_for('dashboard'))
            else:
                flash('Please verify your email first!')
        else:
            flash('Invalid username or password!')

    return render_template('login.html', config=config)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        user = users_collection.find_one({"email": email})

        if user:
            reset_code = generate_code()
            users_collection.update_one(
                {"email": email},
                {"$set": {"reset_code": reset_code}}
            )

            subject = f"{config['app_name']} - Password Reset Request"
            content = f"""
Dear User,

We received a request to reset your password for your {config['app_name']} account.

Password Reset Code: {reset_code}

Please use this code to reset your password. If you didn't request this password reset, please ignore this email and your password will remain unchanged.

For security reasons, this code will expire soon, so please use it promptly.

Best regards,
The {config['app_name']} Team
            """
            send_email(email, subject, content)

            flash('Password reset code sent to your email!')
            return redirect(url_for('reset_password', email=email))
        else:
            flash('Email not found!')

    return render_template('forgot_password.html', config=config)

@app.route('/reset_password/<email>', methods=['GET', 'POST'])
def reset_password(email):
    if request.method == 'POST':
        code = request.form['code']
        new_password = request.form['new_password']

        user = users_collection.find_one({"email": email, "reset_code": code})

        if user:
            password_hash = generate_password_hash(new_password)
            users_collection.update_one(
                {"email": email},
                {"$set": {"password_hash": password_hash}, "$unset": {"reset_code": ""}}
            )
            flash('Password reset successfully!')
            return redirect(url_for('login'))
        else:
            flash('Invalid reset code!')

    return render_template('reset_password.html', email=email, config=config)

@app.route('/dashboard')
@login_required
def dashboard():
    # Get user data with creation date
    user_data = users_collection.find_one({"_id": ObjectId(current_user.id)})

    # Get purchase count
    purchase_count = purchases_collection.count_documents({"user_id": ObjectId(current_user.id)})

    # Get recent purchases (last 5)
    recent_purchases_cursor = purchases_collection.find({
        "user_id": ObjectId(current_user.id)
    }).sort("created_at", -1).limit(5)

    recent_purchases = list(recent_purchases_cursor)

    # Update current_user object with creation date
    current_user.created_at = user_data.get('created_at')

    return render_template('dashboard.html', 
                         user=current_user, 
                         config=config,
                         purchase_count=purchase_count,
                         recent_purchases=recent_purchases)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/earn_coins')
@login_required
def earn_coins():
    # Generate/get different routes for each link type
    expire_time_check = datetime.now()
    routes_dict = {}
    new_routes_generated = []

    for link_type in timer_config['links'].keys():
        # Check if route exists and is not expired
        route_data = dynamic_routes_collection.find_one({
            "link_type": link_type,
            "expires_at": {"$gt": expire_time_check}
        })

        if not route_data:
            # Generate new route for this link type
            new_route = generate_route()
            expire_time = datetime.now() + timedelta(hours=timer_config['route_generation_hours'])

            # Delete old routes for this link type
            dynamic_routes_collection.delete_many({"link_type": link_type})

            # Insert new route
            dynamic_routes_collection.insert_one({
                "link_type": link_type,
                "route_path": new_route,
                "created_at": datetime.now(),
                "expires_at": expire_time
            })

            # Add to list for webhook
            new_routes_generated.append({
                "link_type": link_type,
                "route": new_route,
                "expires": expire_time
            })

            routes_dict[link_type] = new_route
        else:
            routes_dict[link_type] = route_data['route_path']

    # Send single webhook with all new routes
    if new_routes_generated:
        fields = []
        for route_info in new_routes_generated:
            fields.append({
                "name": f"{route_info['link_type']}",
                "value": f"Route: `{route_info['route']}`\nExpires: {route_info['expires'].strftime('%Y-%m-%d %H:%M')}",
                "inline": False
            })

        send_webhook_log(
            "🔄 Routes Refreshed",
            f"**{len(new_routes_generated)}** new destination routes generated",
            0x3498db,
            fields
        )

    # Get user timers (2-minute wait timers)
    active_timers_cursor = user_timers_collection.find({
        "user_id": ObjectId(current_user.id),
        "timer_end": {"$gt": datetime.now()}
    })
    active_timers = {timer['link_type']: timer['timer_end'] for timer in active_timers_cursor}
    
    # Get per-link cooldowns (3-hour cooldowns after completion)
    link_cooldowns_cursor = user_cooldowns_collection.find({
        "user_id": ObjectId(current_user.id),
        "cooldown_end": {"$gt": datetime.now()}
    })
    link_cooldowns = {cooldown['link_type']: cooldown['cooldown_end'] for cooldown in link_cooldowns_cursor}

    return render_template('earn_coins.html', 
                         timer_config=timer_config, 
                         routes_dict=routes_dict,
                         active_timers=active_timers,
                         link_cooldowns=link_cooldowns,
                         links_config=links_config,
                         config=config)

@app.route('/generate_link/<link_type>')
@login_required
def generate_link(link_type):
    try:
        print(f"DEBUG: Attempting to generate link for type: '{link_type}'")
        print(f"DEBUG: Available link types: {list(timer_config['links'].keys())}")

        if link_type not in timer_config['links']:
            return jsonify({'error': f'Invalid link type: {link_type}'}), 400

        # Check if this specific link is in 3-hour cooldown
        link_cooldown = user_cooldowns_collection.find_one({
            "user_id": ObjectId(current_user.id),
            "link_type": link_type,
            "cooldown_end": {"$gt": datetime.now()}
        })

        if link_cooldown:
            remaining = link_cooldown['cooldown_end'] - datetime.now()
            hours = int(remaining.total_seconds() // 3600)
            minutes = int((remaining.total_seconds() % 3600) // 60)
            return jsonify({'error': f'This link is in cooldown. Try again in {hours}h {minutes}m'}), 400

        # Check if user has active timer for this link
        active_timer = user_timers_collection.find_one({
            "user_id": ObjectId(current_user.id),
            "link_type": link_type,
            "timer_end": {"$gt": datetime.now()}
        })

        if active_timer:
            return jsonify({'error': 'Timer still active for this link'}), 400

        # Get route specific to this link type
        route_data = dynamic_routes_collection.find_one({
            "link_type": link_type,
            "expires_at": {"$gt": datetime.now()}
        })

        print(f"DEBUG: Route data found: {route_data is not None}")

        if not route_data:
            return jsonify({'error': 'No active route available'}), 400

        current_route = route_data['route_path']
        link_config = timer_config['links'][link_type]

        # Make API call to generate shortened link
        # Get the full URL including protocol
        destination_url = f"{request.scheme}://{request.host}/{current_route}"

        # URL encode the destination
        import urllib.parse
        encoded_destination = urllib.parse.quote(destination_url, safe='')

        # Build API URL without alias parameter
        api_url = link_config['api_url'].split('&alias=')[0].replace('{destination}', encoded_destination)

        print(f"DEBUG: API URL: {api_url}")
        print(f"DEBUG: Destination URL: {destination_url}")

        response = requests.get(api_url, timeout=10)
        response_data = response.json()

        print(f"DEBUG: API Response: {response_data}")

        if response_data.get('status') == 'success':
            # Set timer for user with start time
            timer_start = datetime.now()
            timer_end = timer_start + timedelta(minutes=link_config['timer_minutes'])
            user_timers_collection.update_one(
                {"user_id": ObjectId(current_user.id), "link_type": link_type},
                {"$set": {
                    "timer_start": timer_start,
                    "timer_end": timer_end,
                    "coins": link_config['coins']
                }},
                upsert=True
            )

            return jsonify({
                'success': True,
                'shortened_url': response_data.get('shortenedUrl'),
                'timer_minutes': link_config['timer_minutes']
            })
        else:
            print(f"DEBUG: API returned non-success status: {response_data}")
            return jsonify({'error': 'Failed to generate link', 'details': response_data}), 500

    except Exception as e:
        print(f"DEBUG: Exception in generate_link: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/<route_path>')
def claim_coins(route_path):
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    arrival_time = datetime.now()
    user_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', ''))
    if ',' in user_ip:
        user_ip = user_ip.split(',')[0].strip()

    # Check if route is valid and not expired
    route_data = dynamic_routes_collection.find_one({
        "route_path": route_path,
        "expires_at": {"$gt": datetime.now()}
    })

    if not route_data:
        return render_template('access_denied.html', message="Invalid or expired route", config=config)

    # Get link type from route
    link_type = route_data.get('link_type')

    # Check if user has active timer for this specific link type
    active_timer = user_timers_collection.find_one({
        "user_id": ObjectId(current_user.id),
        "link_type": link_type
    })

    if not active_timer:
        # Log bypass attempt
        send_webhook_log(
            "⚠️ Bypass Attempt Detected",
            f"User **{current_user.username}** tried to access reward route without valid timer",
            0xff6600,
            [
                {"name": "User", "value": current_user.username, "inline": True},
                {"name": "Link Type", "value": link_type, "inline": True},
                {"name": "IP Address", "value": user_ip, "inline": True},
                {"name": "Route", "value": route_path, "inline": True}
            ]
        )
        return render_template('access_denied.html', message="Bypass detected", config=config)
    
    # Log arrival time
    timer_start = active_timer.get('timer_start')
    time_taken = (arrival_time - timer_start).total_seconds() if timer_start else 0

    # Check if timer has expired (2 minutes passed)
    timer_start = active_timer.get('timer_start')
    if not timer_start or datetime.now() < active_timer.get('timer_end'):
        time_remaining = active_timer.get('timer_end') - datetime.now()
        minutes = int(time_remaining.total_seconds() // 60)
        seconds = int(time_remaining.total_seconds() % 60)
        return render_template('access_denied.html', 
                             message=f"Please wait {minutes}m {seconds}s before claiming coins",
                             config=config)

    # Get coins for this link type from timer config
    link_config = timer_config['links'].get(link_type, {})
    coins_to_award = link_config.get('coins', 1)

    # Award coins and remove timer
    users_collection.update_one(
        {"_id": ObjectId(current_user.id)},
        {"$inc": {"balance": coins_to_award}}
    )
    user_timers_collection.delete_one({
        "user_id": ObjectId(current_user.id),
        "link_type": link_type
    })

    # Set 3-hour cooldown for this specific link type
    cooldown_end = datetime.now() + timedelta(hours=3)
    user_cooldowns_collection.update_one(
        {"user_id": ObjectId(current_user.id), "link_type": link_type},
        {"$set": {"cooldown_end": cooldown_end}},
        upsert=True
    )

    # Format time taken
    minutes_taken = int(time_taken // 60)
    seconds_taken = int(time_taken % 60)
    time_display = f"{minutes_taken}m {seconds_taken}s"

    # Send webhook notification for link completion with arrival time
    send_webhook_log(
        "🎯 Link Completed",
        f"User **{current_user.username}** completed a link and earned {coins_to_award} coins!",
        0x00ff00,
        [
            {"name": "User", "value": current_user.username, "inline": True},
            {"name": "Link Type", "value": link_type, "inline": True},
            {"name": "Coins Earned", "value": str(coins_to_award), "inline": True},
            {"name": "Time Taken", "value": time_display, "inline": True},
            {"name": "Arrival Time", "value": arrival_time.strftime('%H:%M:%S'), "inline": True},
            {"name": "IP Address", "value": user_ip, "inline": True}
        ]
    )

    return render_template('claim_success.html', config=config)

@app.route('/store')
@login_required
def store():
    return render_template('store.html', config=config, user=current_user)

@app.route('/purchase_history')
@login_required
def purchase_history():
    purchases_cursor = purchases_collection.find({
        "user_id": ObjectId(current_user.id)
    }).sort("created_at", -1)

    purchases = list(purchases_cursor)

    return render_template('purchase_history.html', purchases=purchases, config=config)

@app.route('/purchase_history_data')
@login_required
def purchase_history_data():
    purchases_cursor = purchases_collection.find({
        "user_id": ObjectId(current_user.id)
    }).sort("created_at", -1)

    purchases = []
    for purchase in purchases_cursor:
        purchases.append({
            'item_name': purchase['item_name'],
            'coins_spent': purchase['coins_spent'],
            'status': purchase['status'],
            'created_at': purchase['created_at'].isoformat() if purchase['created_at'] else None
        })

    return jsonify(purchases)

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    # Check if current user email is in admin access list
    if current_user.email not in access_config['admin_emails']:
        flash('Access denied. You do not have admin privileges.')
        return redirect(url_for('dashboard'))

    purchases_cursor = purchases_collection.aggregate([
        {
            "$lookup": {
                "from": "users",
                "localField": "user_id",
                "foreignField": "_id",
                "as": "user"
            }
        },
        {"$unwind": "$user"},
        {"$sort": {"created_at": -1}}
    ])

    purchases = []
    for purchase in purchases_cursor:
        purchases.append({
            'id': str(purchase['_id']),
            'username': purchase['user']['username'],
            'item_name': purchase['item_name'],
            'coins_spent': purchase['coins_spent'],
            'status': purchase['status'],
            'created_at': purchase['created_at'],
            'item_details': purchase.get('item_details', ''),
            'store_type': purchase.get('store_type', ''),
            'admin_code': purchase.get('admin_code', ''),
            'voucher_code': purchase.get('voucher_code', ''),
            'proof_image': purchase.get('proof_image', '')
        })

    return render_template('admin_dashboard.html', purchases=purchases, config=config)

@app.route('/update_order_status', methods=['POST'])
@login_required
def update_order_status():
    if current_user.email not in access_config['admin_emails']:
        return jsonify({'error': 'Unauthorized'}), 401

    purchase_id = request.form['purchase_id']
    new_status = request.form['status']
    admin_code = request.form.get('admin_code', '')

    # Get order details
    purchase_data = purchases_collection.aggregate([
        {"$match": {"_id": ObjectId(purchase_id)}},
        {
            "$lookup": {
                "from": "users",
                "localField": "user_id",
                "foreignField": "_id",
                "as": "user"
            }
        },
        {"$unwind": "$user"}
    ]).next()

    if not purchase_data:
        return jsonify({'error': 'Order not found'}), 404

    # Update order
    update_data = {"status": new_status}
    if admin_code:
        update_data["admin_code"] = admin_code

    purchases_collection.update_one(
        {"_id": ObjectId(purchase_id)},
        {"$set": update_data}
    )

    # Send email notifications and webhook
    if new_status in ['approved', 'success']:
        item_name = purchase_data['item_name']
        username = purchase_data['user']['username']
        email = purchase_data['user']['email']
        voucher_code = purchase_data.get('voucher_code', '')

        if new_status == 'approved':
            subject = f"Order #{purchase_id} Approved - {config['app_name']}"
            content = f"""
Dear {username},

Good news! Your order has been approved and is now being processed.

Order ID: #{purchase_id}
Item: {item_name}
Status: Approved ✅

Your order will be completed within the next few hours. You'll receive another notification when it's ready.

Thank you for choosing {config['app_name']}!

Best regards,
The {config['app_name']} Team
            """

        elif new_status == 'success':
            subject = f"Order #{purchase_id} Completed - {config['app_name']}"
            
            # Determine item type and customize email
            item_details = purchase_data.get('item_details', '')
            
            if 'ff_diamond' in purchase_data['item_name'] or 'pubg_uc' in purchase_data['item_name'] or 'pes_coins' in purchase_data['item_name']:
                # Gaming items (Free Fire, PUBG, PES)
                uid_match = item_details.split('UID: ')[-1] if 'UID: ' in item_details else 'N/A'
                item_type = "diamonds" if 'diamond' in item_name.lower() else ("UC" if 'UC' in item_name else "coins")
                
                content = f"""
Dear {username},

🎉 Congratulations! Your gaming order has been successfully completed.

Order ID: #{purchase_id}
Item: {item_name}
Status: Completed ✅

Your {item_type} have been credited to the following UID: {uid_match}

If you didn't receive it, please contact us through Discord: https://discord.gg/DWzJFuyeFy

Thank you for choosing {config['app_name']}!

Best regards,
The {config['app_name']} Team
                """
            elif 'likes' in item_name.lower():
                # Likes store items
                uid_match = item_details.split('UID: ')[-1] if 'UID: ' in item_details else 'N/A'
                likes_count = admin_code if admin_code else 'N/A'
                
                content = f"""
Dear {username},

🎉 Great news! Your likes order has been completed.

Order ID: #{purchase_id}
Item: {item_name}
Status: Completed ✅

You got {likes_count} likes on UID: {uid_match}

Thanks for using our service!

Best regards,
The {config['app_name']} Team
                """
            elif 'amazon' in item_name.lower() or 'google_play' in item_name.lower():
                # Amazon and Google Play vouchers
                voucher_text = admin_code if admin_code else 'N/A'
                
                content = f"""
Dear {username},

🎉 Congratulations! Your voucher order has been successfully completed.

Order ID: #{purchase_id}
Item: {item_name}
Status: Completed ✅

Redeem Code: {voucher_text}

Please use this code to redeem your voucher. If you have any questions, please contact our support team.

Thank you for using {config['app_name']}!

Best regards,
The {config['app_name']} Team
                """
            else:
                # Default template for other items
                content = f"""
Dear {username},

🎉 Congratulations! Your order has been successfully completed.

Order ID: #{purchase_id}
Item: {item_name}
Status: Completed ✅
"""
                if voucher_code:
                    content += f"\nVoucher Code: {voucher_code}"
                if admin_code:
                    content += f"\nCode: {admin_code}"

                content += f"""

Your order is now ready! If you have any questions, please contact our support team.

Thank you for using {config['app_name']}!

Best regards,
The {config['app_name']} Team
                """

        send_email(email, subject, content)

        # Send webhook notification
        webhook_fields = [
            {"name": "Order ID", "value": f"#{purchase_id}", "inline": True},
            {"name": "User", "value": username, "inline": True},
            {"name": "Item", "value": item_name, "inline": True},
            {"name": "Status", "value": new_status.title(), "inline": True}
        ]

        if voucher_code:
            webhook_fields.append({"name": "Voucher Code", "value": voucher_code, "inline": True})
        if admin_code:
            webhook_fields.append({"name": "Redeem Code", "value": admin_code, "inline": True})

        color = 0xffa500 if new_status == 'approved' else 0x00ff00
        send_webhook_log(
            f"📦 Order {new_status.title()}",
            f"Order #{purchase_id} has been {new_status}",
            color,
            webhook_fields
        )

    return jsonify({'success': True})

@app.route('/complete_upi_transfer', methods=['POST'])
@login_required
def complete_upi_transfer():
    if current_user.email not in access_config['admin_emails']:
        return jsonify({'error': 'Unauthorized'}), 401

    purchase_id = request.form['purchase_id']

    # Handle transfer proof upload
    transfer_proof_path = None
    if 'transfer_proof' in request.files:
        proof_file = request.files['transfer_proof']
        if proof_file and proof_file.filename:
            # Create uploads directory if it doesn't exist
            import os
            uploads_dir = 'static/admin_uploads'
            if not os.path.exists(uploads_dir):
                os.makedirs(uploads_dir)

            # Save file with unique name
            import uuid
            file_extension = proof_file.filename.rsplit('.', 1)[1].lower()
            unique_filename = f"transfer_{uuid.uuid4()}.{file_extension}"
            transfer_proof_path = f"{uploads_dir}/{unique_filename}"
            proof_file.save(transfer_proof_path)

    if not transfer_proof_path:
        return jsonify({'error': 'Transfer proof is required'}), 400

    # Get order details
    purchase_data = purchases_collection.aggregate([
        {"$match": {"_id": ObjectId(purchase_id)}},
        {
            "$lookup": {
                "from": "users",
                "localField": "user_id",
                "foreignField": "_id",
                "as": "user"
            }
        },
        {"$unwind": "$user"}
    ]).next()

    if not purchase_data:
        return jsonify({'error': 'Order not found'}), 404

    # Update order with transfer proof and set to success
    purchases_collection.update_one(
        {"_id": ObjectId(purchase_id)},
        {"$set": {"transfer_proof": transfer_proof_path, "status": "success"}}
    )

    # Send success email with transfer proof
    item_name = purchase_data['item_name']
    username = purchase_data['user']['username']
    email = purchase_data['user']['email']

    subject = f"Order #{purchase_id} Completed - UPI Transfer Sent - {config['app_name']}"
    content = f"""
Dear {username},

🎉 Great news! Your UPI voucher order has been completed successfully.

Order ID: #{purchase_id}
Item: {item_name}
Status: Completed ✅

💰 The money has been transferred to your UPI ID! Please check your UPI app for the payment confirmation.

Transfer proof has been attached to this order for your reference.

If you don't receive the payment within a few minutes, please contact our support team with your order ID.

Thank you for using {config['app_name']}!

Best regards,
The {config['app_name']} Team
    """

    send_email(email, subject, content)

    # Send webhook notification
    webhook_fields = [
        {"name": "Order ID", "value": f"#{purchase_id}", "inline": True},
        {"name": "User", "value": username, "inline": True},
        {"name": "Item", "value": item_name, "inline": True},
        {"name": "Status", "value": "Completed", "inline": True},
        {"name": "Transfer Proof", "value": "Uploaded", "inline": True}
    ]

    send_webhook_log(
        "💰 UPI Transfer Completed",
        f"Order #{purchase_id} completed with UPI transfer proof uploaded",
        0x00ff00,
        webhook_fields
    )

    return jsonify({'success': True})

@app.route('/validate_voucher', methods=['POST'])
@login_required
def validate_voucher():
    if current_user.email not in access_config['admin_emails']:
        return jsonify({'error': 'Unauthorized'}), 401

    voucher_code = request.form.get('voucher_code', '').strip()

    if not voucher_code or len(voucher_code) != 16:
        return jsonify({'error': 'Invalid voucher code format. Must be 16 characters.'}), 400

    # Find purchase with this voucher code
    purchase = purchases_collection.aggregate([
        {"$match": {"voucher_code": voucher_code}},
        {
            "$lookup": {
                "from": "users",
                "localField": "user_id",
                "foreignField": "_id",
                "as": "user"
            }
        },
        {"$unwind": "$user"}
    ])

    purchase_list = list(purchase)
    
    if not purchase_list:
        return jsonify({
            'success': False,
            'message': 'Invalid voucher code. This code does not exist in our system.'
        })

    purchase_data = purchase_list[0]
    
    return jsonify({
        'success': True,
        'valid': True,
        'message': 'Valid KPRP Voucher!',
        'details': {
            'voucher_code': voucher_code,
            'item_name': purchase_data['item_name'],
            'username': purchase_data['user']['username'],
            'status': purchase_data['status'],
            'created_at': purchase_data['created_at'].strftime('%Y-%m-%d %H:%M:%S'),
            'order_id': str(purchase_data['_id'])
        }
    })

@app.route('/give_coins', methods=['POST'])
@login_required
def give_coins():
    if current_user.email not in access_config['admin_emails']:
        return jsonify({'error': 'Unauthorized'}), 401

    username = request.form['username']
    coins = int(request.form['coins'])

    user = users_collection.find_one({"username": username})

    if user:
        users_collection.update_one(
            {"username": username},
            {"$inc": {"balance": coins}}
        )
        return jsonify({'success': True, 'message': f'Successfully gave {coins} coins to {username}'})
    else:
        return jsonify({'error': 'User not found'})

@app.route('/delete_user', methods=['POST'])
@login_required
def delete_user():
    if current_user.email not in access_config['admin_emails']:
        return jsonify({'error': 'Unauthorized'}), 401

    username = request.form['username']

    user = users_collection.find_one({"username": username})

    if not user:
        return jsonify({'error': 'User not found'})

    user_id = user['_id']

    try:
        # Delete user's purchases
        purchases_collection.delete_many({"user_id": user_id})

        # Delete user's timers
        user_timers_collection.delete_many({"user_id": user_id})

        # Delete user's cooldowns
        user_cooldowns_collection.delete_many({"user_id": user_id})

        # Delete the user
        users_collection.delete_one({"_id": user_id})

        # Send webhook notification
        send_webhook_log(
            "🗑️ User Deleted",
            f"Admin **{current_user.username}** deleted user **{username}**",
            0xff0000,
            [
                {"name": "Deleted User", "value": username, "inline": True},
                {"name": "Admin", "value": current_user.username, "inline": True}
            ]
        )

        return jsonify({'success': True, 'message': f'Successfully deleted user {username} and all associated data'})

    except Exception as e:
        return jsonify({'error': f'Error deleting user: {str(e)}'})

@app.route('/purchase', methods=['POST'])
@login_required
def purchase():
    item_type = request.form['item_type']
    coins = int(request.form['coins'])
    additional_info = request.form.get('additional_info', '')

    # Handle file upload for UPI vouchers
    proof_image_path = None
    if 'proof_image' in request.files:
        proof_file = request.files['proof_image']
        if proof_file and proof_file.filename:
            # Create uploads directory if it doesn't exist
            import os
            uploads_dir = 'static/uploads'
            if not os.path.exists(uploads_dir):
                os.makedirs(uploads_dir)

            # Save file with unique name
            import uuid
            file_extension = proof_file.filename.rsplit('.', 1)[1].lower()
            unique_filename = f"{uuid.uuid4()}.{file_extension}"
            proof_image_path = f"{uploads_dir}/{unique_filename}"
            proof_file.save(proof_image_path)

    # Check if user has enough balance
    user_data = users_collection.find_one({"_id": ObjectId(current_user.id)})
    if user_data['balance'] < coins:
        return jsonify({'error': 'Insufficient balance'}), 400

    # Item details mapping
    item_details = {
        'ff_likes_1day': '1 Day Free Fire Likes (50-100 per day)',
        'ff_likes_7day': '7 Days Auto Free Fire Likes (50-100 per day)',
        'ff_likes_30day': '30 Days Auto Free Fire Likes (50-100 per day)',
        'ff_diamond_100': '100 Free Fire Diamonds',
        'ff_diamond_310': '310 Free Fire Diamonds',
        'ff_diamond_520': '520 Free Fire Diamonds',
        'ff_diamond_1060': '1060 Free Fire Diamonds',
        'ff_diamond_2180': '2180 Free Fire Diamonds',
        'ff_diamond_5600': '5600 Free Fire Diamonds',
        'kprp_cash_10l': 'KPRP 10 Lakh In-Game Cash',
        'kprp_cash_30l': 'KPRP 30 Lakh In-Game Cash',
        'kprp_cash_50l': 'KPRP 50 Lakh In-Game Cash',
        'kprp_cash_1cr': 'KPRP 1 Cr In-Game Cash',
        'kprp_vip_base': 'KPRP Base VIP Plan',
        'kprp_vip_bronze': 'KPRP Bronze VIP Plan',
        'kprp_vip_silver': 'KPRP Silver VIP Plan',
        'kprp_vip_gold': 'KPRP Gold VIP Plan',
        'kprp_vip_diamond': 'KPRP Diamond VIP Plan',
        'kprp_vip_legendary': 'KPRP Legendary VIP Plan',
        'kprp_car_normal': 'KPRP Normal Car',
        'kprp_car_normal_2nd': 'KPRP Normal 2nd Class Car',
        'kprp_car_normal_3rd': 'KPRP Normal 3rd Class Car',
        'kprp_car_rare_2nd': 'KPRP Rare 2nd Class Car',
        'kprp_car_rare_1st': 'KPRP Rare 1st Class Car',
        'kprp_car_restricted': 'KPRP Restricted Car',
        'kprp_car_exotic': 'KPRP Exotic Car',
        'kprp_voucher_10': 'KPRP ₹10 Voucher',
        'kprp_voucher_50': 'KPRP ₹50 Voucher',
        'kprp_voucher_100': 'KPRP ₹100 Voucher',
        'kprp_voucher_200': 'KPRP ₹200 Voucher',
        'kprp_voucher_500': 'KPRP ₹500 Voucher',
        'kprp_voucher_1000': 'KPRP ₹1000 Voucher',
        'upi_voucher_10': '₹10 UPI Voucher',
        'upi_voucher_20': '₹20 UPI Voucher',
        'upi_voucher_50': '₹50 UPI Voucher',
        'upi_voucher_100': '₹100 UPI Voucher',
        'amazon_voucher_10': '₹10 Amazon Voucher',
        'amazon_voucher_30': '₹30 Amazon Voucher',
        'amazon_voucher_50': '₹50 Amazon Voucher',
        'amazon_voucher_100': '₹100 Amazon Voucher',
        'amazon_voucher_200': '₹200 Amazon Voucher',
        'amazon_voucher_500': '₹500 Amazon Voucher',
        'amazon_voucher_1000': '₹1,000 Amazon Voucher',
        'amazon_voucher_2000': '₹2,000 Amazon Voucher',
        'amazon_voucher_5000': '₹5,000 Amazon Voucher',
        'google_play_10': '₹10 Google Play Code',
        'google_play_30': '₹30 Google Play Code',
        'google_play_50': '₹50 Google Play Code',
        'google_play_100': '₹100 Google Play Code',
        'google_play_200': '₹200 Google Play Code',
        'google_play_500': '₹500 Google Play Code',
        'google_play_1000': '₹1,000 Google Play Code',
        'pubg_uc_60': '60 PUBG UC',
        'pubg_uc_325': '325 PUBG UC',
        'pubg_uc_660': '660 PUBG UC',
        'pubg_uc_1800': '1800 PUBG UC',
        'pubg_uc_3850': '3850 PUBG UC',
        'pes_coins_250': '250 PES/eFootball Coins',
        'pes_coins_1050': '1,050 PES/eFootball Coins',
        'pes_coins_2150': '2,150 PES/eFootball Coins',
        'pes_coins_3300': '3,300 PES/eFootball Coins',
        'pes_coins_6900': '6,900 PES/eFootball Coins'
    }

    item_name = item_details.get(item_type, item_type)

    # Generate 16-character voucher code for KPRP vouchers
    voucher_code = ''
    auto_complete = False
    
    if 'kprp_voucher' in item_type:
        voucher_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))
        auto_complete = True  # KPRP vouchers don't need admin approval

    # Deduct coins and create purchase record
    users_collection.update_one(
        {"_id": ObjectId(current_user.id)},
        {"$inc": {"balance": -coins}}
    )

    # Set status based on item type
    initial_status = "success" if auto_complete else "pending"

    purchase_doc = {
        "user_id": ObjectId(current_user.id),
        "store_type": item_type.split('_')[0],
        "item_name": item_name,
        "coins_spent": coins,
        "item_details": additional_info,
        "status": initial_status,
        "created_at": datetime.now()
    }

    if voucher_code:
        purchase_doc["voucher_code"] = voucher_code

    if proof_image_path:
        purchase_doc["proof_image"] = proof_image_path

    result = purchases_collection.insert_one(purchase_doc)
    purchase_id = str(result.inserted_id)

    # Send webhook notification for new order
    webhook_fields = [
        {"name": "User", "value": current_user.username, "inline": True},
        {"name": "Item", "value": item_name, "inline": True},
        {"name": "Coins Spent", "value": str(coins), "inline": True},
        {"name": "Order ID", "value": f"#{purchase_id}", "inline": True}
    ]

    if additional_info:
        webhook_fields.append({"name": "Details", "value": additional_info, "inline": False})

    send_webhook_log(
        "🛒 New Order Placed",
        f"**{current_user.username}** placed a new order!",
        0x0099ff,
        webhook_fields
    )

    # Send email based on item type
    if auto_complete and voucher_code:
        # KPRP Voucher - instant delivery
        subject = f"Your KPRP Voucher Code - Order #{purchase_id}"
        content = f"""
Dear {current_user.username},

Thank you for your purchase! Your KPRP voucher is ready.

Order ID: #{purchase_id}
Item: {item_name}
Status: Completed ✅

🎟️ YOUR VOUCHER CODE: {voucher_code}

This 16-character code can be used to redeem {item_name} in the KPRP server.

If you have any questions, feel free to contact our support team.

Best regards,
The {config['app_name']} Team
        """
        send_email(current_user.email, subject, content)
        
        # Send webhook for instant voucher
        send_webhook_log(
            "🎟️ KPRP Voucher Generated",
            f"**{current_user.username}** purchased a KPRP voucher (auto-completed)",
            0x00ff00,
            [
                {"name": "User", "value": current_user.username, "inline": True},
                {"name": "Item", "value": item_name, "inline": True},
                {"name": "Voucher Code", "value": voucher_code, "inline": False}
            ]
        )
        
        return jsonify({'success': True, 'order_id': purchase_id, 'voucher_code': voucher_code})
    else:
        # Regular order - needs admin approval
        subject = f"Order Confirmation #{purchase_id} - {config['app_name']}"
        content = f"""
Dear {current_user.username},

Thank you for your purchase! Your order has been received and is being processed.

Order ID: #{purchase_id}
Item: {item_name}
Coins Spent: {coins}
Status: Pending

Your order will be processed within 1-24 hours. You'll receive updates as your order progresses.

Best regards,
The {config['app_name']} Team
        """

        if proof_image_path:
            content += f"\n\nNote: Payment proof has been uploaded and will be reviewed by our admin team."

        send_email(current_user.email, subject, content)
        
        # Send webhook notification for new order
        webhook_fields = [
            {"name": "User", "value": current_user.username, "inline": True},
            {"name": "Item", "value": item_name, "inline": True},
            {"name": "Coins Spent", "value": str(coins), "inline": True},
            {"name": "Order ID", "value": f"#{purchase_id}", "inline": True}
        ]

        if additional_info:
            webhook_fields.append({"name": "Details", "value": additional_info, "inline": False})

        send_webhook_log(
            "🛒 New Order Placed",
            f"**{current_user.username}** placed a new order!",
            0x0099ff,
            webhook_fields
        )

        return jsonify({'success': True, 'order_id': purchase_id})

@app.route('/complete_order_with_code', methods=['POST'])
@login_required
def complete_order_with_code():
    if current_user.email not in access_config['admin_emails']:
        return jsonify({'error': 'Unauthorized'}), 401

    purchase_id = request.form['purchase_id']
    admin_code = request.form['admin_code']

    if not admin_code:
        return jsonify({'error': 'Admin code is required'}), 400

    # Get order details
    purchase_data = purchases_collection.aggregate([
        {"$match": {"_id": ObjectId(purchase_id)}},
        {
            "$lookup": {
                "from": "users",
                "localField": "user_id",
                "foreignField": "_id",
                "as": "user"
            }
        },
        {"$unwind": "$user"}
    ]).next()

    if not purchase_data:
        return jsonify({'error': 'Order not found'}), 404

    # Update order with admin code and set to success
    purchases_collection.update_one(
        {"_id": ObjectId(purchase_id)},
        {"$set": {"admin_code": admin_code, "status": "success"}}
    )

    # Send success email with code
    item_name = purchase_data['item_name']
    username = purchase_data['user']['username']
    email = purchase_data['user']['email']
    voucher_code = purchase_data.get('voucher_code', '')
    item_details = purchase_data.get('item_details', '')
    item_type = purchase_data.get('store_type', '')

    subject = f"Order #{purchase_id} Successfully Completed - {config['app_name']}"
    
    # Extract UID or KPRP Name from item_details using regex for robustness
    import re
    uid = ''
    kprp_name = ''
    
    uid_match = re.search(r'UID:\s*(.+?)(?:\n|$)', item_details, re.IGNORECASE)
    if uid_match:
        uid = uid_match.group(1).strip()
    
    kprp_match = re.search(r'KPRP Name:\s*(.+?)(?:\n|$)', item_details, re.IGNORECASE)
    if kprp_match:
        kprp_name = kprp_match.group(1).strip()
    
    # Determine category-specific message
    content_body = ""
    
    if 'pubg' in item_name.lower() or 'uc' in item_name.lower():
        # PUBG UC
        content_body = f"""Your PUBG UC has been credited to the following UID: {uid}

If you did not receive it, please contact us through Discord: {config['discord_link']}"""
    
    elif 'pes' in item_name.lower() or 'efootball' in item_name.lower():
        # PES/eFootball
        content_body = f"""Your eFootball coins have been credited to the following UID: {uid}

If you did not receive it, please contact us through Discord: {config['discord_link']}"""
    
    elif 'diamond' in item_name.lower() and 'fire' in item_name.lower():
        # Free Fire Diamonds
        content_body = f"""Your Free Fire diamonds have been credited to the following UID: {uid}

If you did not receive it, please contact us through Discord: {config['discord_link']}"""
    
    elif 'like' in item_name.lower():
        # Likes
        content_body = f"""You got {admin_code} likes for UID: {uid}

Thank you for using our service!"""
    
    elif 'amazon' in item_name.lower() or 'google' in item_name.lower():
        # Amazon or Google Play vouchers - use admin_code or fall back to voucher_code
        code_to_use = admin_code if admin_code else voucher_code
        content_body = f"""Your voucher code: {code_to_use}

Please use this code to redeem your {item_name}."""
    
    elif 'kprp' in item_name.lower() and 'voucher' not in item_name.lower():
        # KPRP items (cash, VIP, cars) - not vouchers
        content_body = f"""Your KPRP item request has been confirmed for in-game name: {kprp_name}

Please create a support ticket to complete the process.
Tutorial: {config['kprp_ticket_tutorial']}"""
    
    else:
        # Generic completion message
        content_body = f"""Your order has been successfully completed."""
        if admin_code:
            content_body += f"\n\nCode/Details: {admin_code}"
        elif voucher_code:
            content_body += f"\n\nVoucher Code: {voucher_code}"

    content = f"""
Dear {username},

Order Successfully Completed

Order ID: #{purchase_id}
Item: {item_name}
Status: Completed ✅

{content_body}

If you have any questions, please contact our support team.

Best regards,
The {config['app_name']} Team
    """

    send_email(email, subject, content)

    # Send webhook notification
    webhook_fields = [
        {"name": "Order ID", "value": f"#{purchase_id}", "inline": True},
        {"name": "User", "value": username, "inline": True},
        {"name": "Item", "value": item_name, "inline": True},
        {"name": "Status", "value": "Completed", "inline": True}
    ]

    if voucher_code:
        webhook_fields.append({"name": "Voucher Code", "value": voucher_code, "inline": True})
    if admin_code:
        webhook_fields.append({"name": "Redeem Code", "value": admin_code, "inline": True})

    send_webhook_log(
        "📦 Order Completed",
        f"Order #{purchase_id} has been completed with code",
        0x00ff00,
        webhook_fields
    )

    return jsonify({'success': True})

# Initialize database and start scheduler
if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)