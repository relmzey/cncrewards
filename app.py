
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
    dynamic_routes_collection.create_index("route_path", unique=True)
    user_timers_collection.create_index("user_id")
    user_cooldowns_collection.create_index("user_id", unique=True)
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
        
        # Check if user exists
        if users_collection.find_one({"$or": [{"username": username}, {"email": email}]}):
            flash('Username or email already exists!')
            return render_template('register.html', config=config)
        
        # Check if IP already has an account
        if ip_tracking_collection.find_one({"ip_address": user_ip}):
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
                "account_created_at": datetime.now()
            })
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
        
        user_data = users_collection.find_one({"username": username})
        
        if user_data and check_password_hash(user_data['password_hash'], password):
            if user_data['is_verified']:
                user = User(user_data['_id'], user_data['username'], user_data['email'], 
                           user_data['balance'], user_data['is_verified'])
                login_user(user)
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
    # Check if user is in cooldown period (3 hours)
    cooldown_data = user_cooldowns_collection.find_one({
        "user_id": ObjectId(current_user.id),
        "last_earn_time": {"$gt": datetime.now() - timedelta(hours=3)}
    })
    
    if cooldown_data:
        last_earn = cooldown_data['last_earn_time']
        next_allowed = last_earn + timedelta(hours=3)
        remaining_time = next_allowed - datetime.now()
        
        return render_template('earn_coins.html', 
                             timer_config=timer_config, 
                             cooldown_remaining=remaining_time,
                             links_config=links_config,
                             config=config)
    
    # Get current dynamic route
    current_route_data = dynamic_routes_collection.find_one({
        "expires_at": {"$gt": datetime.now()}
    })
    
    if not current_route_data:
        new_route = generate_route()
        expire_time = datetime.now() + timedelta(hours=timer_config['route_generation_hours'])
        dynamic_routes_collection.delete_many({})  # Clear old routes
        dynamic_routes_collection.insert_one({
            "route_path": new_route,
            "created_at": datetime.now(),
            "expires_at": expire_time
        })
        current_route = new_route
    else:
        current_route = current_route_data['route_path']
    
    # Get user timers
    active_timers_cursor = user_timers_collection.find({
        "user_id": ObjectId(current_user.id),
        "timer_end": {"$gt": datetime.now()}
    })
    active_timers = {timer['link_type']: timer['timer_end'] for timer in active_timers_cursor}
    
    return render_template('earn_coins.html', 
                         timer_config=timer_config, 
                         current_route=current_route,
                         active_timers=active_timers,
                         links_config=links_config,
                         config=config)

@app.route('/generate_link/<link_type>')
@login_required
def generate_link(link_type):
    if link_type not in timer_config['links']:
        return jsonify({'error': 'Invalid link type'}), 400
    
    # Check if user has active timer for this link
    active_timer = user_timers_collection.find_one({
        "user_id": ObjectId(current_user.id),
        "link_type": link_type,
        "timer_end": {"$gt": datetime.now()}
    })
    
    if active_timer:
        return jsonify({'error': 'Timer still active for this link'}), 400
    
    # Get current route
    route_data = dynamic_routes_collection.find_one({
        "expires_at": {"$gt": datetime.now()}
    })
    
    if not route_data:
        return jsonify({'error': 'No active route available'}), 400
    
    current_route = route_data['route_path']
    link_config = timer_config['links'][link_type]
    
    # Make API call to generate shortened link
    try:
        api_url = link_config['api_url'].format(
            destination=f"https://{request.host}/{current_route}",
            alias=f"kprp_{link_type}_{current_user.id}"
        )
        response = requests.get(api_url)
        response_data = response.json()
        
        if response_data.get('status') == 'success':
            # Set timer for user
            timer_end = datetime.now() + timedelta(minutes=link_config['timer_minutes'])
            user_timers_collection.update_one(
                {"user_id": ObjectId(current_user.id), "link_type": link_type},
                {"$set": {"timer_end": timer_end}},
                upsert=True
            )
            
            return jsonify({
                'success': True,
                'shortened_url': response_data.get('shortenedUrl'),
                'timer_minutes': link_config['timer_minutes']
            })
        else:
            return jsonify({'error': 'Failed to generate link'}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/<route_path>')
def claim_coins(route_path):
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    # Check if route is valid and not expired
    route_data = dynamic_routes_collection.find_one({
        "route_path": route_path,
        "expires_at": {"$gt": datetime.now()}
    })
    
    if not route_data:
        return render_template('access_denied.html', message="Invalid or expired route")
    
    # Check if user has any active timers (bypass detection)
    active_timer = user_timers_collection.find_one({
        "user_id": ObjectId(current_user.id),
        "timer_end": {"$gt": datetime.now()}
    })
    
    if not active_timer:
        return render_template('access_denied.html', message="Access denied - bypass detected")
    
    # Award coin and remove timer
    users_collection.update_one(
        {"_id": ObjectId(current_user.id)},
        {"$inc": {"balance": 1}}
    )
    user_timers_collection.delete_one({
        "user_id": ObjectId(current_user.id),
        "link_type": active_timer['link_type']
    })
    
    # Set 3-hour cooldown
    user_cooldowns_collection.update_one(
        {"user_id": ObjectId(current_user.id)},
        {"$set": {"last_earn_time": datetime.now()}},
        upsert=True
    )
    
    # Send webhook notification for link completion
    send_webhook_log(
        "🎯 Link Completed",
        f"User **{current_user.username}** completed a link and earned 1 coin!",
        0x00ff00,
        [
            {"name": "User", "value": current_user.username, "inline": True},
            {"name": "Link Type", "value": active_timer['link_type'], "inline": True},
            {"name": "Coins Earned", "value": "1", "inline": True}
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
            content = f"""
Dear {username},

🎉 Congratulations! Your order has been successfully completed.

Order ID: #{purchase_id}
Item: {item_name}
Status: Completed ✅
"""
            
            # Add codes to email based on item type
            if voucher_code:
                content += f"\nVoucher Code: {voucher_code}"
            if admin_code:
                content += f"\nRedeem Code: {admin_code}"
            
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
    
    # Generate voucher code for KPRP vouchers
    voucher_code = ''
    if 'kprp_voucher' in item_type:
        voucher_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        additional_info += f" | Voucher Code: {voucher_code}"
    
    # Deduct coins and create purchase record
    users_collection.update_one(
        {"_id": ObjectId(current_user.id)},
        {"$inc": {"balance": -coins}}
    )
    
    purchase_doc = {
        "user_id": ObjectId(current_user.id),
        "store_type": item_type.split('_')[0],
        "item_name": item_name,
        "coins_spent": coins,
        "item_details": additional_info,
        "status": "pending",
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
    
    # Send simple order confirmation email
    subject = f"Order Confirmation #{purchase_id} - {config['app_name']}"
    content = f"""
Dear {current_user.username},

Thank you for your purchase! Your order has been received.

Order ID: #{purchase_id}
Item: {item_name}
Coins Spent: {coins}
Status: Pending

Your order will be processed within 1-24 hours. You'll receive updates as your order progresses.

Best regards,
The {config['app_name']} Team
    """
    
    # For UPI vouchers, include proof image info in admin notification
    if proof_image_path:
        content += f"\n\nNote: Payment proof has been uploaded and will be reviewed by our admin team."
        
    send_email(current_user.email, subject, content)
    
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
    
    subject = f"Order #{purchase_id} Completed - {config['app_name']}"
    content = f"""
Dear {username},

🎉 Congratulations! Your order has been successfully completed.

Order ID: #{purchase_id}
Item: {item_name}
Status: Completed ✅
"""
    
    # Add codes to email based on item type
    if voucher_code:
        content += f"\nVoucher Code: {voucher_code}"
    if admin_code:
        content += f"\nRedeem Code: {admin_code}"
    
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
    app.run(host='0.0.0.0', port=5000, debug=True)
