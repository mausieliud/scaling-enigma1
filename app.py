from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_pymongo import PyMongo
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

app = Flask(__name__)
app.secret_key = "your_secret_key"

# MongoDB Configuration
app.config["MONGO_URI"] = "mongodb://localhost:27017/user_database"
mongo = PyMongo(app)

# Flask-Mail Configuration (use SMTP settings of your email provider)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your-email-password'
app.config['MAIL_DEFAULT_SENDER'] = 'your-email@gmail.com'

mail = Mail(app)

# Home Route
@app.route('/')
def home():
    return render_template('home.html')

# Signup Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])

        if mongo.db.users.find_one({'username': username}):
            flash("Username already exists!", "danger")
            return redirect(url_for('signup'))

        mongo.db.users.insert_one({'username': username, 'email': email, 'password': password})
        flash("Signup successful! Please login.", "success")
        return redirect(url_for('login'))

    return render_template('signup.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = mongo.db.users.find_one({'username': username})
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password!", "danger")

    return render_template('login.html')

# Forgot Password Route
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = mongo.db.users.find_one({'email': email})
        
        if user:
            token = secrets.token_urlsafe(16)
            mongo.db.reset_tokens.insert_one({'email': email, 'token': token})

            reset_link = url_for('reset_password', token=token, _external=True)
            msg = Message("Password Reset Request", recipients=[email])
            msg.body = f"Click the link to reset your password: {reset_link}"
            mail.send(msg)

            flash("Password reset link sent to your email.", "success")
        else:
            flash("No account found with this email.", "danger")

    return render_template('forgot_password.html')

# Password Reset Route
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    token_data = mongo.db.reset_tokens.find_one({'token': token})

    if not token_data:
        flash("Invalid or expired token.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = generate_password_hash(request.form['password'])
        mongo.db.users.update_one({'email': token_data['email']}, {'$set': {'password': new_password}})
        mongo.db.reset_tokens.delete_one({'token': token})
        flash("Password reset successful! Please login.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html')

# Dashboard (Add Contact Details)
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        phone = request.form['phone']
        email = request.form['email']
        address = request.form['address']
        reg_number = request.form['reg_number']

        mongo.db.contacts.insert_one({
            'username': session['username'],
            'phone': phone,
            'email': email,
            'address': address,
            'reg_number': reg_number
        })
        flash("Contact details saved!", "success")

    return render_template('dashboard.html')

# Search Contacts by Registration Number
@app.route('/search', methods=['GET', 'POST'])
def search():
    contacts = None
    if request.method == 'POST':
        reg_number = request.form['reg_number']
        contacts = mongo.db.contacts.find_one({'reg_number': reg_number})

    return render_template('search.html', contacts=contacts)

# Logout Route
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)

