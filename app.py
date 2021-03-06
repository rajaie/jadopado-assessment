from flask import Flask, render_template, session, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_heroku import Heroku
from hashlib import sha256
import requests
import re
from authy.api import AuthyApiClient

AUTHY_API_KEY = "MVZQaKGv2n8k94T377n6bamoVpn3TGEB"
authy_api = AuthyApiClient(AUTHY_API_KEY)

app = Flask(__name__)
app.secret_key = 'Ajoj(*039483jlkjer093#$J#4j343'

#app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://human:password@localhost/jadopado'
heroku = Heroku(app)
db = SQLAlchemy(app)

########## MODELS ###############

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    name = db.Column(db.String(100))
    password = db.Column(db.LargeBinary())
    country_code = db.Column(db.String(100))
    phone = db.Column(db.String(100))
    authy_id = db.Column(db.Integer)

    def __init__(self, email, name, password, country_code, phone, authy_id):
        self.email = email
        self.name = name
        self.password = password
        self.country_code = country_code
        self.phone = phone
        self.authy_id = authy_id

########## UTILS ###############

def hashpw(password):
    return sha256(password.encode('ascii')).hexdigest()

def send_onetouch_request(authy_id):
    url = "http://api.authy.com/onetouch/json/users/{}/approval_requests".format(authy_id)
    data = {'message': 'Login requested for JADOPADO assessment site'}
    headers = {'X-Authy-API-Key': AUTHY_API_KEY}

    r = requests.post(url, headers=headers, data=data)
    # OneTouch request created successfully
    if r.status_code == 200:
        return r.json()['approval_request']['uuid']

def verify_onetouch_request(uuid):
    url = "http://api.authy.com/onetouch/json/approval_requests/{}".format(uuid)
    headers = {'X-Authy-API-Key': AUTHY_API_KEY}

    r = requests.get(url, headers=headers)
    # Retrieved OneTouch authentication status
    if r.status_code == 200:
        return r.json()['approval_request']['status']

def validate_name(name):
    if re.match(r"^[a-zA-Z][a-zA-Z\s]{1,100}$", name) is not None:
        return True
    else:
        return False

def validate_email(email):
    if re.match(r"[^@]+@[^@]+\.[^@]+", email) is not None:
        return True
    else:
        return False

def validate_phone(phone):
    if re.match(r"^[0-9]{6,30}$", phone) is not None:
        return True
    else:
        return False

def validate_country_code(country_code):
    if re.match(r"^[0-9]{1,3}$", country_code) is not None:
        return True
    else:
        return False

def validate_token(token):
    if re.match(r"^[0-9]{7}$", token) is not None:
        return True
    else:
        return False

# Returns False if no errors were found, otherwise returns an error message.
def validate_signup_fields(email, name, password, country_code, phone):
    if email == "" or name == "" or password == "" or country_code == "" \
            or phone == "":
        return "Please go back and fill out all fields."
    if not validate_email(email):
        return "Bad email format, go back and try again"
    if not validate_name(name):
        return "Bad name format, go back and try again"
    if not validate_country_code(country_code):
        return "Bad country code format, go back and try again"
    if not validate_phone(phone):
        return "Bad phone format, go back and try again"
    return False

def validate_login_fields(email, password):
    if email == "" or password == "":
        return "Please go back and fill out all fields."
    if not validate_email(email):
        return "Bad email format, go back and try again"

########## VIEWS ###############

# Index
@app.route('/')
def index():
    return render_template('index.html')

# Signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        password = request.form['password']
        password_hash = hashpw(password)
        country_code = request.form['country_code']
        phone = request.form['phone']

        # All fields must be filled in and valid. Return error message otherwise.
        not_valid = validate_signup_fields(email, name, password, country_code, phone)
        if not_valid:
            return not_valid

        # Only add user to DB if Authy user creation succeeds
        authy_user = authy_api.users.create(email, phone, country_code)
        if not authy_user.ok():
            return "Authy user creation failed, go back and try again"
        new_user = User(email, name, password_hash, country_code, phone, authy_user.id)

        # Email address must be unique
        if not User.query.filter_by(email=email).count():
            db.session.add(new_user)
            db.session.commit()
            return "Signup successful, want to <a href='" + url_for('login') + "'>login</a>?"
        else:
            return "Email already exists, go back and try again"

    return render_template('signup.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # All fields must be filled in and valid. Return error message otherwise.
        not_valid = validate_login_fields(email, password)
        if not_valid:
            return not_valid

        user = User.query.filter_by(email=email).first()
        if user is None:
            message = "Email doesn't exist, <a href='"+\
                      url_for('login') + "'>try again</a>"
            return message

        password_hash = hashpw(password)
        if password_hash == user.password:
            session['authy_id'] = user.authy_id
            return redirect(url_for('totp'))
        else:
            message = "Incorrect password, <a href='"+\
                      url_for('login') + "'>try again</a>"
            return message
    return render_template('login.html')

# Logout
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('authy_id', None)
    session.pop('onetouch_uuid', None)
    return redirect(url_for('index'))

# Authy TOTP
@app.route('/totp', methods=['GET', 'POST'])
def totp():
    authy_id = session.get('authy_id', None)

    if request.method == 'POST':
        token = request.form['token']

        # Token not formatted properly
        if not validate_token(token):
            message = "Bad token format, <a href='" + \
                       url_for('totp') + "'>try again</a>"
            return message

        # Send token verification request to Authy
        verification = authy_api.tokens.verify(authy_id, token)
        if verification.ok():
            session.pop('onetouch_uuid', None)
            return redirect(url_for('onetouch'))
        else:
            message = "Incorrect token, <a href='" + \
                       url_for('totp') + "'>try again</a>"
            return message

    return render_template('totp.html')

# Authy OneTouch
@app.route('/onetouch')
def onetouch():
    authy_id = session.get('authy_id', None)
    onetouch_uuid = session.get('onetouch_uuid', None)

    if onetouch_uuid is None:
        uuid = send_onetouch_request(authy_id)
        session['onetouch_uuid'] = uuid
    else:
        response = verify_onetouch_request(session['onetouch_uuid'])
        if response == "approved":
            session['logged_in'] = True
        else:
            return "You have not approved the OneTouch request yet, please approve " \
                   "it and reload this page.<br /><br /> If you denied the request, " \
                   "please restart the <a href='" + url_for('login') + "'>login</a> process."

    return render_template('onetouch.html')