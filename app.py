from flask import Flask, render_template, session, request
from flask_sqlalchemy import SQLAlchemy
from hashlib import sha256

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://human:password@localhost/jadopado'
db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = "users"
    email = db.Column(db.String(130), primary_key=True)
    name = db.Column(db.String(100))
    password = db.Column(db.LargeBinary())

    def __init__(self, email, name, password):
        self.email = email;
        self.name = name;
        self.password = password;

def hashpw(password):
    return sha256(password.encode('ascii')).hexdigest()

# Index
@app.route('/')
def hello_world():
    return 'How did you end up here?'

# Sign up page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        password = request.form['password']
        passwordHash = hashpw(password)

        newUser = User(email, name, passwordHash)

        # Only add users with unique email
        if not User.query.filter_by(email=email).count():
            db.session.add(newUser)
            db.session.commit()
            return "Signup successful".format(email, password)
        else:
            return "Email already exists"

    return render_template('signup.html')

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        passwordHash = hashpw(password)
        if passwordHash == user.password:
            return "Login successful"
        else:
            return "Wrong email/password combination"
    return render_template('login.html')