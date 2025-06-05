from flask import *
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__, static_url_path='/static', static_folder='static', template_folder='templates')

app.config['SECRET_KEY'] = "123"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db' # SQLite database file will be users.db
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False) # Increased length for hash

    def __repr__(self):
        return f'<User {self.username}>'
class SpotDetails(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    spot_name = db.Column(db.String(100), nullable=False)
    spot_userid = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    spot_token = db.Column(db.String(400), nullable=False)
    spot_refresh_token = db.Column(db.String(400), nullable=False)
    spot_expiry = db.Column(db.DateTime, nullable=False)

    def __repr__(self):
        return f'<SpotDetails {self.spot_name}>'

@app.route("/")
def slash():
    return redirect(url_for('home'))

@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if 'user_id' in session:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not username or not password or not confirm_password:
            flash('All fields are required.', 'danger')
            return render_template('signup.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('signup.html')
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists.', 'danger')
            return render_template('signup.html')
        
        hashed_password = generate_password_hash(password)

        new_user = User(username=username, password_hash=hashed_password)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('User created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating user: {str(e)}', 'danger')
            return render_template('signup.html')
    return render_template('signup.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash('Username and password are required.', 'danger')
            return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route("/h")
def home():
    if 'user_id' not in session:
        flash('You need to log in first.', 'warning')
        return redirect(url_for('login'))
    
    username = session.get('username', 'Guest')
    return render_template('home.html', username=username)

@app.route("/logout")
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

def create_tables():
    with app.app_context():
        db.create_all()

if __name__ == "__main__":
    if not os.path.exists('users.db'):
        create_tables()
    app.run(debug=True)