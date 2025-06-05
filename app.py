from flask import *
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import requests
import base64
from urllib.parse import urlencode

app = Flask(__name__, static_url_path='/static', static_folder='static', template_folder='templates')

app.config['SECRET_KEY'] = "123"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db' # SQLite database file will be users.db
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
CLIENT_ID = "8e510e1809544a978d4d6544317096a8"
CLIENT_SECRET = "54bd47d0133f48189fe9c1b550afdfbf"
REDIRECT_URI = "https://45-33-115-242.ip.linodeusercontent.com/callback"

AUTH_URL = "https://accounts.spotify.com/authorize"
TOKEN_URL = "https://accounts.spotify.com/api/token"
API_BASE_URL = "https://api.spotify.com/v1/"

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
            spot_details = SpotDetails.query.filter_by(spot_userid=user.id).first()
            if not spot_details:
                flash('You need to authenticate with Spotify first.', 'warning')
                return redirect(url_for('spotify'))
            else:
                session['spot_token'] = spot_details.spot_token
                session['spot_refresh_token'] = spot_details.spot_refresh_token
                session['spot_expiry'] = spot_details.spot_expiry.isoformat()
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
    if 'spot_token' not in session or 'spot_expiry' not in session:
        flash('You need to authenticate with Spotify first.', 'warning')
        return redirect(url_for('spotify'))
    
    headers = {
        'Authorization': f"Bearer {session['access_token']}"
    }
    response = requests.get(f"{API_BASE_URL}me", headers=headers)
    if response.status_code != 200:
        flash('Failed to fetch user data from Spotify.', 'danger')
        return redirect(url_for('spotify'))
    user_data = response.json()
    display_name = user_data.get('display_name', 'Unknown User')
    if not display_name:
        display_name = username
    return render_template('home.html', username=username, display_name=display_name)

@app.route("/spotify")
def spotify():
    if 'user_id' not in session:
        flash('You need to log in first.', 'warning')
        return redirect(url_for('login'))
    
    return render_template('spotify.html')
@app.route("/spcnt")
def spotify_auth():
    if 'user_id' not in session:
        flash('You need to log in first.', 'warning')
        return redirect(url_for('login'))
    scope = "user-read-private user-read-email playlist-read-private playlist-modify-public playlist-modify-private user-library-read user-library-modify user-follow-modify user-follow-read user-read-playback-position user-top-read user-read-recently-played user-read-playback-state user-modify-playback-state app-remote-control streaming user-read-currently-playing"
    params = {
        'client_id': CLIENT_ID,
        'response_type': 'code',
        'scope': scope,
        'redirect_uri': REDIRECT_URI,
    }
    auth_url = f"{AUTH_URL}?{urlencode(params)}"
    return redirect(auth_url)

@app.route("/callback")
def callback():
    if 'error' in request.args:
        return f"Error: {request.args['error']}"

    if 'code' in request.args:
        req_body = {
            'code': request.args['code'],
            'grant_type': 'authorization_code',
            'redirect_uri': REDIRECT_URI,
        }
        auth_header = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
        headers = {'Authorization': f'Basic {auth_header}'}

        response = requests.post(TOKEN_URL, data=req_body, headers=headers)
        token_info = response.json()

        if 'access_token' in token_info:
            access_token = token_info['access_token']
            refresh_token = token_info.get('refresh_token')
            expires_in = token_info.get('expires_in')

            user_id = session.get('user_id')
            if user_id:
                spot_details = SpotDetails.query.filter_by(spot_userid=user_id).first()
                if not spot_details:
                    spot_details = SpotDetails(spot_name='Spotify', spot_userid=user_id)
                spot_details.spot_token = access_token
                spot_details.spot_refresh_token = refresh_token
                spot_details.spot_expiry = datetime.utcnow() + timedelta(seconds=expires_in)

                db.session.add(spot_details)
                db.session.commit()

                flash('Spotify authentication successful!', 'success')
                return redirect(url_for('home'))
            else:
                flash('User not found.', 'danger')
                return redirect(url_for('login'))
        else:
            return "Failed to retrieve access token."

    return "Something went wrong during callback."
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
    app.run(debug=True)
    if not os.path.exists('users.db'):
        create_tables()
        