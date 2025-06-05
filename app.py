from flask import *
from werkzeug.security import generate_password_hash, check_password_hash
import os
import requests
import base64
import json
from datetime import datetime, timedelta
from urllib.parse import urlencode

app = Flask(__name__, static_url_path='/static', static_folder='static', template_folder='templates')
app.config['SECRET_KEY'] = "123"

CLIENT_ID = "8e510e1809544a978d4d6544317096a8"
CLIENT_SECRET = "54bd47d0133f48189fe9c1b550afdfbf"
REDIRECT_URI = "https://45-33-115-242.ip.linodeusercontent.com/callback"

AUTH_URL = "https://accounts.spotify.com/authorize"
TOKEN_URL = "https://accounts.spotify.com/api/token"
API_BASE_URL = "https://api.spotify.com/v1/"

USERS_FILE = 'users.json'
SPOT_FILE = 'spotdetails.json'

def load_json(filename):
    if not os.path.exists(filename):
        return {}
    with open(filename, 'r') as f:
        return json.load(f)

def save_json(filename, data):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2, default=str)

def get_user(username):
    users = load_json(USERS_FILE)
    return users.get(username)

def add_user(username, password_hash):
    users = load_json(USERS_FILE)
    if username in users:
        return False
    users[username] = {
        'password_hash': password_hash
    }
    save_json(USERS_FILE, users)
    return True

def get_spotdetails(username):
    spots = load_json(SPOT_FILE)
    return spots.get(username)

def set_spotdetails(username, token, refresh_token, expiry):
    spots = load_json(SPOT_FILE)
    spots[username] = {
        'spot_token': token,
        'spot_refresh_token': refresh_token,
        'spot_expiry': expiry.isoformat()
    }
    save_json(SPOT_FILE, spots)

@app.route("/")
def slash():
    return redirect(url_for('home'))

@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if 'username' in session:
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
        if get_user(username):
            flash('Username already exists.', 'danger')
            return render_template('signup.html')
        hashed_password = generate_password_hash(password)
        if add_user(username, hashed_password):
            flash('User created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Error creating user.', 'danger')
    return render_template('signup.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if not username or not password:
            flash('Username and password are required.', 'danger')
            return render_template('login.html')
        user = get_user(username)
        if user and check_password_hash(user['password_hash'], password):
            session['username'] = username
            flash('Login successful!', 'success')
            spot_details = get_spotdetails(username)
            if not spot_details:
                flash('You need to authenticate with Spotify first.', 'warning')
                return redirect(url_for('spotify'))
            else:
                session['spot_token'] = spot_details['spot_token']
                session['spot_refresh_token'] = spot_details['spot_refresh_token']
                session['spot_expiry'] = spot_details['spot_expiry']
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route("/h")
def home():
    if 'username' not in session:
        flash('You need to log in first.', 'warning')
        return redirect(url_for('login'))
    username = session.get('username', 'Guest')
    if 'spot_token' not in session or 'spot_expiry' not in session:
        flash('You need to authenticate with Spotify first.', 'warning')
        return redirect(url_for('spotify'))
    headers = {
        'Authorization': f"Bearer {session['spot_token']}"
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
    if 'username' not in session:
        flash('You need to log in first.', 'warning')
        return redirect(url_for('login'))
    return render_template('spotify.html')

@app.route("/spcnt", methods=['GET', 'POST'])
def spotify_auth():
    if 'username' not in session:
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
            username = session.get('username')
            if username:
                expiry = datetime.utcnow() + timedelta(seconds=expires_in)
                set_spotdetails(username, access_token, refresh_token, expiry)
                session['spot_token'] = access_token
                session['spot_refresh_token'] = refresh_token
                session['spot_expiry'] = expiry.isoformat()
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
    session.pop('username', None)
    session.pop('spot_token', None)
    session.pop('spot_refresh_token', None)
    session.pop('spot_expiry', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)
