import os
from flask import Flask, request, redirect, session, url_for
import requests
import base64
from urllib.parse import urlencode

app = Flask(__name__)
app.secret_key = os.urandom(24) # Needed for session management

# Replace with your Spotify app credentials
CLIENT_ID = "YOUR_SPOTIFY_CLIENT_ID"
CLIENT_SECRET = "YOUR_SPOTIFY_CLIENT_SECRET"
REDIRECT_URI = "http://127.0.0.1:5000/callback" # Must match your Spotify app settings

# Spotify API endpoints
AUTH_URL = "https://accounts.spotify.com/authorize"
TOKEN_URL = "https://accounts.spotify.com/api/token"
API_BASE_URL = "https://api.spotify.com/v1/"

@app.route('/')
def index():
    return """
        <h1>Spotify OAuth with Flask</h1>
        <a href="/login">Login with Spotify</a>
    """

@app.route('/login')
def login():
    scope = "user-read-private user-read-email" # Define the permissions your app needs
    params = {
        'client_id': CLIENT_ID,
        'response_type': 'code',
        'scope': scope,
        'redirect_uri': REDIRECT_URI,
        'show_dialog': True # Optional: Forces the auth dialog to show every time
    }
    auth_url = f"{AUTH_URL}?{urlencode(params)}"
    return redirect(auth_url)

@app.route('/callback')
def callback():
    if 'error' in request.args:
        return f"Error: {request.args['error']}"

    if 'code' in request.args:
        req_body = {
            'code': request.args['code'],
            'grant_type': 'authorization_code',
            'redirect_uri': REDIRECT_URI,
        }
        # Encode Client ID and Client Secret for Basic Auth
        auth_header = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
        headers = {'Authorization': f'Basic {auth_header}'}

        response = requests.post(TOKEN_URL, data=req_body, headers=headers)
        token_info = response.json()

        if 'access_token' in token_info:
            session['access_token'] = token_info['access_token']
            session['refresh_token'] = token_info.get('refresh_token') # Good practice to store this
            session['expires_at'] = token_info.get('expires_in')
            return redirect(url_for('profile'))
        else:
            return "Failed to retrieve access token."

    return "Something went wrong during callback."

@app.route('/profile')
def profile():
    if 'access_token' not in session:
        return redirect(url_for('login'))

    headers = {
        'Authorization': f"Bearer {session['access_token']}"
    }
    response = requests.get(API_BASE_URL + 'me', headers=headers)

    if response.status_code == 200:
        user_data = response.json()
        return f"""
            <h1>User Profile</h1>
            <p><strong>Display Name:</strong> {user_data.get('display_name')}</p>
            <p><strong>Email:</strong> {user_data.get('email')}</p>
            <p><strong>Spotify ID:</strong> {user_data.get('id')}</p>
            <img src="{user_data.get('images')[0]['url'] if user_data.get('images') else ''}" width="100">
            <br><a href="/">Home</a>
        """
    elif response.status_code == 401: # Token might have expired
        # You would typically implement token refresh here
        return "Access token expired. Please login again. (Refresh logic not implemented in this example)"
    else:
        return f"Error fetching profile: {response.status_code} - {response.text}"

if __name__ == '__main__':
    app.run(debug=True)