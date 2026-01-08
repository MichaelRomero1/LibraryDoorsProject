import dotenv
import os
import uuid
import mysql.connector
import pathlib
import requests
import google.auth.transport.requests
import pip._vendor.cachecontrol as cachecontrol
import time
import redis
from authlib.integrations.flask_client import OAuth
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from google.oauth2 import id_token
from functools import wraps
from flask import Flask, abort, jsonify, redirect, request, session, render_template, url_for
from flask_session import Session
import boto3
from botocore.exceptions import NoCredentialsError

dotenv.load_dotenv()
if not os.getenv('FLASK_SECRET_KEY'):
    print('Please set FLASK_SECRET_KEY in .env file')

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')

oauth = OAuth(app)
oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid profile email'},
    jwks_uri = "https://www.googleapis.com/oauth2/v3/certs",
    clock_skew_in_seconds=10
    
)

# Google OAuth configuration
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')

def login_is_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if 'email' not in session:  # Check if the user is logged in
            return abort(401)  # If not, return 401 Unauthorized
        else:
            return function(*args, **kwargs)
    return wrapper

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    google = oauth.create_client('google') # Create/get the google client above
    redirect_uri = url_for('authorize', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@app.route('/logout') 
def logout():
    for key in list(session.keys()): # Clear all keys from the session data
        session.pop(key)
    return redirect('/')