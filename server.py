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

