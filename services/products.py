import requests
from flask import Flask, jsonify, request, make_response
import jwt
from functools import wraps
import json
import os
from jwt.exceptions import DecodeError


app = Flask(__name__)

# secret key for JWT signing
app.config['SECRET_KEY'] = os.urandom(24)

# load user data from users.json
with open('users.json', 'r') as f:
    users = json.load(f)

# base URL for the dummy JSON API
BASE_URL = "https://dummyjson.com"

# decorator function for verifying JWT

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')

        if not token:
            return jsonify({'error': 'Authorization token is missing'}), 401

        try:
            # decode JWT and extract user ID
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user_id = data['user_id']

        except DecodeError:
            return jsonify({'error': 'Authorization token is invalid'}), 401

        return f(current_user_id, *args, **kwargs)

    return decorated


@app.route("/")
def home():
    return "Hello, this is a Flask Microservice"


# Define the API endpoint for user authentication
@app.route('/auth', methods=['POST'])
def authenticate_user():
    if request.headers['Content-Type'] != 'application/json':
        return jsonify({'error': 'Unsupported Media Type'}), 415

    # extract username and password from request body
    username = request.json.get('username')
    password = request.json.get('password')

    # check if username and password are valid
    for user in users:
        if user['username'] == username and user['password'] == password:
            # generate JWT 
            token = jwt.encode({'user_id': user['id']}, app.config['SECRET_KEY'], algorithm="HS256")

            # set JWT token in response cookies
            response = make_response(jsonify({'message': 'Authentication successful'}))
            response.set_cookie('token', token)
            return response, 200

    return jsonify({'error': 'Invalid username or password'}), 401

#API endpoint for getting all products
@app.route('/products', methods=['GET'])
@token_required
def get_products(current_user_id):
    # Add the JWT token to the headers of the GET request
    headers = {'Authorization': f'Bearer {request.cookies.get("token")}'}    

    # Make a GET request to the products endpoint and retrieve the response
    response = requests.get(f"{BASE_URL}/products", headers=headers)

    # If the response status code is not 200 (OK), return the error message from the response
    if response.status_code != 200:
        return jsonify({'error': response.json()['message']}), response.status_code

    # Parse the JSON data from the response and extract the relevant product data
    products = []
    for product in response.json()['products']:
        product_data = {
            'id': product['id'],
            'title': product['title'],
            'brand': product['brand'],
            'price': product['price'],
            'description': product['description']
        }
        products.append(product_data)

    # Return the extracted product data as a JSON response
    return jsonify({'data': products}), 200 if products else 204
