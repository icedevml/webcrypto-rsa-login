import base64
import os

from cryptography.exceptions import InvalidSignature
from flask import Flask
from flask import render_template
from flask import request
from uuid import uuid4

app = Flask(__name__)
app.debug = True

users = {}
challenges = {}


def generate_challenge():
    challenge_id = str(uuid4())
    challenge = base64.b64encode(os.urandom(128)).decode('ascii')

    challenges[challenge_id] = challenge
    return challenge_id, challenge


def pop_challenge(challenge_id):
    return challenges.pop(challenge_id)


def load_pem_public_key(public_key_pem):
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.hazmat.backends import default_backend

    return load_pem_public_key(request.form.get('public_key').encode('ascii'), backend=default_backend())


def verify_signature(public_key, challenge_str, signature_str):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    message = base64.b64decode(challenge_str)
    signature = bytes(bytearray.fromhex(signature_str))

    # print(padding.calculate_max_pss_salt_length(public_key, hashes.SHA256()))

    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


@app.route('/register')
def register():
    challenge_id, challenge = generate_challenge()

    return render_template('register.html', challenge_id=challenge_id, challenge=challenge)


@app.route('/register/submit', methods=['POST'])
def register_submit():
    public_key = load_pem_public_key(request.form.get('public_key'))
    try:
        challenge = pop_challenge(request.form.get('challenge_id'))
    except KeyError:
        return 'tried to use challenge for the second time'

    verify_signature(public_key, challenge, request.form.get('signature'))

    username = request.form.get('username')
    users[username] = {"public_key": public_key}

    return 'OK'


@app.route('/login/submit', methods=['POST'])
def login_submit():
    user = users.get(request.form.get('username'))

    try:
        challenge = pop_challenge(request.form.get('challenge_id'))
    except KeyError:
        return 'tried to use challenge for the second time'

    if not user:
        return 'no such user'

    try:
        verify_signature(user["public_key"], challenge, request.form.get('signature'))
    except InvalidSignature:
        return 'you are not him'

    return 'hello user ' + request.form.get('username')


@app.route('/login')
def login():
    challenge_id, challenge = generate_challenge()

    return render_template('login.html', challenge_id=challenge_id, challenge=challenge)


@app.route('/')
def main():
    return render_template('main.html')


if __name__ == '__main__':
    app.run()
