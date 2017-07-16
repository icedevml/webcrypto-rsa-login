import base64
import os

from cryptography.exceptions import InvalidSignature
from flask import Flask
from flask import flash
from flask import redirect
from flask import render_template
from flask import request
from uuid import uuid4

from flask import url_for

app = Flask(__name__)
app.debug = True
app.secret_key = 'foobar123'

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
        flash('tried to use inexistent challenge nonce/the same nonce for the second time', 'error')
        return redirect(url_for('main'))

    try:
        verify_signature(public_key, challenge, request.form.get('signature'))
    except InvalidSignature:
        flash('signature verification failed', 'error')
        return redirect(url_for('main'))

    username = request.form.get('username')

    if username in users:
        flash('such user already exists', 'error')
        return redirect(url_for('main'))

    users[username] = {"public_key": public_key}

    flash('succesfully registered as {}'.format(username), 'success')
    return redirect(url_for('main'))


@app.route('/login/submit', methods=['POST'])
def login_submit():
    username = request.form.get('username')
    user = users.get(username)

    try:
        challenge = pop_challenge(request.form.get('challenge_id'))
    except KeyError:
        flash('tried to use inexistent challenge nonce/the same nonce for the second time', 'error')
        return redirect(url_for('main'))

    if not user:
        flash('no such user {}'.format(username), 'error')
        return redirect(url_for('main'))

    try:
        verify_signature(user["public_key"], challenge, request.form.get('signature'))
    except InvalidSignature:
        flash('you are not {}'.format(username), 'error')
        return redirect(url_for('main'))

    flash('hello user {}'.format(username), 'success')
    return redirect(url_for('main'))


@app.route('/login')
def login():
    challenge_id, challenge = generate_challenge()

    return render_template('login.html', challenge_id=challenge_id, challenge=challenge)


@app.route('/')
def main():
    return render_template('main.html')


if __name__ == '__main__':
    app.run()
