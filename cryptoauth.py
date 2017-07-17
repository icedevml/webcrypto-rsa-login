import base64
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from flask import Flask
from flask import flash
from flask import redirect
from flask import render_template
from flask import request

from flask import session
from flask import url_for
from redis import Redis

from redis_session import RedisSessionInterface

redis = Redis()

app = Flask(__name__)
app.session_interface = RedisSessionInterface(redis)
app.debug = True

users = {}


class MalformedPublicKey(RuntimeError):
    pass


def generate_challenge():
    return base64.b64encode(os.urandom(128)).decode('ascii')


def load_pem_public_key(public_key_pem):
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.hazmat.backends import default_backend

    public_key = load_pem_public_key(public_key_pem, backend=default_backend())

    if not isinstance(public_key, RSAPublicKey):
        raise MalformedPublicKey('Expected RSA public key')

    if public_key.key_size != 2048:
        raise MalformedPublicKey('Expected 2048 bit modulus RSA public key')

    app.logger.info('Loaded key: {}'.format(public_key.public_numbers()))

    return public_key


def verify_signature(public_key, challenge_str, signature_str):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    message = base64.b64decode(challenge_str)
    signature = bytes(bytearray.fromhex(signature_str))

    public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())


@app.route('/register')
def register():
    challenge = generate_challenge()
    session['challenge_register'] = challenge

    return render_template('register.html', challenge=challenge)


@app.route('/register/submit', methods=['POST'])
def register_submit():
    public_key_pem = request.form.get('public_key')
    public_key = load_pem_public_key(public_key_pem.encode('ascii'))

    try:
        challenge = session.pop('challenge_register')
    except KeyError:
        flash('no challenge was stored in session', 'danger')
        return redirect(url_for('main'))

    try:
        verify_signature(public_key, challenge, request.form.get('signature'))
    except InvalidSignature as e:
        flash('signature verification failed', 'danger')
        return redirect(url_for('main'))

    username = request.form.get('username')

    if redis.get('user:{}:public_key'.format(username)):
        flash('such user already exists', 'danger')
        return redirect(url_for('main'))

    redis.set('user:{}:public_key'.format(username), public_key_pem)

    flash('succesfully registered as {}'.format(username), 'success')
    return redirect(url_for('main'))


@app.route('/login/submit', methods=['POST'])
def login_submit():
    username = request.form.get('username')
    user_public_key_pem = redis.get('user:{}:public_key'.format(username))

    try:
        challenge = session.pop('challenge_login')
    except KeyError:
        flash('no challenge was stored in session', 'danger')
        return redirect(url_for('main'))

    if not user_public_key_pem:
        flash('no such user {}'.format(username), 'danger')
        return redirect(url_for('main'))

    user_public_key = load_pem_public_key(user_public_key_pem)

    try:
        verify_signature(user_public_key, challenge, request.form.get('signature'))
    except InvalidSignature:
        flash('you are not {}'.format(username), 'danger')
        return redirect(url_for('main'))

    flash('hello user {}'.format(username), 'success')
    return redirect(url_for('main'))


@app.route('/login')
def login():
    challenge = generate_challenge()
    session['challenge_login'] = challenge

    return render_template('login.html', challenge=challenge)


@app.route('/')
def main():
    return render_template('main.html')


if __name__ == '__main__':
    app.run()
