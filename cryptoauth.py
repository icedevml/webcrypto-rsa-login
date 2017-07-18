from cryptography.exceptions import InvalidSignature
from flask import Flask, flash, redirect, render_template, request, session, url_for
from redis import Redis

from redis_session import RedisSessionInterface
from util import load_public_key, MalformedPublicKey, random_base64, verify_spkac, verify_challenge

app = Flask(__name__)
app.config.from_pyfile('config.py')
redis = Redis(**app.config['REDIS_CONFIG'])
app.session_interface = RedisSessionInterface(redis)
app.debug = True


@app.after_request
def add_csp(response):
    response.headers["Content-Security-Policy"] = app.config['CSP_HEADER']
    return response


@app.route('/register')
def register():
    challenge = random_base64(app.config['CHALLENGE_BYTES'])
    session['challenge_register'] = challenge

    return render_template('register.html', challenge=challenge)


@app.route('/register/submit', methods=['POST'])
def register_submit():
    public_key_pem = request.form.get('public_key')

    try:
        public_key = load_public_key(public_key_pem.encode('ascii'))
    except MalformedPublicKey as e:
        flash('malformed public key: {}'.format(e), 'danger')
        return redirect(url_for('main'))

    try:
        challenge = session.pop('challenge_register')
    except KeyError:
        flash('no challenge was stored in session', 'danger')
        return redirect(url_for('main'))

    try:
        verify_spkac(public_key, challenge, request.form.get('signature'))
    except InvalidSignature as e:
        flash('signature verification failed', 'danger')
        return redirect(url_for('main'))

    username = request.form.get('username')

    if len(username) == 0:
        flash('empty username not allowed', 'danger')
        return redirect(url_for('main'))

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

    user_public_key = load_public_key(user_public_key_pem)

    try:
        verify_challenge(user_public_key, challenge, request.form.get('signature'))
    except InvalidSignature:
        flash('you are not {}'.format(username), 'danger')
        return redirect(url_for('main'))

    flash('hello user {}'.format(username), 'success')
    return redirect(url_for('main'))


@app.route('/login')
def login():
    challenge = random_base64(app.config['CHALLENGE_BYTES'])
    session['challenge_login'] = challenge

    return render_template('login.html', challenge=challenge)


@app.route('/')
def main():
    return render_template('main.html')


if __name__ == '__main__':
    app.run()
