from cryptography.exceptions import InvalidSignature
from flask import Blueprint, flash, redirect, render_template, request, session, url_for, current_app as app

from util import random_base64, load_public_key, MalformedPublicKey, verify_spkac, verify_challenge

signature_login_poc = Blueprint('signature_login_poc', __name__, template_folder='templates')


@signature_login_poc.route('/register')
def register():
    challenge = random_base64(app.config['CHALLENGE_BYTES'])
    session['challenge_register'] = challenge

    return render_template('register.html', challenge=challenge)


@signature_login_poc.route('/register/submit', methods=['POST'])
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

    if app.extensions['public_keys'].fetch_user_pem(username):
        flash('such user already exists', 'danger')
        return redirect(url_for('main'))

    app.extensions['public_keys'].store_user_pem(username, public_key_pem)

    flash('succesfully registered as {}'.format(username), 'success')
    return redirect(url_for('main'))


@signature_login_poc.route('/login')
def login():
    challenge = random_base64(app.config['CHALLENGE_BYTES'])
    session['challenge_login'] = challenge

    return render_template('login.html', challenge=challenge)


@signature_login_poc.route('/login/submit', methods=['POST'])
def login_submit():
    username = request.form.get('username')
    user_public_key_pem = app.extensions['public_keys'].fetch_user_pem(username)

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
