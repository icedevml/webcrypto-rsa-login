from flask import Flask, render_template
from redis import Redis

from redis_session import RedisSessionInterface
from cryptoauth_blueprint import signature_login_poc


class PublicKeyStorage:
    def __init__(self, redis):
        self.redis = redis

    def fetch_user_pem(self, username):
        return self.redis.get('user:{}:public_key'.format(username))

    def store_user_pem(self, username, public_key_pem):
        self.redis.set('user:{}:public_key'.format(username), public_key_pem)


app = Flask(__name__)
app.config.from_pyfile('config.py')
redis = Redis(**app.config['REDIS_CONFIG'])
app.extensions['public_keys'] = PublicKeyStorage(redis)
app.session_interface = RedisSessionInterface(redis)
app.debug = True

app.register_blueprint(signature_login_poc)


@app.after_request
def add_csp(response):
    response.headers['Content-Security-Policy'] = app.config['CSP_HEADER']
    return response


@app.route('/')
def main():
    return render_template('main.html')


if __name__ == '__main__':
    app.run()
