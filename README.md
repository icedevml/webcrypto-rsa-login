Signature Login PoC
===================

This is a proof-of-concept which implements user registration and sign-in using Web Crypto API key generation
and signing features. During registration, user generates an RSA key pair on the client side and the private key
is stored in user browser's IndexedDB. This private key is later used for signing the login challenges and this
is how user could authenticate with the server.

Requires `cryptography` (for checking RSA signatures) and `redis` (for maintaining server side sessions; it doesn't
make much sense to use challenge nonces with default Flask's client side sessions).


Deployment
----------

1. Install Python 3 interpreter: `apt-get install python3 python3-pip`
2. Install necessary requirements: `pip3 install -r requirements.txt`
3. Install Redis server: `apt-get install redis-server`
4. Run everything with `python3 cryptoauth.py`, the application will listen on http://localhost:5000