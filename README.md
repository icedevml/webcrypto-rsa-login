This is a proof-of-concept which implements user registration and sign-in using Web Crypto API key generation
and signing features. During registration, user generates an RSA key pair on the client side and the private key
is stored in user browser's IndexedDB. This private key is later used for signing the login challenges and this
is how user could authenticate with the server.
