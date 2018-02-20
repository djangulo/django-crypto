# django-crypto

Creates an RSAKeys table in your database, and provides an RSAKeyField to your users, with the following defaults:
 - user: OneToOneField to settings.AUTH_USER_MODEL
 - private_key: a `cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey` instance. This field is automatically populated when a user is created.
 - private_pem: binary representation of the self.private_key PEM (`---BEGIN PRIVATE KEY--- ... ---END PRIVATE KEY---`)
 - public_pem: binary representation of the self.private_key.public_key() PEM


 This library is a work in progress.