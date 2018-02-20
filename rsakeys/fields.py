from base64 import b64decode, b64encode
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from django.core import exceptions
from django.db.models import BinaryField
from django.utils.encoding import force_bytes
from django.utils.translation import gettext_lazy as _

import pdb


class RSAKeyField(BinaryField):
    public_exponent = None
    key_size = None
    backend = None
    key = None
    description = _("""An extension of django.db.models.BinaryField
which generates cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey
object, adding its full functionality.""")

    def __init__(self, public_exponent=None, key_size=None, backend=None,
        *args, **kwargs):
        self.public_exponent, self.key_size, self.backend = (
            public_exponent, key_size, backend)
        kwargs['editable'] = False
        self.generate_keys()
        super(RSAKeyField, self).__init__(*args, **kwargs)

    def deconstruct(self):
        name, path, args, kwargs = super(RSAKeyField, self).deconstruct()
        if self.public_exponent is not None:
            kwargs['public_exponent'] = self.public_exponent
        if self.key_size is not None:
            kwargs['key_size'] = self.key_size
        if self.backend is not None:
            kwargs['backend'] = self.backend
        return name, path, args, kwargs

    def from_db_value(self, value, expression, connection):
        if value is None:
            return value
        return self.parse_pem(pem=value, backend=self.backend)

    def to_python(self, value):
        if (
            isinstance(value, rsa.RSAPrivateKey) or
            isinstance(value, rsa.RSAPrivateKeyWithSerialization)):
            return value
        
        if isinstance(value, bytes):
            return self.parse_pem(pem=value, backend=self.backend)

        if value is None:
            return value

    def get_prep_value(self, value):
        return self.parse_pem(pem=value, backend=self.backend)

    def get_db_prep_value(self, value, connection, prepared=False):
        value = self.key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
        if value is not None:
            return connection.Database.Binary(value)
        return value

    def generate_keys(self):
        if self.public_exponent not in [3, 5, 17, 257, 65537]:
            raise exceptions.ValidationError(_("""It's HIGHLY recommended 
    that the exponent be one of the small Fermat primes (3, 5, 17, 257, 
    65537). If in doubt, use 65337 (default)."""))
        if self.key_size < 512:
            raise exceptions.ValidationError(_("""Key size must be greater
    than 512 bits."""))
        if self.backend is None:
            self.backend = backends.default_backend
        self.key =  rsa.generate_private_key(
                public_exponent=self.public_exponent,
                key_size=self.key_size,
                backend=self.backend())
        return self.key

    def parse_pem(self, pem=None, password=None, backend=None):
        if not isinstance(pem, bytes):
            raise exceptions.ValidationError(_("""The pem object needs to 
    be of type 'bytes'."""))
        if len(pem) == 0:
            pem = self.key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
        if self.backend is None:
            self.backend = backends.default_backend
        return serialization.load_pem_private_key(
            pem,
            password=password,
            backend=backend())


class RSAEncryptedTextField(BinaryField):
    key = None
    description = _("""Creates and saves an encrypted message. Requires
the model to have a RSAKeyField defined.""")

    def __init__(self, *args, **kwargs):
        rsa_field_exists = [
            m for m in self.model._meta.get_fields() if isinstance(
                                                        m, RSAKeyField)]
        if not rsa_field_exists:
            raise exceptions.ImproperlyConfigured(_("""In order to use
the EncryptedTextField you must define an RSAKeyField in the model"""))
        self.key = m[0].value_from_object(self.model)
        super(RSAEncryptedTextField, self).__init__(*args, **kwargs)

    def from_db_value(self, value, expression, connection):
        if value is None:
            return value
        return self.parse_pem(pem=value, password=self.passphrase,
            backend=self.backend)

    def to_python(self, value):
        if isinstance(value, str) or value is None:
            return value
        
        if isinstance(value, bytes):
            return self.decrypt(value)

    def get_prep_value(self, value):
        if isinstance(value, str) or value is None:
            return self.encrypt(value)
        
        if isinstance(value, bytes):
            return value

    def get_db_prep_value(self, value, connection, prepared=False):
        value = super().get_db_prep_value(value, connection, prepared)
        if value is not None:
            return connection.Database.Binary(value)
        return value

    # def pre_save(self, model_instance, add, *args, **kwargs):
    #     self.generate_key()
    #     super(RSAKeyField, self).pre_save(model_instance, add,
    #         *args, **kwargs)

    def encrypt(self, value, label=None):
        cipher = self.key.public_key().encrypt(
            value,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=label
            )
        )
        return cipher

    def decrypt(self, value, label=None):
        plaintext = self.key.decrypt(
            value,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=label
            )
        )
        return plaintext
