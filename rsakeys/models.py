from cryptography.hazmat.primitives import serialization
from django.conf import settings
from django.db import models

from rsakeys.fields import RSAKeyField

class RSAKeys(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE, related_name='rsa_keys')
    private_key = RSAKeyField(key_size=2048, public_exponent=65537)
    private_pem = models.BinaryField(blank=True, null=True)
    public_pem = models.BinaryField(blank=True, null=True)
    

    def get_public_key(self):
        return self.private_key.public_key()

    def get_private_pem(self):
        return self.private_pem

    def get_public_pem(self):
        return self.public_pem

    # def get_passphrase(self):
    #     return self.passphrase

    def populate(self):
        self.private_pem = self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
        self.public_pem = self.private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
    def clean(self, *args, **kwargs):
        self.populate()
        super(RSAKeys, self).clean(*args, **kwargs)

    def save(self, *args, **kwargs):
        self.full_clean()
        super(RSAKeys, self).save(*args, **kwargs)
