# users/signals.py
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import CustomUser
from .crypto_utils import kem_generate, generate_sign_keypair

@receiver(post_save, sender=CustomUser)
def generate_user_keys(sender, instance, created, **kwargs):
    if created:
        kem = kem_generate()
        sig = generate_sign_keypair()
        instance.kem_pk = kem["pk"]; instance.kem_sk = kem["sk"]
        instance.sign_pk = sig["pk"]; instance.sign_sk = sig["sk"]
        instance.save()
