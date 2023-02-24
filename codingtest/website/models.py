# Create your models here.
from django.db import models
from hashlib import sha256
from django.contrib.auth.models import User

class Uploadedg(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    filename = models.CharField(max_length=255)
    path = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'filename')