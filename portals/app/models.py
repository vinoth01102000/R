import base64
import datetime
from io import BytesIO
import random
import string
from django.db import models
# from easy_thumbnails.fields import ThumbnailerImageField
import os
import uuid
from PIL import Image
from django.conf import settings

from django.db.models.signals import post_save
from django.utils.translation import gettext as _
import subprocess
# Create your models here.
def password():
    result = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    return str(result)

def otp():
    result = ''.join(random.choices( string.digits, k=4))
    return str(result)
    
class User(models.Model):
    UserName = models.CharField(max_length=25, blank=False, unique=True)
    Email = models.CharField(max_length=50, blank='', unique=True)
    MobileNumber = models.CharField(max_length=15, default='')
    Address = models.CharField(max_length=50, blank='')
    City = models.CharField(max_length=25, default='')
    State = models.CharField(max_length=25, default='')
    Credits = models.IntegerField(default=0)
    Password = models.CharField(max_length=15, blank=False, default=password)
    otp = models.CharField(max_length=10, default=otp)
    Role = models.CharField(max_length=50, default='Admin')
    REQUIRED_FIELDS = [],
    EMAIL_FIELD = "Email"
    USERNAME_FIELD = 'UserName'
    is_anonymous = models.BooleanField(default=False)
    is_authenticated = models.BooleanField(default=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=True)
    
    class meta:
        ordering = ['-id']


class Recruiters(models.Model):
    CompanyName = models.CharField(max_length=25, blank=False)
    UserName = models.CharField(max_length=25, blank=False)
    Email = models.CharField(max_length=50, blank='',unique=True)
    MobileNumber = models.CharField(max_length=15, default='')
    Address = models.CharField(max_length=50, blank='')
    City = models.CharField(max_length=25, default='')
    State = models.CharField(max_length=25, default='')
    Credits = models.IntegerField(default=0)
    Password = models.CharField(max_length=15, blank=False, default=password)
    otp = models.CharField(max_length=10, default=otp)
    Role = models.CharField(max_length=50, default='user')
    created_at = models.DateTimeField(default=datetime.datetime.now())
    REQUIRED_FIELDS = [],
    EMAIL_FIELD = "Email"
    USERNAME_FIELD = 'UserName'
    is_anonymous = models.BooleanField(default=False)
    is_authenticated = models.BooleanField(default=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=True)
    
    class meta:
        ordering = ['-id']

class Assessment(models.Model):
    Name = models.CharField(max_length=25, blank=False)
    Tags = models.CharField(max_length=25, blank=False)
    Description = models.CharField(max_length=25, blank=False)
    Question = models.TextField()
    
    class meta:
        ordering = ['-id']
    
class Plan(models.Model):
    Title = models.CharField(max_length=100)
    Price = models.IntegerField()
    Features = models.CharField(max_length=100)

def scramble_uploaded_filename(instance, filename):
    extension = filename.split(".")[-1]
    return "{}.{}".format(uuid.uuid4(), extension)

# import PIL.Image as PILI

class FileUpload(models.Model):
    location = models.TextField() 
    experience = models.TextField()
    company = models.TextField()
    designation = models.TextField()
    file = models.FileField() 
    thumbnail = models.ImageField(blank=True, null=True)
    
    class meta:
        ordering = ['-id']
    
    def save(self, force_insert=False, force_update=False, using=None, update_fields=None):
        thumbnail = "%s.png" % (self.file,)
        self.thumbnail = thumbnail
        super(FileUpload, self).save()

    def __unicode__(self):
        return self.file

def fileupload_post_save(sender, instance=False, **kwargs):
    fileupload = FileUpload.objects.get(id=instance.id)
    command = "convert -quality 95 -thumbnail 222 %s%s[0] %s%s" % (settings.MEDIA_ROOT, fileupload.file, settings.MEDIA_ROOT, fileupload.thumbnail)

    proc = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,)
    stdout_value = proc.communicate()[0]

post_save.connect(fileupload_post_save, sender=FileUpload)
    # thumbnail = models.ImageField("Thumbail of the uploaded image", blank=True)

    # def save(self, force_insert=False, force_update=False, using=None, update_fields=None):
    #     self.thumbnail = create_thumbnail(self.file)
    #     super(FileUpload, self).save()
    
    # def __str__(self):
    #     return self.location

