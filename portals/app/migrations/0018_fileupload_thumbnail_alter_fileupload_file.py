# Generated by Django 4.1.5 on 2023-01-24 05:48

import app.models
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0017_remove_fileupload_thumbnail_alter_fileupload_file'),
    ]

    operations = [
        migrations.AddField(
            model_name='fileupload',
            name='thumbnail',
            field=models.ImageField(blank=True, upload_to='', verbose_name='Thumbail of the uploaded image'),
        ),
        migrations.AlterField(
            model_name='fileupload',
            name='file',
            field=models.FileField(upload_to=app.models.scramble_uploaded_filename),
        ),
    ]