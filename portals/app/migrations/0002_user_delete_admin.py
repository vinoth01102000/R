# Generated by Django 4.1.1 on 2022-12-12 12:14

import app.models
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('UserName', models.CharField(max_length=25)),
                ('Email', models.CharField(blank='', max_length=50)),
                ('MobileNumber', models.CharField(default='', max_length=15)),
                ('Address', models.CharField(blank='', max_length=50)),
                ('City', models.CharField(default='', max_length=25)),
                ('State', models.CharField(default='', max_length=25)),
                ('Credits', models.CharField(default='', max_length=40)),
                ('Password', models.CharField(default=app.models.password, max_length=15)),
            ],
        ),
        migrations.DeleteModel(
            name='Admin',
        ),
    ]
