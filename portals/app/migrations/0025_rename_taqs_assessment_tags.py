# Generated by Django 4.1.5 on 2023-02-02 11:04

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0024_assessment'),
    ]

    operations = [
        migrations.RenameField(
            model_name='assessment',
            old_name='Taqs',
            new_name='Tags',
        ),
    ]
