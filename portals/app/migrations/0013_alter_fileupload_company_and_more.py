# Generated by Django 4.1.1 on 2023-01-09 04:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0012_remove_fileupload_thumbnail_alter_fileupload_company_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='fileupload',
            name='company',
            field=models.JSONField(max_length=25),
        ),
        migrations.AlterField(
            model_name='fileupload',
            name='designation',
            field=models.JSONField(max_length=25),
        ),
        migrations.AlterField(
            model_name='fileupload',
            name='experience',
            field=models.JSONField(max_length=25),
        ),
        migrations.AlterField(
            model_name='fileupload',
            name='location',
            field=models.JSONField(max_length=20),
        ),
    ]
