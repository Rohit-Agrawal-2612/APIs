# Generated by Django 3.2.8 on 2022-01-26 06:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0004_remove_myuser_is_superuser'),
    ]

    operations = [
        migrations.AlterField(
            model_name='myuser',
            name='password',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
    ]