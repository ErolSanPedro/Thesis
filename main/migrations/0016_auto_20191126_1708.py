# Generated by Django 2.2.3 on 2019-11-26 09:08

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0015_audit'),
    ]

    operations = [
        migrations.DeleteModel(
            name='Audit',
        ),
        migrations.RemoveField(
            model_name='penalty',
            name='ipaddress',
        ),
        migrations.DeleteModel(
            name='Blacklist',
        ),
        migrations.DeleteModel(
            name='Penalty',
        ),
    ]
