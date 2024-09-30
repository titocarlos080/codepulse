# Generated by Django 5.0.3 on 2024-05-03 21:18

import django
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('codepulse', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='ScanResult',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user', models.ForeignKey(to=settings.AUTH_USER_MODEL,on_delete=django.db.models.deletion.CASCADE,)),       
                ('url', models.URLField()),
                ('scanned_on', models.DateTimeField(auto_now_add=True)),
                ('xss_detected', models.BooleanField(default=False)),
                ('sql_injection_detected', models.BooleanField(default=False)),
                ('csrf_issues_detected', models.BooleanField(default=False)),
                ('additional_info', models.TextField(blank=True, null=True)),
            ],
        ),
    ]
