# Generated by Django 5.0.6 on 2024-10-25 09:18

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('erp_admin', '0026_quotation_details'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='allemployee',
            name='manager_details',
        ),
    ]
