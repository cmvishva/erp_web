# Generated by Django 5.0.6 on 2024-10-09 12:10

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('erp_admin', '0017_remove_leaves_employee_alter_leaves_leavestatus'),
    ]

    operations = [
        migrations.DeleteModel(
            name='leaves',
        ),
    ]
