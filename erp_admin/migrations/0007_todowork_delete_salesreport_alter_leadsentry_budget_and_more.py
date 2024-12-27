# Generated by Django 5.0.6 on 2024-10-03 06:22

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('erp_admin', '0006_leadsentry_purchasereport_salesreport'),
    ]

    operations = [
        migrations.CreateModel(
            name='todowork',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('work', models.TextField()),
                ('start_date', models.DateField()),
                ('end_date', models.DateField()),
                ('work_desc', models.TextField()),
                ('status', models.CharField(max_length=10000)),
                ('delay_reason', models.TextField()),
                ('fullname', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='erp_admin.allemployee')),
            ],
        ),
        migrations.DeleteModel(
            name='salesreport',
        ),
        migrations.AlterField(
            model_name='leadsentry',
            name='budget',
            field=models.CharField(blank=True, max_length=20000),
        ),
        migrations.AlterField(
            model_name='leadsentry',
            name='companyname',
            field=models.CharField(blank=True, max_length=500),
        ),
        migrations.AlterField(
            model_name='leadsentry',
            name='followup_method',
            field=models.CharField(blank=True, max_length=1200),
        ),
        migrations.AlterField(
            model_name='leadsentry',
            name='jobtitle',
            field=models.CharField(blank=True, max_length=500),
        ),
    ]
