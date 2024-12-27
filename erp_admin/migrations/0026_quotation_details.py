# Generated by Django 5.0.6 on 2024-10-18 10:16

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('erp_admin', '0025_delete_quotation_details'),
    ]

    operations = [
        migrations.CreateModel(
            name='quotation_details',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('quotation_header', models.CharField(blank=True, max_length=10000)),
                ('consignee_name', models.CharField(blank=True, max_length=10000)),
                ('consignee_address', models.TextField(blank=True)),
                ('pi_no', models.CharField(blank=True, max_length=10000)),
                ('date', models.DateField(blank=True)),
                ('clearing_port', models.CharField(blank=True, max_length=10000)),
                ('product_name', models.CharField(blank=True, max_length=10000)),
                ('exchange_rate', models.CharField(blank=True, max_length=10000)),
                ('fortyfive_container', models.CharField(blank=True, max_length=10000)),
                ('forty_container', models.CharField(blank=True, max_length=10000)),
                ('twenty_container', models.CharField(blank=True, max_length=10000)),
                ('sl_qty_cont', models.CharField(blank=True, max_length=10000)),
                ('sl_inr_per_cont', models.CharField(blank=True, max_length=10000)),
                ('sl_gst_18', models.CharField(blank=True, max_length=10000)),
                ('sl_total_inr', models.CharField(blank=True, max_length=10000)),
                ('cfs_qty_cont', models.CharField(max_length=10000)),
                ('cfs_inr_per_cont', models.CharField(blank=True, max_length=10000)),
                ('cfs_gst_18', models.CharField(blank=True, max_length=10000)),
                ('cfs_total_inr', models.CharField(blank=True, max_length=10000)),
                ('transportation_qty_cont', models.CharField(blank=True, max_length=10000)),
                ('transportation_inr_per_cont', models.CharField(blank=True, max_length=10000)),
                ('transportation_gst_18', models.CharField(blank=True, max_length=10000)),
                ('transportation_total_inr', models.CharField(blank=True, max_length=10000)),
                ('stamp_qty_cont', models.CharField(blank=True, max_length=10000)),
                ('stamp_inr_per_cont', models.CharField(blank=True, max_length=10000)),
                ('stamp_gst_18', models.CharField(max_length=10000)),
                ('stamp_total_inr', models.CharField(max_length=10000)),
                ('agency_qty_cont', models.CharField(blank=True, max_length=10000)),
                ('agency_inr_per_cont', models.CharField(blank=True, max_length=10000)),
                ('agency_gst_18', models.CharField(blank=True, max_length=10000)),
                ('agency_total_inr', models.CharField(blank=True, max_length=10000)),
                ('customduty_qty_cont', models.CharField(max_length=10000)),
                ('customduty_inr_per_cont', models.CharField(max_length=10000)),
                ('customduty_gst_18', models.CharField(max_length=10000)),
                ('customduty_total_inr', models.CharField(max_length=10000)),
                ('oceanfreight_qty_cont', models.CharField(blank=True, max_length=10000)),
                ('oceanfreight_inr_per_cont', models.CharField(blank=True, max_length=10000)),
                ('oceanfreight_gst_18', models.CharField(blank=True, max_length=10000)),
                ('oceanfreight_total_inr', models.CharField(blank=True, max_length=10000)),
                ('round_off', models.CharField(blank=True, max_length=10000)),
                ('total', models.CharField(blank=True, max_length=10000)),
                ('ac_name', models.CharField(blank=True, max_length=10000)),
                ('bank_name', models.CharField(blank=True, max_length=10000)),
                ('ac_no', models.CharField(blank=True, max_length=10000)),
                ('ifsc_code', models.CharField(blank=True, max_length=10000)),
                ('pan_no', models.CharField(blank=True, max_length=10000)),
                ('gst_no', models.CharField(blank=True, max_length=10000)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]