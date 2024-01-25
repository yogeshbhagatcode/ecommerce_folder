# -*- coding: utf-8 -*-
# Generated by Django 1.11.15 on 2019-03-28 11:17


from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0050_add_specific_ecommerce_roles'),
    ]

    operations = [
        migrations.AddField(
            model_name='ecommercefeatureroleassignment',
            name='enterprise_id',
            field=models.UUIDField(blank=True, null=True, verbose_name=b'Enterprise Customer UUID'),
        ),
    ]
