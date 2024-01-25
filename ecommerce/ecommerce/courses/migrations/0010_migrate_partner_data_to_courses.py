# -*- coding: utf-8 -*-
# Generated by Django 1.11.11 on 2018-07-27 07:57


import django.db.models.deletion
from django.db import migrations, models


def add_partner_to_courses(apps, schema_editor):
    Course = apps.get_model("courses", "Course")

    for course in Course.objects.all():
        course.partner = course.site.siteconfiguration.partner
        course.save()


def reverse_add_partner_to_courses(apps, schema_editor):
    Course = apps.get_model("courses", "Course")

    for course in Course.objects.all():
        site_configuration = course.site.siteconfiguration if course.site else None
        if site_configuration and course.partner != site_configuration.partner:
            site_configuration.partner = course.partner
            site_configuration.save()


class Migration(migrations.Migration):

    dependencies = [
        ('courses', '0009_allow_site_to_be_nullable'),
    ]

    operations = [
        migrations.RunPython(add_partner_to_courses, reverse_add_partner_to_courses),
        migrations.AlterField(
            model_name='course',
            name='partner',
            field=models.ForeignKey(blank=False, null=False, on_delete=django.db.models.deletion.PROTECT,
                                    to='partner.Partner'),
        ),
    ]