# Generated by Django 3.2.2 on 2021-07-20 21:02

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('metagov', '0002_metagovplatformaction_metagovprocess_metagovuser'),
    ]

    operations = [
        migrations.AlterField(
            model_name='metagovplatformaction',
            name='json_data',
            field=models.CharField(blank=True, max_length=2000, null=True),
        ),
        migrations.AlterField(
            model_name='metagovprocess',
            name='json_data',
            field=models.CharField(blank=True, max_length=2000, null=True),
        ),
    ]