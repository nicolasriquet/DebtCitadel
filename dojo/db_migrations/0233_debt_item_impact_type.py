# Generated by Django 4.1.11 on 2023-12-07 08:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0232_debt_item_artifact'),
    ]

    operations = [
        migrations.AddField(
            model_name='debt_item',
            name='impact_type',
            field=models.CharField(default=1, help_text='The type of impact.', max_length=200, verbose_name='Impact Type'),
            preserve_default=False,
        ),
    ]
