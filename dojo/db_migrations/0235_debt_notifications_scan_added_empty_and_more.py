# Generated by Django 4.1.11 on 2023-12-19 14:18

from django.db import migrations, models
import multiselectfield.db.fields


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0234_alter_debt_engagement_presets_test_type'),
    ]

    operations = [
        migrations.AddField(
            model_name='debt_notifications',
            name='scan_added_empty',
            field=multiselectfield.db.fields.MultiSelectField(blank=True, choices=[('slack', 'slack'), ('msteams', 'msteams'), ('mail', 'mail'), ('alert', 'alert')], default=[], help_text='Triggered whenever an (re-)import has been done (even if that created/updated/closed no debt items).', max_length=24),
        ),
        migrations.AddField(
            model_name='notifications',
            name='scan_added_empty',
            field=multiselectfield.db.fields.MultiSelectField(blank=True, choices=[('slack', 'slack'), ('msteams', 'msteams'), ('mail', 'mail'), ('alert', 'alert')], default=[], help_text='Triggered whenever an (re-)import has been done (even if that created/updated/closed no findings).', max_length=24),
        ),
        migrations.AlterField(
            model_name='debt_notifications',
            name='risk_acceptance_expiration',
            field=multiselectfield.db.fields.MultiSelectField(blank=True, choices=[('slack', 'slack'), ('msteams', 'msteams'), ('mail', 'mail'), ('alert', 'alert')], default=('alert', 'alert'), help_text='Get notified of (upcoming) Risk Acceptance expiries', max_length=24, verbose_name='Risk Acceptance Expiration'),
        ),
        migrations.AlterField(
            model_name='system_settings',
            name='jira_webhook_secret',
            field=models.CharField(blank=True, help_text='Secret needed in URL for incoming JIRA Webhook', max_length=64, null=True, verbose_name='JIRA Webhook URL'),
        ),
    ]
