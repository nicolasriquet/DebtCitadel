# Generated by Django 4.1.11 on 2023-11-14 13:47

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0200_alter_debt_endpoint_status_debt_item_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='Debt_JIRA_Project',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('project_key', models.CharField(blank=True, max_length=200)),
                ('issue_template_dir', models.CharField(blank=True, help_text='Choose the folder containing the Django templates used to render the JIRA issue description. These are stored in dojo/templates/issue-trackers. Leave empty to use the default jira_full templates.', max_length=255, null=True)),
                ('component', models.CharField(blank=True, max_length=200)),
                ('custom_fields', models.JSONField(blank=True, help_text='JIRA custom field JSON mapping of Id to value, e.g. {"customfield_10122": [{"name": "8.0.1"}]}', max_length=200, null=True)),
                ('default_assignee', models.CharField(blank=True, help_text='JIRA default assignee (name). If left blank then it defaults to whatever is configured in JIRA.', max_length=200, null=True)),
                ('jira_labels', models.CharField(blank=True, help_text='JIRA issue labels space seperated', max_length=200, null=True)),
                ('add_vulnerability_id_to_jira_label', models.BooleanField(default=False, verbose_name='Add vulnerability Id as a JIRA label')),
                ('push_all_issues', models.BooleanField(blank=True, default=False, help_text='Automatically maintain parity with JIRA. Always create and update JIRA tickets for debt_items in this Debt_Context.')),
                ('enable_debt_engagement_epic_mapping', models.BooleanField(blank=True, default=False)),
                ('push_notes', models.BooleanField(blank=True, default=False)),
                ('debt_context_jira_sla_notification', models.BooleanField(blank=True, default=False, verbose_name='Send SLA notifications as comment?')),
                ('risk_acceptance_expiration_notification', models.BooleanField(blank=True, default=False, verbose_name='Send Risk Acceptance expiration notifications as comment?')),
                ('debt_context', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='dojo.debt_context')),
                ('debt_engagement', models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='dojo.debt_engagement')),
                ('jira_instance', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='dojo.jira_instance', verbose_name='JIRA Instance')),
            ],
        ),
    ]
