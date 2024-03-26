# Developer Cheat Sheet

## Restoring Data

1. cd into the project folder
2. venv\Scripts\activate
3. python manage.py flush
   1. Type "Yes"
4. python manage.py createsuperuser
   1. Enter a username
   2. Enter an email address
   3. Enter the password twice
5. python manage.py loaddata \<path to a fixture\>
   1. E.g., python manage.py loaddata dojo\fixtures\debt_story_empirical_study_data.json

## Manage database migrations

1. python manage.py makemigrations
2. python manage.py migrate