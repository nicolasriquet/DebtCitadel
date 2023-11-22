from django.urls import re_path

from dojo.debt_search import views

urlpatterns = [
    #  search
    re_path(r'^simple_search$', views.simple_search,
        name='simple_search'),
]
