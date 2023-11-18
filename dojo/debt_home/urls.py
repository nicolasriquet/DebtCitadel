from django.urls import re_path

from dojo.debt_home import views

urlpatterns = [
    #  dojo home pages
    re_path(r'^$', views.home, name='home'),
    re_path(r'^debt_dashboard$', views.debt_dashboard, name='debt_dashboard'),
    re_path(r'^support$', views.support, name='support'),
]
