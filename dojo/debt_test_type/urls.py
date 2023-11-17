from django.urls import re_path

from dojo.debt_test_type import views

urlpatterns = [
    # test types
    re_path(r'^debt_test_type$', views.debt_test_type, name='debt_test_type'),
    re_path(r'^debt_test_type/add$', views.add_debt_test_type,
        name='add_debt_test_type'),
    re_path(r'^debt_test_type/(?P<ptid>\d+)/edit$',
        views.edit_debt_test_type, name='edit_debt_test_type'),
]
