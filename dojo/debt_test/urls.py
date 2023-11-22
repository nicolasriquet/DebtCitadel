from django.urls import re_path

from dojo.debt_test import views

urlpatterns = [
    #  debt_tests
    re_path(r'^calendar/debt_tests$', views.debt_test_calendar, name='debt_test_calendar'),
    re_path(
        r'^debt_test/(?P<debt_test_id>\d+)$',
        views.ViewDebtTest.as_view(),
        name='view_debt_test'
    ),
    re_path(r'^debt_test/(?P<tid>\d+)/ics$', views.debt_test_ics,
        name='debt_test_ics'),
    re_path(r'^debt_test/(?P<tid>\d+)/edit$', views.edit_debt_test,
        name='edit_debt_test'),
    re_path(r'^debt_test/(?P<tid>\d+)/delete$', views.delete_debt_test,
        name='delete_debt_test'),
    re_path(r'^debt_test/(?P<tid>\d+)/copy$', views.copy_debt_test,
        name='copy_debt_test'),
    re_path(
        r'^debt_test/(?P<debt_test_id>\d+)/add_debt_items$',
        views.AddDebtItemView.as_view(),
        name='add_debt_items'),
    re_path(r'^debt_test/(?P<tid>\d+)/add_debt_items/(?P<fid>\d+)$',
        views.add_temp_debt_item, name='add_temp_debt_item'),
    re_path(r'^debt_test/(?P<tid>\d+)/search$', views.search, name='search'),
    re_path(r'^debt_test/(?P<tid>\d+)/re_import_scan_results', views.re_import_scan_results, name='re_import_scan_results'),
]
