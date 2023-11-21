from django.urls import re_path

from dojo.debt_metrics import views

urlpatterns = [
    #  debt_metrics
    re_path(r'^debt_metrics$', views.debt_metrics, {'mtype': 'All'},
        name='debt_metrics'),
    re_path(r'^critical_debt_context_metrics$', views.critical_debt_context_metrics, {'mtype': 'All'},
        name='critical_debt_context_metrics'),
    re_path(r'^debt_metrics/all$', views.debt_metrics, {'mtype': 'All'},
        name='debt_metrics_all'),
    re_path(r'^debt_metrics/debt_context/type$', views.debt_metrics, {'mtype': 'All'},
        name='debt_metrics_debt_context_type'),
    re_path(r'^debt_metrics/simple$', views.simple_debt_metrics,
        name='simple_debt_metrics'),
    re_path(r'^debt_metrics/debt_context/type/(?P<mtype>\d+)$',
        views.debt_metrics, name='debt_context_type_metrics'),
    re_path(r'^debt_metrics/debt_context/type/(?P<mtype>\d+)$',
            views.debt_metrics, name='debt_context_type_metrics'),
    re_path(r'^debt_metrics/debt_context/type/counts$',
        views.debt_context_type_counts, name='debt_context_type_counts'),
    re_path(r'^debt_metrics/engineer$', views.engineer_metrics,
        name='engineer_debt_metrics'),
    re_path(r'^debt_metrics/engineer/(?P<eid>\d+)$', views.view_engineer,
        name='view_engineer'),
]
