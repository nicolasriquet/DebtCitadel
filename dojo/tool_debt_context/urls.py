from django.urls import re_path
from . import views

urlpatterns = [
    re_path(r'^debt_context/(?P<pid>\d+)/tool_debt_context/add$', views.new_tool_debt_context, name='new_tool_debt_context'),
    re_path(r'^debt_context/(?P<pid>\d+)/tool_debt_context/all$', views.all_tool_debt_context, name='all_tool_debt_context'),
    re_path(r'^debt_context/(?P<pid>\d+)/tool_debt_context/(?P<ttid>\d+)/edit$', views.edit_tool_debt_context, name='edit_tool_debt_context'),
    re_path(r'^debt_context/(?P<pid>\d+)/tool_debt_context/(?P<ttid>\d+)/delete$', views.delete_tool_debt_context,
        name='delete_tool_debt_context'),
]
