from django.urls import re_path

from dojo.debt_context_type import views
from dojo.debt_context import views as debt_context_views

urlpatterns = [
    #  debt_context type
    re_path(r'^debt_context/type$', views.debt_context_type, name='debt_context_type'),
    re_path(r'^debt_context/type/(?P<ptid>\d+)$',
        views.view_debt_context_type, name='view_debt_context_type'),
    re_path(r'^debt_context/type/(?P<ptid>\d+)/edit$',
        views.edit_debt_context_type, name='edit_debt_context_type'),
    re_path(r'^debt_context/type/(?P<ptid>\d+)/delete$',
        views.delete_debt_context_type, name='delete_debt_context_type'),
    re_path(r'^debt_context/type/add$', views.add_debt_context_type,
        name='add_debt_context_type'),
    re_path(r'^debt_context/type/(?P<ptid>\d+)/add_debt_context',
        debt_context_views.new_debt_context,
        name='add_debt_context_to_debt_context_type'),
    re_path(r'^debt_context/type/(?P<ptid>\d+)/add_member$', views.add_debt_context_type_member,
        name='add_debt_context_type_member'),
    re_path(r'^debt_context/type/member/(?P<memberid>\d+)/edit$', views.edit_debt_context_type_member,
        name='edit_debt_context_type_member'),
    re_path(r'^debt_context/type/member/(?P<memberid>\d+)/delete$', views.delete_debt_context_type_member,
        name='delete_debt_context_type_member'),
    re_path(r'^debt_context/type/(?P<ptid>\d+)/add_group$', views.add_debt_context_type_group,
        name='add_debt_context_type_group'),
    re_path(r'^debt_context/type/group/(?P<groupid>\d+)/edit$', views.edit_debt_context_type_group,
        name='edit_debt_context_type_group'),
    re_path(r'^debt_context/type/group/(?P<groupid>\d+)/delete$', views.delete_debt_context_type_group,
        name='delete_debt_context_type_group')
]
