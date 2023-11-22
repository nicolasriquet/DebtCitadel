from django.urls import re_path
from . import views

urlpatterns = [
    re_path(r'^cred/add', views.new_cred, name='add_cred'),
    re_path(r'^cred/(?P<ttid>\d+)/view$', views.view_cred_details, name='view_cred_details'),
    re_path(r'^cred/(?P<ttid>\d+)/edit$', views.edit_cred, name='edit_cred'),
    re_path(r'^cred/(?P<ttid>\d+)/delete$', views.delete_cred, name='delete_cred'),
    re_path(r'^cred$', views.cred, name='cred'),
    re_path(r'^debt_context/(?P<pid>\d+)/cred/add$', views.new_cred_debt_context, name='new_cred_debt_context'),
    re_path(r'^debt_context/(?P<pid>\d+)/cred/all$', views.all_cred_debt_context, name='all_cred_debt_context'),
    re_path(r'^debt_context/(?P<pid>\d+)/cred/(?P<ttid>\d+)/edit$', views.edit_cred_debt_context, name='edit_cred_debt_context'),
    re_path(r'^debt_context/(?P<pid>\d+)/cred/(?P<ttid>\d+)/view$', views.view_cred_debt_context, name='view_cred_debt_context'),
    re_path(r'^debt_context/(?P<pid>\d+)/cred/(?P<ttid>\d+)/delete$', views.delete_cred_debt_context, name='delete_cred_debt_context'),
    re_path(r'^debt_engagement/(?P<eid>\d+)/cred/add$', views.new_cred_debt_context_debt_engagement, name='new_cred_debt_context_debt_engagement'),
    re_path(r'^debt_engagement/(?P<eid>\d+)/cred/(?P<ttid>\d+)/view$', views.view_cred_debt_context_debt_engagement,
        name='view_cred_debt_context_debt_engagement'),
    re_path(r'^debt_engagement/(?P<eid>\d+)/cred/(?P<ttid>\d+)/delete$', views.delete_cred_debt_engagement,
        name='delete_cred_debt_engagement'),
    re_path(r'^debt_test/(?P<tid>\d+)/cred/add$', views.new_cred_debt_engagement_debt_test, name='new_cred_debt_engagement_debt_test'),
    re_path(r'^debt_test/(?P<tid>\d+)/cred/(?P<ttid>\d+)/view$', views.view_cred_debt_engagement_debt_test,
        name='view_cred_debt_engagement_debt_test'),
    re_path(r'^debt_test/(?P<tid>\d+)/cred/(?P<ttid>\d+)/delete$', views.delete_cred_debt_test, name='delete_cred_debt_test'),
    re_path(r'^debt_item/(?P<fid>\d+)/cred/add$', views.new_cred_debt_item, name='new_cred_debt_item'),
    re_path(r'^debt_item/(?P<fid>\d+)/cred/(?P<ttid>\d+)/view$', views.view_cred_debt_item, name='view_cred_debt_item'),
    re_path(r'^debt_item/(?P<fid>\d+)/cred/(?P<ttid>\d+)/delete$', views.delete_cred_debt_item, name='delete_cred_debt_item'),
]
