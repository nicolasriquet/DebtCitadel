from django.urls import re_path

from dojo.debt_item import views

urlpatterns = [
    # CRUD operations
    re_path(
        r'^debt_item/(?P<debt_item_id>\d+)$',
        views.ViewDebtItem.as_view(),
        name='view_debt_item'
    ),
    re_path(
        r'^debt_item/(?P<debt_item_id>\d+)/edit$',
        views.EditDebtItem.as_view(),
        name='edit_debt_item'
    ),
    re_path(
        r'^debt_item/(?P<debt_item_id>\d+)/delete$',
        views.DeleteDebtItem.as_view(),
        name='delete_debt_item'
    ),
    # Listing operations
    re_path(
        r'^debt_item$',
        views.ListDebtItems.as_view(),
        name='all_debt_items'
    ),
    re_path(
        r'^debt_item/open$',
        views.ListOpenDebtItems.as_view(),
        name='open_debt_items'
    ),
    re_path(
        r'^debt_item/verified$',
        views.ListVerifiedDebtItems.as_view(),
        name='verified_debt_items'
    ),
    re_path(
        r'^debt_item/closed$',
        views.ListClosedDebtItems.as_view(),
        name='closed_debt_items'
    ),
    re_path(
        r'^debt_item/accepted$',
        views.ListAcceptedDebtItems.as_view(),
        name='accepted_debt_items'
    ),
    re_path(
        r'^product/(?P<product_id>\d+)/debt_item/open$',
        views.ListOpenDebtItems.as_view(),
        name='product_open_debt_items'
    ),
    re_path(
        r'^product/(?P<product_id>\d+)/debt_items$',
        views.ListOpenDebtItems.as_view(),
        name='view_product_debt_items_old'
    ),
    re_path(
        r'^product/(?P<product_id>\d+)/debt_item/verified$',
        views.ListVerifiedDebtItems.as_view(),
        name='product_verified_debt_items'
    ),
    re_path(
        r'^product/(?P<product_id>\d+)/debt_item/out_of_scope$',
        views.ListOutOfScopeDebtItems.as_view(),
        name='product_out_of_scope_debt_items'
    ),
    re_path(
        r'^product/(?P<product_id>\d+)/debt_item/inactive$',
        views.ListInactiveDebtItems.as_view(),
        name='product_inactive_debt_items'
    ),
    re_path(
        r'^product/(?P<product_id>\d+)/debt_item/all$',
        views.ListDebtItems.as_view(),
        name='product_all_debt_items'
    ),
    re_path(
        r'^product/(?P<product_id>\d+)/debt_item/closed$',
        views.ListClosedDebtItems.as_view(),
        name='product_closed_debt_items'
    ),
    re_path(
        r'^product/(?P<product_id>\d+)/debt_item/false_positive$',
        views.ListFalsePositiveDebtItems.as_view(),
        name='product_false_positive_debt_items'
    ),
    re_path(
        r'^product/(?P<product_id>\d+)/debt_item/accepted$',
        views.ListAcceptedDebtItems.as_view(),
        name='product_accepted_debt_items'
    ),
    re_path(
        r'^engagement/(?P<engagement_id>\d+)/debt_item/open$',
        views.ListOpenDebtItems.as_view(),
        name='engagement_open_debt_items'
    ),
    re_path(
        r'^engagement/(?P<engagement_id>\d+)/debt_item/closed$',
        views.ListClosedDebtItems.as_view(),
        name='engagement_closed_debt_items'
    ),
    re_path(
        r'^engagement/(?P<engagement_id>\d+)/debt_item/verified$',
        views.ListVerifiedDebtItems.as_view(),
        name='engagement_verified_debt_items'
    ),
    re_path(
        r'^engagement/(?P<engagement_id>\d+)/debt_item/accepted$',
        views.ListAcceptedDebtItems.as_view(),
        name='engagement_accepted_debt_items'
    ),
    re_path(
        r'^engagement/(?P<engagement_id>\d+)/debt_item/all$',
        views.ListDebtItems.as_view(),
        name='engagement_all_debt_items'
    ),
    #  debt_items
    re_path(r'^debt_item/bulk$', views.debt_item_bulk_update_all,
        name='debt_item_bulk_update_all'),
    re_path(r'^product/(?P<pid>\d+)/debt_item/bulk_product$', views.debt_item_bulk_update_all,
        name='debt_item_bulk_update_all_product'),
    # re_path(r'^test/(?P<tid>\d+)/bulk', views.debt_item_bulk_update_all,
    #     name='debt_item_bulk_update_all_test'),
    re_path(r'^debt_item/(?P<fid>\d+)/touch$',
        views.touch_debt_item, name='touch_debt_item'),
    re_path(r'^debt_item/(?P<fid>\d+)/simple_risk_accept$',
        views.simple_risk_accept, name='simple_risk_accept_debt_item'),
    re_path(r'^debt_item/(?P<fid>\d+)/simple_risk_unaccept$',
        views.risk_unaccept, name='risk_unaccept_debt_item'),
    re_path(r'^debt_item/(?P<fid>\d+)/request_review$',
        views.request_debt_item_review, name='request_debt_item_review'),
    re_path(r'^debt_item/(?P<fid>\d+)/review$',
        views.clear_debt_item_review, name='clear_debt_item_review'),
    re_path(r'^debt_item/(?P<fid>\d+)/copy$',
        views.copy_debt_item, name='copy_debt_item'),
    re_path(r'^debt_item/(?P<fid>\d+)/apply_cwe$',
        views.apply_template_cwe, name='apply_template_cwe'),
    re_path(r'^debt_item/(?P<fid>\d+)/mktemplate$', views.mktemplate,
        name='mktemplate'),
    re_path(r'^debt_item/(?P<fid>\d+)/find_template_to_apply$', views.find_template_to_apply,
        name='find_template_to_apply'),
    re_path(r'^debt_item/(?P<tid>\d+)/(?P<fid>\d+)/choose_debt_item_template_options$', views.choose_debt_item_template_options,
        name='choose_debt_item_template_options'),
    re_path(r'^debt_item/(?P<fid>\d+)/(?P<tid>\d+)/apply_template_to_debt_item$',
        views.apply_template_to_debt_item, name='apply_template_to_debt_item'),
    re_path(r'^debt_item/(?P<fid>\d+)/close$', views.close_debt_item,
        name='close_debt_item'),
    re_path(r'^debt_item/(?P<fid>\d+)/defect_review$',
        views.defect_debt_item_review, name='defect_debt_item_review'),
    re_path(r'^debt_item/(?P<fid>\d+)/open$', views.reopen_debt_item,
        name='reopen_debt_item'),
    re_path(r'^debt_item/image/(?P<token>[^/]+)$', views.download_debt_item_pic,
        name='download_debt_item_pic'),
    re_path(r'^debt_item/(?P<fid>\d+)/merge$',
        views.merge_debt_item_debt_context, name='merge_debt_item'),
    re_path(r'^product/(?P<pid>\d+)/merge$', views.merge_debt_item_debt_context,
        name='merge_debt_item_debt_context'),
    re_path(r'^debt_item/(?P<duplicate_id>\d+)/duplicate/(?P<original_id>\d+)$',
        views.mark_debt_item_duplicate, name='mark_debt_item_duplicate'),
    re_path(r'^debt_item/(?P<duplicate_id>\d+)/duplicate/reset$',
        views.reset_debt_item_duplicate_status, name='reset_debt_item_duplicate_status'),
    re_path(r'^debt_item/(?P<debt_item_id>\d+)/original/(?P<new_original_id>\d+)$',
        views.set_debt_item_as_original, name='set_debt_item_as_original'),
    re_path(r'^debt_item/(?P<fid>\d+)/remediation_date$', views.remediation_date,
        name='remediation_date'),
    # stub debt_items
    re_path(r'^stub_debt_item/(?P<tid>\d+)/add$',
        views.add_stub_debt_item, name='add_stub_debt_item'),
    re_path(r'^stub_debt_item/(?P<fid>\d+)/promote$',
        views.promote_to_debt_item, name='promote_to_debt_item'),
    re_path(r'^stub_debt_item/(?P<fid>\d+)/delete$',
        views.delete_stub_debt_item, name='delete_stub_debt_item'),

    # template debt_items

    re_path(r'^template$', views.templates,
        name='templates'),
    re_path(r'^template/add$', views.add_template,
        name='add_template'),
    re_path(r'^template/(?P<tid>\d+)/edit$',
        views.edit_template, name='edit_template'),
    re_path(r'^template/(?P<tid>\d+)/delete$',
        views.delete_template, name='delete_template'),
    re_path(r'^template/export$',
        views.export_templates_to_json, name='export_template'),

    re_path(r'^debt_item/(?P<fid>\d+)/jira/unlink$', views.unlink_jira, name='debt_item_unlink_jira'),
    re_path(r'^debt_item/(?P<fid>\d+)/jira/push$', views.push_to_jira, name='debt_item_push_to_jira'),
    # re_path(r'^debt_item/(?P<fid>\d+)/jira/push', views.debt_item_link_to_jira, name='debt_item_link_to_jira'),

]
