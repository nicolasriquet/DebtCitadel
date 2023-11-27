# #  debt_context
import calendar as tcalendar
import logging
import base64

from collections import OrderedDict
from datetime import datetime, date, timedelta
from dateutil.relativedelta import relativedelta
from github import Github
from math import ceil

from django.contrib import messages
from django.contrib.admin.utils import NestedObjects
from django.contrib.postgres.aggregates import StringAgg
from django.db import DEFAULT_DB_ALIAS, connection
from django.db.models import Sum, Count, Q, Max, Prefetch, F, OuterRef, Subquery
from django.db.models.query import QuerySet
from django.core.exceptions import ValidationError, PermissionDenied
from django.http import HttpResponseRedirect, Http404, JsonResponse, HttpRequest
from django.shortcuts import render, get_object_or_404
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext as _
from django.views import View

from dojo.templatetags.display_tags import asvs_calc_level
from dojo.filters import DebtContextEngagementFilter, DebtContextFilter, EngagementFilter, DebtEngagementFilter, \
    MetricsEndpointFilter, MetricsDebtItemFilter, DebtContextComponentFilter
from dojo.forms import DebtContextForm, DebtEngForm, DeleteDebtContextForm, DojoMetaDataForm, JIRAProjectForm,DebtJIRAProjectForm, \
    JIRADebtItemForm, AdHocDebtItemForm, EngagementPresetsForm, DeleteEngagementPresetsForm, DebtContextNotificationsForm, \
    GITHUBDebtItemForm, GITHUB_Debt_Context_Form, GITHUBDebtItemForm, AppAnalysisForm, JIRAEngagementForm, Add_Debt_Context_MemberForm, \
    Edit_Debt_Context_MemberForm, Delete_Debt_Context_MemberForm, Add_Debt_Context_GroupForm, Edit_Debt_Context_Group_Form, \
    Delete_Debt_Context_GroupForm, SLA_Configuration, \
    DeleteAppAnalysisForm, Debt_Context_API_Scan_ConfigurationForm, DeleteDebt_Context_API_Scan_ConfigurationForm
from dojo.models import Debt_Context_Type, Note_Type, Debt_Item, Debt_Context, Debt_Engagement, Debt_Test, GITHUB_PKey, \
    Debt_Test_Type, System_Settings, Languages, Debt_Languages, App_Analysis, Debt_App_Analysis, Benchmark_Debt_Context_Summary, Endpoint_Status, \
    Endpoint, Debt_Endpoint, Engagement_Presets, DojoMeta, Notifications, Debt_Notifications, BurpRawRequestResponse, Debt_Context_Member, \
    Debt_Context_Group, Debt_Context_API_Scan_Configuration
from dojo.utils import add_external_issue, add_error_message_to_response, add_field_errors_to_response, get_page_items, \
    add_breadcrumb, async_delete, \
    get_system_setting, get_setting, Debt_Context_Tab, get_punchcard_data, queryset_check, is_title_in_breadcrumbs, \
    get_enabled_notifications_list, get_zero_severity_level, sum_by_severity_level, get_open_debt_items_burndown

from dojo.debt_notifications.helper import create_notification
from dojo.components.sql_group_concat import Sql_GroupConcat
from dojo.authorization.authorization import user_has_permission, user_has_permission_or_403
from dojo.authorization.roles_permissions import Permissions
from dojo.authorization.authorization_decorators import user_is_authorized
from dojo.debt_context.queries import get_authorized_debt_contexts, get_authorized_members_for_debt_context, \
    get_authorized_groups_for_debt_context
from dojo.debt_context_type.queries import get_authorized_members_for_debt_context_type, get_authorized_groups_for_debt_context_type, \
    get_authorized_debt_context_types
from dojo.tool_config.factory import create_API
from dojo.tools.factory import get_api_scan_configuration_hints

import dojo.debt_item.helper as debt_item_helper
import dojo.jira_link.helper as jira_helper

logger = logging.getLogger(__name__)


def debt_context(request):
    # validate debt_context_type param
    debt_context_type = None
    if 'debt_context_type' in request.GET:
        p = request.GET.getlist('debt_context_type', [])
        if len(p) == 1:
            debt_context_type = get_object_or_404(Debt_Context_Type, id=p[0])

    debt_contexts = get_authorized_debt_contexts(Permissions.Debt_Context_View)

    # perform all stuff for filtering and pagination first, before annotation/prefetching
    # otherwise the paginator will perform all the annotations/prefetching already only to count the total number of records
    # see https://code.djangoproject.com/ticket/23771 and https://code.djangoproject.com/ticket/25375
    name_words = debt_contexts.values_list('name', flat=True)

    debt_context_filter = DebtContextFilter(request.GET, queryset=debt_contexts, user=request.user)

    debt_context_list = get_page_items(request, debt_context_filter.qs, 25)

    # perform annotation/prefetching by replacing the queryset in the page with an annotated/prefetched queryset.
    debt_context_list.object_list = prefetch_for_debt_context(debt_context_list.object_list)

    # print(debt_context_list.object_list.explain)

    add_breadcrumb(title=_("Debt Contexts List"), top_level=not len(request.GET), request=request)

    return render(request, 'dojo/debt_context.html', {
        'debt_context_list': debt_context_list,
        'debt_context_filter': debt_context_filter,
        'name_words': sorted(set(name_words)),
        'user': request.user})


def prefetch_for_debt_context(debt_contexts):
    prefetched_debt_contexts = debt_contexts
    if isinstance(debt_contexts,
                  QuerySet):  # old code can arrive here with debt_contexts being a list because the query was already executed

        prefetched_debt_contexts = prefetched_debt_contexts.prefetch_related('team_manager')
        prefetched_debt_contexts = prefetched_debt_contexts.prefetch_related('debt_context_manager')
        prefetched_debt_contexts = prefetched_debt_contexts.prefetch_related('technical_contact')

        prefetched_debt_contexts = prefetched_debt_contexts.annotate(
            active_debt_engagement_count=Count('debt_engagement__id', filter=Q(debt_engagement__active=True)))
        prefetched_debt_contexts = prefetched_debt_contexts.annotate(
            closed_debt_engagement_count=Count('debt_engagement__id', filter=Q(debt_engagement__active=False)))
        prefetched_debt_contexts = prefetched_debt_contexts.annotate(last_debt_engagement_date=Max('debt_engagement__target_start'))
        prefetched_debt_contexts = prefetched_debt_contexts.annotate(active_debt_item_count=Count('debt_engagement__debt_test__debt_item__id',
                                                                                filter=Q(
                                                                                    debt_engagement__debt_test__debt_item__active=True)))
        prefetched_debt_contexts = prefetched_debt_contexts.annotate(
            active_verified_debt_item_count=Count('debt_engagement__debt_test__debt_item__id',
                                                filter=Q(
                                                    debt_engagement__debt_test__debt_item__active=True,
                                                    debt_engagement__debt_test__debt_item__verified=True)))
        prefetched_debt_contexts = prefetched_debt_contexts.prefetch_related('debt_jira_project_set__jira_instance')
        prefetched_debt_contexts = prefetched_debt_contexts.prefetch_related('members')
        prefetched_debt_contexts = prefetched_debt_contexts.prefetch_related('debt_context_type__members')
        active_endpoint_query = Debt_Endpoint.objects.filter(
            debt_item__active=True,
            debt_item__mitigated__isnull=True).distinct()
        prefetched_debt_contexts = prefetched_debt_contexts.prefetch_related(
            Prefetch('debt_endpoint_set', queryset=active_endpoint_query, to_attr='active_endpoints'))
        prefetched_debt_contexts = prefetched_debt_contexts.prefetch_related('tags')

        if get_system_setting('enable_github'):
            prefetched_debt_contexts = prefetched_debt_contexts.prefetch_related(
                Prefetch('github_pkey_set', queryset=GITHUB_PKey.objects.all().select_related('git_conf'),
                         to_attr='github_confs'))

    else:
        logger.debug('unable to prefetch because query was already executed')

    return prefetched_debt_contexts


def iso_to_gregorian(iso_year, iso_week, iso_day):
    jan4 = date(iso_year, 1, 4)
    start = jan4 - timedelta(days=jan4.isoweekday() - 1)
    return start + timedelta(weeks=iso_week - 1, days=iso_day - 1)


@user_is_authorized(Debt_Context, Permissions.Debt_Context_View, 'pid')
def view_debt_context(request, pid):
    debt_context_query = Debt_Context.objects.all().select_related('debt_context_manager', 'technical_contact', 'team_manager', 'sla_configuration') \
                                      .prefetch_related('members') \
                                      .prefetch_related('debt_context_type__members')
    debt_context = get_object_or_404(debt_context_query, id=pid)
    debt_context_members = get_authorized_members_for_debt_context(debt_context, Permissions.Debt_Context_View)
    debt_context_type_members = get_authorized_members_for_debt_context_type(debt_context.debt_context_type, Permissions.Debt_Context_Type_View)
    debt_context_groups = get_authorized_groups_for_debt_context(debt_context, Permissions.Debt_Context_View)
    debt_context_type_groups = get_authorized_groups_for_debt_context_type(debt_context.debt_context_type, Permissions.Debt_Context_Type_View)
    personal_notifications_form = DebtContextNotificationsForm(
        instance=Debt_Notifications.objects.filter(user=request.user).filter(debt_context=debt_context).first())
    langSummary = Debt_Languages.objects.filter(debt_context=debt_context).aggregate(Sum('files'), Sum('code'), Count('files'))
    languages = Debt_Languages.objects.filter(debt_context=debt_context).order_by('-code').select_related('language')
    app_analysis = Debt_App_Analysis.objects.filter(debt_context=debt_context).order_by('name')
    benchmarks = Benchmark_Debt_Context_Summary.objects.filter(debt_context=debt_context, publish=True,
                                                          benchmark_type__enabled=True).order_by('benchmark_type__name')
    sla = SLA_Configuration.objects.filter(id=debt_context.sla_configuration_id).first()
    benchAndPercent = []
    for i in range(0, len(benchmarks)):
        desired_level, total, total_pass, total_wait, total_fail, total_viewed = asvs_calc_level(benchmarks[i])

        success_percent = round((float(total_pass) / float(total)) * 100, 2)
        waiting_percent = round((float(total_wait) / float(total)) * 100, 2)
        fail_percent = round(100 - success_percent - waiting_percent, 2)
        print(fail_percent)
        benchAndPercent.append({
            'id': benchmarks[i].benchmark_type.id,
            'name': benchmarks[i].benchmark_type,
            'level': desired_level,
            'success': {'count': total_pass, 'percent': success_percent},
            'waiting': {'count': total_wait, 'percent': waiting_percent},
            'fail': {'count': total_fail, 'percent': fail_percent},
            'pass': total_pass + total_fail,
            'total': total
        })
    system_settings = System_Settings.objects.get()

    debt_context_metadata = dict(debt_context.debt_context_meta.order_by('name').values_list('name', 'value'))

    open_debt_items = Debt_Item.objects.filter(debt_test__debt_engagement__debt_context=debt_context,
                                           false_p=False,
                                           active=True,
                                           duplicate=False,
                                           out_of_scope=False).order_by('numerical_severity').values(
        'severity').annotate(count=Count('severity'))

    critical = 0
    high = 0
    medium = 0
    low = 0
    info = 0

    for v in open_debt_items:
        if v["severity"] == "Critical":
            critical = v["count"]
        elif v["severity"] == "High":
            high = v["count"]
        elif v["severity"] == "Medium":
            medium = v["count"]
        elif v["severity"] == "Low":
            low = v["count"]
        elif v["severity"] == "Info":
            info = v["count"]

    total = critical + high + medium + low + info

    debt_context_tab = Debt_Context_Tab(debt_context, title=_("Debt Context"), tab="overview")
    return render(request, 'dojo/debt_view_debt_context_details.html', {
        'debt_context': debt_context,
        'debt_context_tab': debt_context_tab,
        'debt_context_metadata': debt_context_metadata,
        'critical': critical,
        'high': high,
        'medium': medium,
        'low': low,
        'info': info,
        'total': total,
        'user': request.user,
        'languages': languages,
        'langSummary': langSummary,
        'app_analysis': app_analysis,
        'system_settings': system_settings,
        'benchmarks_percents': benchAndPercent,
        'benchmarks': benchmarks,
        'debt_context_members': debt_context_members,
        'debt_context_type_members': debt_context_type_members,
        'debt_context_groups': debt_context_groups,
        'debt_context_type_groups': debt_context_type_groups,
        'personal_notifications_form': personal_notifications_form,
        'enabled_notifications': get_enabled_notifications_list(),
        'sla': sla})


@user_is_authorized(Debt_Context, Permissions.Component_View, 'pid')
def view_debt_context_components(request, pid):
    debt_context = get_object_or_404(Debt_Context, id=pid)
    debt_context_tab = Debt_Context_Tab(debt_context, title=_("debt_context"), tab="components")
    separator = ', '

    # Get components ordered by component_name and concat component versions to the same row
    if connection.vendor == 'postgresql':
        component_query = Debt_Item.objects.filter(debt_testdebt_engagement__debt_context__id=pid).values("component_name").order_by(
            'component_name').annotate(
            component_version=StringAgg('component_version', delimiter=separator, distinct=True))
    else:
        component_query = Debt_Item.objects.filter(debt_testdebt_engagement__debt_context__id=pid).values("component_name")
        component_query = component_query.annotate(
            component_version=Sql_GroupConcat('component_version', separator=separator, distinct=True))

    # Append debt_item counts
    component_query = component_query.annotate(total=Count('id')).order_by('component_name', 'component_version')
    component_query = component_query.annotate(active=Count('id', filter=Q(active=True)))
    component_query = component_query.annotate(duplicate=(Count('id', filter=Q(duplicate=True))))

    # Default sort by total descending
    component_query = component_query.order_by('-total')

    comp_filter = DebtContextComponentFilter(request.GET, queryset=component_query)
    result = get_page_items(request, comp_filter.qs, 25)

    # Filter out None values for auto-complete
    component_words = component_query.exclude(component_name__isnull=True).values_list('component_name', flat=True)

    return render(request, 'dojo/debt_context_components.html', {
        'debt_context': debt_context,
        'filter': comp_filter,
        'debt_context_tab': debt_context_tab,
        'result': result,
        'component_words': sorted(set(component_words))
    })


def identify_view(request):
    get_data = request.GET
    view = get_data.get('type', None)
    if view:
        # value of view is reflected in the template, make sure it's valid
        # although any XSS should be catch by django autoescape, we see people sometimes using '|safe'...
        if view in ['Endpoint', 'Debt_Item']:
            return view
        raise ValueError('invalid view, view must be "Endpoint" or "Debt_Item"')
    else:
        if get_data.get('debt_item__severity', None):
            return 'Endpoint'
        elif get_data.get('false_positive', None):
            return 'Endpoint'
    referer = request.META.get('HTTP_REFERER', None)
    if referer:
        if referer.find('type=Endpoint') > -1:
            return 'Endpoint'
    return 'Debt_Item'


def debt_item_querys(request, debt_context):
    filters = dict()

    debt_items_query = Debt_Item.objects.filter(debt_test__debt_engagement__debt_context=debt_context,
                                            severity__in=('Critical', 'High', 'Medium', 'Low', 'Info'))

    # prefetch only what's needed to avoid lots of repeated queries
    debt_items_query = debt_items_query.prefetch_related(
        # 'debt_testdebt_engagement',
        # 'debt_testdebt_engagement__risk_acceptance',
        # 'found_by',
        # 'Debt_Test',
        # 'debt_testtest_type',
        # 'debt_risk_acceptance_set',
        'reporter')
    debt_items = MetricsDebtItemFilter(request.GET, queryset=debt_items_query, pid=debt_context)
    debt_items_qs = queryset_check(debt_items)
    filters['form'] = debt_items.form

    # dead code:
    # if not debt_items_qs and not debt_items_query:
    #     # logger.debug('all filtered')
    #     debt_items = debt_items_query
    #     debt_items_qs = queryset_check(debt_items)
    #     messages.add_message(request,
    #                                  messages.ERROR,
    #                                  'All objects have been filtered away. Displaying all objects',
    #                                  extra_tags='alert-danger')

    try:
        # logger.debug(debt_items_qs.query)
        start_date = debt_items_qs.earliest('date').date
        start_date = datetime(start_date.year,
                              start_date.month, start_date.day,
                              tzinfo=timezone.get_current_timezone())
        end_date = debt_items_qs.latest('date').date
        end_date = datetime(end_date.year,
                            end_date.month, end_date.day,
                            tzinfo=timezone.get_current_timezone())
    except Exception as e:
        logger.debug(e)
        start_date = timezone.now()
        end_date = timezone.now()
    week = end_date - timedelta(days=7)  # seven days and /newnewer are considered "new"

    # risk_acceptances = Risk_Acceptance.objects.filter(debt_engagement__in=Debt_Engagement.objects.filter(debt_context=debt_context)).prefetch_related('accepted_debt_items')
    # filters['accepted'] = [debt_item for ra in risk_acceptances for debt_item in ra.accepted_debt_items.all()]

    from dojo.debt_item.helper import ACCEPTED_DEBT_ITEMS_QUERY
    filters['accepted'] = debt_items_qs.filter(ACCEPTED_DEBT_ITEMS_QUERY).filter(date__range=[start_date, end_date])
    filters['verified'] = debt_items_qs.filter(date__range=[start_date, end_date],
                                             false_p=False,
                                             active=True,
                                             verified=True,
                                             duplicate=False,
                                             out_of_scope=False).order_by("date")
    filters['new_verified'] = debt_items_qs.filter(date__range=[week, end_date],
                                                 false_p=False,
                                                 verified=True,
                                                 active=True,
                                                 duplicate=False,
                                                 out_of_scope=False).order_by("date")
    filters['open'] = debt_items_qs.filter(date__range=[start_date, end_date],
                                         false_p=False,
                                         duplicate=False,
                                         out_of_scope=False,
                                         active=True,
                                         is_mitigated=False)
    filters['inactive'] = debt_items_qs.filter(date__range=[start_date, end_date],
                                             duplicate=False,
                                             out_of_scope=False,
                                             active=False,
                                             is_mitigated=False)
    filters['closed'] = debt_items_qs.filter(date__range=[start_date, end_date],
                                           false_p=False,
                                           duplicate=False,
                                           out_of_scope=False,
                                           active=False,
                                           is_mitigated=True)
    filters['false_positive'] = debt_items_qs.filter(date__range=[start_date, end_date],
                                                   false_p=True,
                                                   duplicate=False,
                                                   out_of_scope=False)
    filters['out_of_scope'] = debt_items_qs.filter(date__range=[start_date, end_date],
                                                 false_p=False,
                                                 duplicate=False,
                                                 out_of_scope=True)
    filters['all'] = debt_items_qs
    filters['open_vulns'] = debt_items_qs.filter(
        false_p=False,
        duplicate=False,
        out_of_scope=False,
        active=True,
        mitigated__isnull=True,
        cwe__isnull=False,
    ).order_by('cwe').values(
        'cwe'
    ).annotate(
        count=Count('cwe')
    )

    filters['all_vulns'] = debt_items_qs.filter(
        duplicate=False,
        cwe__isnull=False,
    ).order_by('cwe').values(
        'cwe'
    ).annotate(
        count=Count('cwe')
    )

    filters['start_date'] = start_date
    filters['end_date'] = end_date
    filters['week'] = week

    return filters


def endpoint_querys(request, debt_context):
    filters = dict()
    endpoints_query = Endpoint_Status.objects.filter(debt_item__debt_testdebt_engagement__debt_context=debt_context,
                                                     debt_item__severity__in=(
                                                         'Critical', 'High', 'Medium', 'Low', 'Info')).prefetch_related(
        'debt_item__debt_testdebt_engagement',
        'debt_item__debt_testdebt_engagement__risk_acceptance',
        'debt_item__debt_risk_acceptance_set',
        'debt_item__reporter').annotate(severity=F('debt_item__severity'))
    endpoints = MetricsEndpointFilter(request.GET, queryset=endpoints_query)
    endpoints_qs = queryset_check(endpoints)
    filters['form'] = endpoints.form

    if not endpoints_qs and not endpoints_query:
        endpoints = endpoints_query
        endpoints_qs = queryset_check(endpoints)
        messages.add_message(request,
                             messages.ERROR,
                             _('All objects have been filtered away. Displaying all objects'),
                             extra_tags='alert-danger')

    try:
        start_date = endpoints_qs.earliest('date').date
        start_date = datetime(start_date.year,
                              start_date.month, start_date.day,
                              tzinfo=timezone.get_current_timezone())
        end_date = endpoints_qs.latest('date').date
        end_date = datetime(end_date.year,
                            end_date.month, end_date.day,
                            tzinfo=timezone.get_current_timezone())
    except:
        start_date = timezone.now()
        end_date = timezone.now()
    week = end_date - timedelta(days=7)  # seven days and /newnewer are considered "new"

    filters['accepted'] = endpoints_qs.filter(date__range=[start_date, end_date],
                                              risk_accepted=True).order_by("date")
    filters['verified'] = endpoints_qs.filter(date__range=[start_date, end_date],
                                              false_positive=False,
                                              mitigated=True,
                                              out_of_scope=False).order_by("date")
    filters['new_verified'] = endpoints_qs.filter(date__range=[week, end_date],
                                                  false_positive=False,
                                                  mitigated=True,
                                                  out_of_scope=False).order_by("date")
    filters['open'] = endpoints_qs.filter(date__range=[start_date, end_date],
                                          mitigated=False,
                                          debt_item__active=True)
    filters['inactive'] = endpoints_qs.filter(date__range=[start_date, end_date],
                                              mitigated=True)
    filters['closed'] = endpoints_qs.filter(date__range=[start_date, end_date],
                                            mitigated=True)
    filters['false_positive'] = endpoints_qs.filter(date__range=[start_date, end_date],
                                                    false_positive=True)
    filters['out_of_scope'] = endpoints_qs.filter(date__range=[start_date, end_date],
                                                  out_of_scope=True)
    filters['all'] = endpoints_qs
    filters['open_vulns'] = endpoints_qs.filter(
        false_positive=False,
        out_of_scope=False,
        mitigated=True,
        debt_item__cwe__isnull=False,
    ).order_by('debt_item__cwe').values(
        'debt_item__cwe'
    ).annotate(
        count=Count('debt_item__cwe')
    )

    filters['all_vulns'] = endpoints_qs.filter(
        debt_item__cwe__isnull=False,
    ).order_by('debt_item__cwe').values(
        'debt_item__cwe'
    ).annotate(
        count=Count('debt_item__cwe')
    )

    filters['start_date'] = start_date
    filters['end_date'] = end_date
    filters['week'] = week

    return filters


@user_is_authorized(Debt_Context, Permissions.Debt_Context_View, 'pid')
def view_debt_context_metrics(request, pid):
    debt_context = get_object_or_404(Debt_Context, id=pid)
    engs = Debt_Engagement.objects.filter(debt_context=debt_context, active=True)
    view = identify_view(request)

    result = DebtEngagementFilter(
        request.GET,
        queryset=Debt_Engagement.objects.filter(debt_context=debt_context, active=False).order_by('-target_end'))

    inactive_engs_page = get_page_items(request, result.qs, 10)

    filters = dict()
    if view == 'Debt_Item':
        filters = debt_item_querys(request, debt_context)
    elif view == 'Endpoint':
        filters = endpoint_querys(request, debt_context)

    start_date = filters['start_date']
    end_date = filters['end_date']
    week_date = filters['week']

    debt_tests = Debt_Test.objects.filter(debt_engagement__debt_context=debt_context).prefetch_related('debt_item_set', 'debt_test_type')
    debt_tests = debt_tests.annotate(verified_debt_item_count=Count('debt_item__id', filter=Q(debt_item__verified=True)))

    open_vulnerabilities = filters['open_vulns']
    all_vulnerabilities = filters['all_vulns']

    start_date = timezone.make_aware(datetime.combine(start_date, datetime.min.time()))
    r = relativedelta(end_date, start_date)
    weeks_between = int(ceil((((r.years * 12) + r.months) * 4.33) + (r.days / 7)))
    if weeks_between <= 0:
        weeks_between += 2

    punchcard, ticks = get_punchcard_data(filters.get('open', None), start_date, weeks_between, view)

    add_breadcrumb(parent=debt_context, top_level=False, request=request)

    open_close_weekly = OrderedDict()
    new_weekly = OrderedDict()
    severity_weekly = OrderedDict()
    critical_weekly = OrderedDict()
    high_weekly = OrderedDict()
    medium_weekly = OrderedDict()

    open_objs_by_severity = get_zero_severity_level()
    accepted_objs_by_severity = get_zero_severity_level()

    for v in filters.get('open', None):
        iso_cal = v.date.isocalendar()
        x = iso_to_gregorian(iso_cal[0], iso_cal[1], 1)
        y = x.strftime("<span class='small'>%m/%d<br/>%Y</span>")
        x = (tcalendar.timegm(x.timetuple()) * 1000)
        if x not in critical_weekly:
            critical_weekly[x] = {'count': 0, 'week': y}
        if x not in high_weekly:
            high_weekly[x] = {'count': 0, 'week': y}
        if x not in medium_weekly:
            medium_weekly[x] = {'count': 0, 'week': y}

        if x in open_close_weekly:
            if v.mitigated:
                open_close_weekly[x]['closed'] += 1
            else:
                open_close_weekly[x]['open'] += 1
        else:
            if v.mitigated:
                open_close_weekly[x] = {'closed': 1, 'open': 0, 'accepted': 0}
            else:
                open_close_weekly[x] = {'closed': 0, 'open': 1, 'accepted': 0}
            open_close_weekly[x]['week'] = y

        if view == 'Debt_Item':
            severity = v.severity
        elif view == 'Endpoint':
            severity = v.debt_item.severity

        if x in severity_weekly:
            if severity in severity_weekly[x]:
                severity_weekly[x][severity] += 1
            else:
                severity_weekly[x][severity] = 1
        else:
            severity_weekly[x] = get_zero_severity_level()
            severity_weekly[x][severity] = 1
            severity_weekly[x]['week'] = y

        if severity == 'Critical':
            if x in critical_weekly:
                critical_weekly[x]['count'] += 1
            else:
                critical_weekly[x] = {'count': 1, 'week': y}
        elif severity == 'High':
            if x in high_weekly:
                high_weekly[x]['count'] += 1
            else:
                high_weekly[x] = {'count': 1, 'week': y}
        elif severity == 'Medium':
            if x in medium_weekly:
                medium_weekly[x]['count'] += 1
            else:
                medium_weekly[x] = {'count': 1, 'week': y}

        # Optimization: count severity level on server side
        if open_objs_by_severity.get(v.severity) is not None:
            open_objs_by_severity[v.severity] += 1

    for a in filters.get('accepted', None):
        if view == 'Debt_Item':
            debt_item = a
        elif view == 'Endpoint':
            debt_item = v.debt_item
        iso_cal = a.date.isocalendar()
        x = iso_to_gregorian(iso_cal[0], iso_cal[1], 1)
        y = x.strftime("<span class='small'>%m/%d<br/>%Y</span>")
        x = (tcalendar.timegm(x.timetuple()) * 1000)

        if x in open_close_weekly:
            open_close_weekly[x]['accepted'] += 1
        else:
            open_close_weekly[x] = {'closed': 0, 'open': 0, 'accepted': 1}
            open_close_weekly[x]['week'] = y

        if accepted_objs_by_severity.get(a.severity) is not None:
            accepted_objs_by_severity[a.severity] += 1

    debt_test_data = {}
    for t in debt_tests:
        if t.debt_test_type.name in debt_test_data:
            debt_test_data[t.debt_test_type.name] += t.verified_debt_item_count
        else:
            debt_test_data[t.debt_test_type.name] = t.verified_debt_item_count

    debt_context_tab = Debt_Context_Tab(debt_context, title=_("Debt Context"), tab="metrics")

    open_objs_by_age = {x: len([_ for _ in filters.get('open') if _.age == x]) for x in set([_.age for _ in filters.get('open')])}

    return render(request, 'dojo/debt_context_metrics.html', {
        'debt_context': debt_context,
        'debt_context_tab': debt_context_tab,
        'engs': engs,
        'inactive_engs': inactive_engs_page,
        'view': view,
        'verified_objs': filters.get('verified', None),
        'verified_objs_by_severity': sum_by_severity_level(filters.get('verified')),
        'open_objs': filters.get('open', None),
        'open_objs_by_severity': open_objs_by_severity,
        'open_objs_by_age': open_objs_by_age,
        'inactive_objs': filters.get('inactive', None),
        'inactive_objs_by_severity': sum_by_severity_level(filters.get('inactive')),
        'closed_objs': filters.get('closed', None),
        'closed_objs_by_severity': sum_by_severity_level(filters.get('closed')),
        'false_positive_objs': filters.get('false_positive', None),
        'false_positive_objs_by_severity': sum_by_severity_level(filters.get('false_positive')),
        'out_of_scope_objs': filters.get('out_of_scope', None),
        'out_of_scope_objs_by_severity': sum_by_severity_level(filters.get('out_of_scope')),
        'accepted_objs': filters.get('accepted', None),
        'accepted_objs_by_severity': accepted_objs_by_severity,
        'new_objs': filters.get('new_verified', None),
        'new_objs_by_severity': sum_by_severity_level(filters.get('new_verified')),
        'all_objs': filters.get('all', None),
        'all_objs_by_severity': sum_by_severity_level(filters.get('all')),
        'form': filters.get('form', None),
        'reset_link': reverse('view_debt_context_metrics', args=(debt_context.id,)) + '?type=' + view,
        'open_vulnerabilities': open_vulnerabilities,
        'all_vulnerabilities': all_vulnerabilities,
        'start_date': start_date,
        'punchcard': punchcard,
        'ticks': ticks,
        'open_close_weekly': open_close_weekly,
        'severity_weekly': severity_weekly,
        'critical_weekly': critical_weekly,
        'high_weekly': high_weekly,
        'medium_weekly': medium_weekly,
        'test_data': debt_test_data,
        'user': request.user})


@user_is_authorized(Debt_Context, Permissions.Debt_Context_View, 'pid')
def async_burndown_metrics(request, pid):
    debt_context = get_object_or_404(Debt_Context, id=pid)
    open_debt_items_burndown = get_open_debt_items_burndown(debt_context)

    return JsonResponse({
        'critical': open_debt_items_burndown.get('Critical', []),
        'high': open_debt_items_burndown.get('High', []),
        'medium': open_debt_items_burndown.get('Medium', []),
        'low': open_debt_items_burndown.get('Low', []),
        'info': open_debt_items_burndown.get('Info', []),
        'max': open_debt_items_burndown.get('y_max', 0),
        'min': open_debt_items_burndown.get('y_min', 0)
    })


@user_is_authorized(Debt_Context, Permissions.Engagement_View, 'pid')
def view_debt_engagements(request, pid):
    debt_context = get_object_or_404(Debt_Context, id=pid)

    default_page_num = 10
    recent_test_day_count = 7

    # In Progress Engagements
    engs = Debt_Engagement.objects.filter(debt_context=debt_context, active=True, status="In Progress").order_by('-updated')
    active_engs_filter = DebtContextEngagementFilter(request.GET, queryset=engs, prefix='active')
    result_active_engs = get_page_items(request, active_engs_filter.qs, default_page_num, prefix="engs")
    # prefetch only after creating the filters to avoid https://code.djangoproject.com/ticket/23771 and https://code.djangoproject.com/ticket/25375
    result_active_engs.object_list = prefetch_for_view_debt_engagements(result_active_engs.object_list,
                                                                   recent_test_day_count)

    # Engagements that are queued because they haven't started or paused
    engs = Debt_Engagement.objects.filter(~Q(status="In Progress"), debt_context=debt_context, active=True).order_by('-updated')
    queued_engs_filter = DebtContextEngagementFilter(request.GET, queryset=engs, prefix='queued')
    result_queued_engs = get_page_items(request, queued_engs_filter.qs, default_page_num, prefix="queued_engs")
    result_queued_engs.object_list = prefetch_for_view_debt_engagements(result_queued_engs.object_list,
                                                                   recent_test_day_count)

    # Cancelled or Completed Engagements
    engs = Debt_Engagement.objects.filter(debt_context=debt_context, active=False).order_by('-target_end')
    inactive_engs_filter = DebtContextEngagementFilter(request.GET, queryset=engs, prefix='closed')
    result_inactive_engs = get_page_items(request, inactive_engs_filter.qs, default_page_num, prefix="inactive_engs")
    result_inactive_engs.object_list = prefetch_for_view_debt_engagements(result_inactive_engs.object_list,
                                                                     recent_test_day_count)

    debt_context_tab = Debt_Context_Tab(debt_context, title=_("All Engagements"), tab="debt_engagements")
    return render(request, 'dojo/debt_view_debt_engagements.html', {
        'debt_context': debt_context,
        'debt_context_tab': debt_context_tab,
        'engs': result_active_engs,
        'engs_count': result_active_engs.paginator.count,
        'engs_filter': active_engs_filter,
        'queued_engs': result_queued_engs,
        'queued_engs_count': result_queued_engs.paginator.count,
        'queued_engs_filter': queued_engs_filter,
        'inactive_engs': result_inactive_engs,
        'inactive_engs_count': result_inactive_engs.paginator.count,
        'inactive_engs_filter': inactive_engs_filter,
        'recent_test_day_count': recent_test_day_count,
        'user': request.user})


def prefetch_for_view_debt_engagements(debt_engagements, recent_test_day_count):
    debt_engagements = debt_engagements.select_related(
        'lead'
    ).prefetch_related(
        Prefetch('debt_test_set', queryset=Debt_Test.objects.filter(
            id__in=Subquery(
                Debt_Test.objects.filter(
                    debt_engagement_id=OuterRef('debt_engagement_id'),
                    updated__gte=timezone.now() - timedelta(days=recent_test_day_count)
                ).values_list('id', flat=True)
            ))
                 ),
        'debt_test_set__debt_test_type',
    ).annotate(
        count_tests=Count('debt_test', distinct=True),
        count_debt_items_all=Count('debt_test__debt_item__id'),
        count_debt_items_open=Count('debt_test__debt_item__id', filter=Q(debt_test__debt_item__active=True)),
        count_debt_items_open_verified=Count('debt_test__debt_item__id',
                                           filter=Q(debt_test__debt_item__active=True) & Q(debt_test__debt_item__verified=True)),
        count_debt_items_close=Count('debt_test__debt_item__id', filter=Q(debt_test__debt_item__is_mitigated=True)),
        count_debt_items_duplicate=Count('debt_test__debt_item__id', filter=Q(debt_test__debt_item__duplicate=True)),
        count_debt_items_accepted=Count('debt_test__debt_item__id', filter=Q(debt_test__debt_item__risk_accepted=True)),
    )

    if System_Settings.objects.get().enable_jira:
        debt_engagements = debt_engagements.prefetch_related(
            'jira_project__jira_instance',
            'debt_context__jira_project_set__jira_instance',
        )

    return debt_engagements


# Authorization is within the import_scan_results method
def import_scan_results_debt_context(request, pid=None):
    from dojo.debt_engagement.views import import_scan_results
    return import_scan_results(request, pid=pid)


def new_debt_context(request, ptid=None):
    if get_authorized_debt_context_types(Permissions.Debt_Context_Type_Add_Debt_Context).count() == 0:
        raise PermissionDenied()

    jira_project_form = None
    error = False
    initial = None
    if ptid is not None:
        debt_context_type = get_object_or_404(Debt_Context_Type, pk=ptid)
        initial = {'debt_context_type': debt_context_type}

    form = DebtContextForm(initial=initial)

    if request.method == 'POST':
        form = DebtContextForm(request.POST, instance=Debt_Context())

        if get_system_setting('enable_github'):
            gform = GITHUB_Debt_Context_Form(request.POST, instance=GITHUB_PKey())
        else:
            gform = None

        if form.is_valid():
            debt_context_type = form.instance.debt_context_type
            user_has_permission_or_403(request.user, debt_context_type, Permissions.Debt_Context_Type_Add_Debt_Context)

            debt_context = form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 _('debt_context added successfully.'),
                                 extra_tags='alert-success')
            success, jira_project_form = jira_helper.debt_process_jira_project_form(request, debt_context=debt_context)
            error = not success

            if get_system_setting('enable_github'):
                if gform.is_valid():
                    github_pkey = gform.save(commit=False)
                    if github_pkey.git_conf is not None and github_pkey.git_project:
                        github_pkey.debt_context = debt_context
                        github_pkey.save()
                        messages.add_message(request,
                                             messages.SUCCESS,
                                             _('GitHub information added successfully.'),
                                             extra_tags='alert-success')
                        # Create appropriate labels in the repo
                        logger.info('Create label in repo: ' + github_pkey.git_project)

                        description = _("This label is automatically applied to all issues created by DefectDojo")
                        try:
                            g = Github(github_pkey.git_conf.api_key)
                            repo = g.get_repo(github_pkey.git_project)
                            repo.create_label(name="security", color="FF0000",
                                              description=description)
                            repo.create_label(name="security / info", color="00FEFC",
                                              description=description)
                            repo.create_label(name="security / low", color="B7FE00",
                                              description=description)
                            repo.create_label(name="security / medium", color="FEFE00",
                                              description=description)
                            repo.create_label(name="security / high", color="FE9A00",
                                              description=description)
                            repo.create_label(name="security / critical", color="FE2200",
                                              description=description)
                        except:
                            logger.info('Labels cannot be created - they may already exists')

            create_notification(event='debt_context_added', title=debt_context.name,
                                debt_context=debt_context,
                                url=reverse('view_debt_context', args=(debt_context.id,)))

            if not error:
                return HttpResponseRedirect(reverse('view_debt_context', args=(debt_context.id,)))
            else:
                # debt_engagement was saved, but JIRA errors, so goto edit_debt_context
                return HttpResponseRedirect(reverse('edit_debt_context', args=(debt_context.id,)))
    else:
        if get_system_setting('enable_jira'):
            jira_project_form = DebtJIRAProjectForm()

        if get_system_setting('enable_github'):
            gform = GITHUB_Debt_Context_Form()
        else:
            gform = None

    add_breadcrumb(title=_("New Debt Context"), top_level=False, request=request)
    return render(request, 'dojo/debt_new_debt_context.html',
                  {'form': form,
                   'jform': jira_project_form,
                   'gform': gform})


@user_is_authorized(Debt_Context, Permissions.Debt_Context_Edit, 'pid')
def edit_debt_context(request, pid):
    debt_context = Debt_Context.objects.get(pk=pid)
    system_settings = System_Settings.objects.get()
    jira_enabled = system_settings.enable_jira
    jira_project = None
    jform = None
    github_enabled = system_settings.enable_github
    github_inst = None
    gform = None
    error = False

    try:
        github_inst = GITHUB_PKey.objects.get(debt_context=debt_context)
    except:
        github_inst = None
        pass

    if request.method == 'POST':
        form = DebtContextForm(request.POST, instance=debt_context)
        jira_project = jira_helper.get_jira_project(debt_context)
        if form.is_valid():
            form.save()
            tags = request.POST.getlist('tags')
            messages.add_message(request,
                                 messages.SUCCESS,
                                 _('debt_context updated successfully.'),
                                 extra_tags='alert-success')

            success, jform = jira_helper.debt_process_jira_project_form(request, instance=jira_project, debt_context=debt_context)
            error = not success

            if get_system_setting('enable_github') and github_inst:
                gform = GITHUB_Debt_Context_Form(request.POST, instance=github_inst)
                # need to handle delete
                try:
                    gform.save()
                except:
                    pass
            elif get_system_setting('enable_github'):
                gform = GITHUB_Debt_Context_Form(request.POST)
                if gform.is_valid():
                    new_conf = gform.save(commit=False)
                    new_conf.debt_context_id = pid
                    new_conf.save()
                    messages.add_message(request,
                                         messages.SUCCESS,
                                         _('GITHUB information updated successfully.'),
                                         extra_tags='alert-success')

            if not error:
                return HttpResponseRedirect(reverse('view_debt_context', args=(pid,)))
    else:
        form = DebtContextForm(instance=debt_context)

        if jira_enabled:
            jira_project = jira_helper.get_jira_project(debt_context)
            jform = DebtJIRAProjectForm(instance=jira_project)
        else:
            jform = None

        if github_enabled:
            if github_inst is not None:
                gform = GITHUB_Debt_Context_Form(instance=github_inst)
            else:
                gform = GITHUB_Debt_Context_Form()
        else:
            gform = None

    debt_context_tab = Debt_Context_Tab(debt_context, title=_("Edit Debt Context"), tab="settings")
    return render(request,
                  'dojo/debt_edit_debt_context.html',
                  {'form': form,
                   'debt_context_tab': debt_context_tab,
                   'jform': jform,
                   'gform': gform,
                   'debt_context': debt_context
                   })


@user_is_authorized(Debt_Context, Permissions.Debt_Context_Delete, 'pid')
def delete_debt_context(request, pid):
    debt_context = get_object_or_404(Debt_Context, pk=pid)
    form = DeleteDebtContextForm(instance=debt_context)

    if request.method == 'POST':
        logger.debug('delete_debt_context: POST')
        if 'id' in request.POST and str(debt_context.id) == request.POST['id']:
            form = DeleteDebtContextForm(request.POST, instance=debt_context)
            if form.is_valid():
                debt_context_type = debt_context.debt_context_type
                if get_setting("ASYNC_OBJECT_DELETE"):
                    async_del = async_delete()
                    async_del.delete(debt_context)
                    message = _('debt_context and relationships will be removed in the background.')
                else:
                    message = _('debt_context and relationships removed.')
                    debt_context.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     message,
                                     extra_tags='alert-success')
                create_notification(event='other',
                                    title=_('Deletion of %(name)s') % {'name': debt_context.name},
                                    debt_context_type=debt_context_type,
                                    description=_('The debt_context "%(name)s" was deleted by %(user)s') % {
                                        'name': debt_context.name, 'user': request.user},
                                    url=reverse('debt_context'),
                                    icon="exclamation-triangle")
                logger.debug('delete_debt_context: POST RETURN')
                return HttpResponseRedirect(reverse('debt_context'))
            else:
                logger.debug('delete_debt_context: POST INVALID FORM')
                logger.error(form.errors)

    logger.debug('delete_debt_context: GET')

    rels = ['Previewing the relationships has been disabled.', '']
    display_preview = get_setting('DELETE_PREVIEW')
    if display_preview:
        collector = NestedObjects(using=DEFAULT_DB_ALIAS)
        collector.collect([debt_context])
        rels = collector.nested()

    debt_context_tab = Debt_Context_Tab(debt_context, title=_("Debt Context"), tab="settings")

    logger.debug('delete_debt_context: GET RENDER')

    return render(request, 'dojo/debt_delete_debt_context.html', {
        'debt_context': debt_context,
        'form': form,
        'debt_context_tab': debt_context_tab,
        'rels': rels})


@user_is_authorized(Debt_Context, Permissions.Engagement_Add, 'pid')
def new_eng_for_app(request, pid, cicd=False):
    jira_project = None
    jira_project_form = None
    jira_epic_form = None

    debt_context = Debt_Context.objects.get(id=pid)
    jira_error = False

    if request.method == 'POST':
        form = DebtEngForm(request.POST, cicd=cicd, debt_context=debt_context, user=request.user)
        jira_project = jira_helper.get_jira_project(debt_context)
        logger.debug('new_eng_for_app')

        if form.is_valid():
            # first create the new debt_engagement
            debt_engagement = form.save(commit=False)
            debt_engagement.threat_model = False
            debt_engagement.api_test = False
            debt_engagement.pen_test = False
            debt_engagement.check_list = False
            debt_engagement.debt_context = form.cleaned_data.get('debt_context')
            if debt_engagement.threat_model:
                debt_engagement.progress = 'threat_model'
            else:
                debt_engagement.progress = 'other'
            if cicd:
                debt_engagement.debt_engagement_type = 'CI/CD'
                debt_engagement.status = "In Progress"
            debt_engagement.active = True

            debt_engagement.save()
            form.save_m2m()

            logger.debug('new_eng_for_app: process jira coming')

            # new debt_engagement, so do not provide jira_project
            success, jira_project_form = jira_helper.debt_process_jira_project_form(request, instance=None,
                                                                               debt_engagement=debt_engagement)
            error = not success

            logger.debug('new_eng_for_app: process jira epic coming')

            success, jira_epic_form = jira_helper.debt_process_jira_epic_form(request, debt_engagement=debt_engagement)
            error = error or not success

            messages.add_message(request,
                                 messages.SUCCESS,
                                 _('Debt_Engagement added successfully.'),
                                 extra_tags='alert-success')

            if not error:
                if "_Add Tests" in request.POST:
                    return HttpResponseRedirect(reverse('add_tests', args=(debt_engagement.id,)))
                elif "_Import Scan Results" in request.POST:
                    return HttpResponseRedirect(reverse('import_scan_results', args=(debt_engagement.id,)))
                else:
                    return HttpResponseRedirect(reverse('view_debt_engagement', args=(debt_engagement.id,)))
            else:
                # debt_engagement was saved, but JIRA errors, so goto edit_debt_engagement
                logger.debug('new_eng_for_app: jira errors')
                return HttpResponseRedirect(reverse('edit_debt_engagement', args=(debt_engagement.id,)))
        else:
            logger.debug(form.errors)
    else:
        form = DebtEngForm(initial={'lead': request.user, 'target_start': timezone.now().date(),
                                'target_end': timezone.now().date() + timedelta(days=7), 'debt_context': debt_context}, cicd=cicd,
                       debt_context=debt_context, user=request.user)

        if get_system_setting('enable_jira'):
            jira_project = jira_helper.get_jira_project(debt_context)
            logger.debug('showing jira-project-form')
            jira_project_form = DebtJIRAProjectForm(target='debt_engagement', debt_context=debt_context)
            logger.debug('showing jira-epic-form')
            jira_epic_form = JIRAEngagementForm()

    if cicd:
        title = _('New CI/CD Debt_Engagement')
    else:
        title = _('New Interactive Debt_Engagement')

    debt_context_tab = Debt_Context_Tab(debt_context, title=title, tab="debt_engagements")
    return render(request, 'dojo/new_eng.html', {
        'form': form,
        'title': title,
        'debt_context_tab': debt_context_tab,
        'jira_epic_form': jira_epic_form,
        'jira_project_form': jira_project_form})


@user_is_authorized(Debt_Context, Permissions.Technology_Add, 'pid')
def new_tech_for_debt_context(request, pid):
    if request.method == 'POST':
        form = AppAnalysisForm(request.POST)
        if form.is_valid():
            tech = form.save(commit=False)
            tech.debt_context_id = pid
            tech.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 _('Technology added successfully.'),
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_debt_context', args=(pid,)))

    form = AppAnalysisForm(initial={'user': request.user})
    debt_context_tab = Debt_Context_Tab(get_object_or_404(Debt_Context, id=pid), title=_("Add Technology"), tab="settings")
    return render(request, 'dojo/new_tech.html',
                  {'form': form,
                   'debt_context_tab': debt_context_tab,
                   'pid': pid})


@user_is_authorized(Debt_App_Analysis, Permissions.Technology_Edit, 'tid')
def edit_technology(request, tid):
    technology = get_object_or_404(Debt_App_Analysis, id=tid)
    form = AppAnalysisForm(instance=technology)
    if request.method == 'POST':
        form = AppAnalysisForm(request.POST, instance=technology)
        if form.is_valid():
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 _('Technology changed successfully.'),
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_debt_context', args=(technology.debt_context.id,)))

    debt_context_tab = Debt_Context_Tab(technology.debt_context, title=_("Edit Technology"), tab="settings")
    return render(request, 'dojo/edit_technology.html',
                  {'form': form,
                   'debt_context_tab': debt_context_tab,
                   'technology': technology})


@user_is_authorized(Debt_App_Analysis, Permissions.Technology_Delete, 'tid')
def delete_technology(request, tid):
    technology = get_object_or_404(Debt_App_Analysis, id=tid)
    form = DeleteAppAnalysisForm(instance=technology)
    if request.method == 'POST':
        form = Delete_Debt_Context_MemberForm(request.POST, instance=technology)
        technology = form.instance
        technology.delete()
        messages.add_message(request,
                             messages.SUCCESS,
                             _('Technology deleted successfully.'),
                             extra_tags='alert-success')
        return HttpResponseRedirect(reverse('view_debt_context', args=(technology.debt_context.id,)))

    debt_context_tab = Debt_Context_Tab(technology.debt_context, title=_("Delete Technology"), tab="settings")
    return render(request, 'dojo/delete_technology.html', {
        'technology': technology,
        'form': form,
        'debt_context_tab': debt_context_tab,
    })


@user_is_authorized(Debt_Context, Permissions.Engagement_Add, 'pid')
def new_eng_for_app_cicd(request, pid):
    # we have to use pid=pid here as new_eng_for_app expects kwargs, because that is how django calls the function based on urls.py named groups
    return new_eng_for_app(request, pid=pid, cicd=True)


@user_is_authorized(Debt_Context, Permissions.Debt_Context_Edit, 'pid')
def add_meta_data(request, pid):
    debt_context = Debt_Context.objects.get(id=pid)
    if request.method == 'POST':
        form = DojoMetaDataForm(request.POST, instance=DojoMeta(debt_context=debt_context))
        if form.is_valid():
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 _('Metadata added successfully.'),
                                 extra_tags='alert-success')
            if 'add_another' in request.POST:
                return HttpResponseRedirect(reverse('add_meta_data', args=(pid,)))
            else:
                return HttpResponseRedirect(reverse('view_debt_context', args=(pid,)))
    else:
        form = DojoMetaDataForm()

    debt_context_tab = Debt_Context_Tab(debt_context, title=_("Add Metadata"), tab="settings")

    return render(request, 'dojo/add_debt_context_meta_data.html',
                  {'form': form,
                   'debt_context_tab': debt_context_tab,
                   'debt_context': debt_context,
                   })


@user_is_authorized(Debt_Context, Permissions.Debt_Context_Edit, 'pid')
def edit_meta_data(request, pid):
    debt_context = Debt_Context.objects.get(id=pid)
    if request.method == 'POST':
        for key, value in request.POST.items():
            if key.startswith('cfv_'):
                cfv_id = int(key.split('_')[1])
                cfv = get_object_or_404(DojoMeta, id=cfv_id)
                value = value.strip()
                if value:
                    cfv.value = value
                    cfv.save()
            if key.startswith('delete_'):
                cfv_id = int(key.split('_')[2])
                cfv = get_object_or_404(DojoMeta, id=cfv_id)
                cfv.delete()

        messages.add_message(request,
                             messages.SUCCESS,
                             _('Metadata edited successfully.'),
                             extra_tags='alert-success')
        return HttpResponseRedirect(reverse('view_debt_context', args=(pid,)))

    debt_context_tab = Debt_Context_Tab(debt_context, title=_("Edit Metadata"), tab="settings")
    return render(request, 'dojo/edit_debt_context_meta_data.html',
                  {'debt_context': debt_context,
                   'debt_context_tab': debt_context_tab,
                   })


class AdHocDebtItemView(View):
    def get_debt_context(self, debt_context_id: int):
        return get_object_or_404(Debt_Context, id=debt_context_id)

    def get_debt_test_type(self):
        debt_test_type, nil = Debt_Test_Type.objects.get_or_create(name=_("Pen Test"))
        return debt_test_type

    def get_debt_engagement(self, debt_context: debt_context):
        try:
            return Debt_Engagement.objects.get(debt_context=debt_context, name=_("Ad Hoc Debt Engagement"))
        except Debt_Engagement.DoesNotExist:
            return Debt_Engagement.objects.create(
                name=_("Ad Hoc Debt Engagement"),
                target_start=timezone.now(),
                target_end=timezone.now(),
                active=False, debt_context=debt_context)

    def get_debt_test(self, debt_engagement: Debt_Engagement, debt_test_type: Debt_Test_Type):
        if debt_test := Debt_Test.objects.filter(debt_engagement=debt_engagement).first():
            return debt_test
        else:
            return Debt_Test.objects.create(
                debt_engagement=debt_engagement,
                debt_test_type=debt_test_type,
                target_start=timezone.now(),
                target_end=timezone.now())

    def create_nested_objects(self, debt_context: debt_context):
        debt_engagement = self.get_debt_engagement(debt_context)
        debt_test_type = self.get_debt_test_type()
        return self.get_debt_test(debt_engagement, debt_test_type)

    def get_initial_context(self, request: HttpRequest, debt_test: Debt_Test):
        # Get the debt_item form first since it is used in another place
        debt_item_form = self.get_debt_item_form(request, debt_test.debt_engagement.debt_context)
        debt_context_tab = Debt_Context_Tab(debt_test.debt_engagement.debt_context, title=_("Add Debt_Item"), tab="debt_engagements")
        debt_context_tab.setDebtEngagement(debt_test.debt_engagement)
        return {
            "form": debt_item_form,
            "debt_context_tab": debt_context_tab,
            "temp": False,
            "tid": debt_test.id,
            "pid": debt_test.debt_engagement.debt_context.id,
            "form_error": False,
            "jform": self.get_jira_form(request, debt_test, debt_item_form=debt_item_form),
            "gform": self.get_github_form(request, debt_test),
        }

    def get_debt_item_form(self, request: HttpRequest, debt_context: debt_context):
        # Set up the args for the form
        args = [request.POST] if request.method == "POST" else []
        # Set the initial form args
        kwargs = {
            "initial": {'date': timezone.now().date()},
            "req_resp": None,
            "debt_context": debt_context,
        }
        # Remove the initial state on post
        if request.method == "POST":
            kwargs.pop("initial")

        return AdHocDebtItemForm(*args, **kwargs)

    def get_jira_form(self, request: HttpRequest, debt_test: Debt_Test, debt_item_form: AdHocDebtItemForm = None):
        # Determine if jira should be used
        if (jira_project := jira_helper.get_jira_project(debt_test)) is not None:
            # Set up the args for the form
            args = [request.POST] if request.method == "POST" else []
            # Set the initial form args
            kwargs = {
                "push_all": jira_helper.is_push_all_issues(debt_test),
                "prefix": "jiraform",
                "jira_project": jira_project,
                "debt_item_form": debt_item_form,
            }

            return JIRADebtItemForm(*args, **kwargs)
        return None

    def get_github_form(self, request: HttpRequest, debt_test: Debt_Test):
        # Determine if github should be used
        if get_system_setting("enable_github"):
            # Ensure there is a github conf correctly configured for the debt_context
            config_present = GITHUB_PKey.objects.filter(debt_context=debt_test.debt_engagement.debt_context)
            if config_present := config_present.exclude(git_conf_id=None):
                # Set up the args for the form
                args = [request.POST] if request.method == "POST" else []
                # Set the initial form args
                kwargs = {
                    "enabled": jira_helper.is_push_all_issues(debt_test),
                    "prefix": "githubform"
                }

                return GITHUBDebtItemForm(*args, **kwargs)
        return None

    def validate_status_change(self, request: HttpRequest, context: dict):
        if ((context["form"]['active'].value() is False or
             context["form"]['false_p'].value()) and
             context["form"]['duplicate'].value() is False):

            closing_disabled = Note_Type.objects.filter(is_mandatory=True, is_active=True).count()
            if closing_disabled != 0:
                error_inactive = ValidationError(
                    _('Can not set a debt item as inactive without adding all mandatory notes'),
                    code='inactive_without_mandatory_notes'
                )
                error_false_p = ValidationError(
                    _('Can not set a debt item as false positive without adding all mandatory notes'),
                    code='false_p_without_mandatory_notes'
                )
                if context["form"]['active'].value() is False:
                    context["form"].add_error('active', error_inactive)
                if context["form"]['false_p'].value():
                    context["form"].add_error('false_p', error_false_p)
                messages.add_message(
                    request,
                    messages.ERROR,
                    _('Can not set a debt item as inactive or false positive without adding all mandatory notes'),
                    extra_tags='alert-danger')

        return request

    def process_debt_item_form(self, request: HttpRequest, debt_test: Debt_Test, context: dict):
        debt_item = None
        if context["form"].is_valid():
            debt_item = context["form"].save(commit=False)
            debt_item.debt_test = debt_test
            debt_item.reporter = request.user
            debt_item.numerical_severity = Debt_Item.get_numerical_severity(debt_item.severity)
            debt_item.tags = context["form"].cleaned_data['tags']
            debt_item.save()
            # Save and add new endpoints
            debt_item_helper.add_debt_endpoints(debt_item, context["form"])
            # Save the debt_item at the end and return
            debt_item.save()

            return debt_item, request, True
        else:
            add_error_message_to_response("The form has errors, please correct them below.")
            add_field_errors_to_response(context["form"])

        return debt_item, request, False

    def process_jira_form(self, request: HttpRequest, debt_item: Debt_Item, context: dict):
        # Capture case if the jira not being enabled
        if context["jform"] is None:
            return request, True, False

        if context["jform"] and context["jform"].is_valid():
            # Push to Jira?
            logger.debug('jira form valid')
            push_to_jira = jira_helper.is_push_all_issues(debt_item) or context["jform"].cleaned_data.get('push_to_jira')
            jira_message = None
            # if the jira issue key was changed, update database
            new_jira_issue_key = context["jform"].cleaned_data.get('jira_issue')
            if debt_item.has_jira_issue:
                jira_issue = debt_item.jira_issue
                # everything in DD around JIRA integration is based on the internal id of the issue in JIRA
                # instead of on the public jira issue key.
                # I have no idea why, but it means we have to retrieve the issue from JIRA to get the internal JIRA id.
                # we can assume the issue exist, which is already checked in the validation of the jform
                if not new_jira_issue_key:
                    jira_helper.debt_item_unlink_jira(request, debt_item)
                    jira_message = 'Link to JIRA issue removed successfully.'

                elif new_jira_issue_key != debt_item.jira_issue.jira_key:
                    jira_helper.debt_item_unlink_jira(request, debt_item)
                    jira_helper.debt_item_link_jira(request, debt_item, new_jira_issue_key)
                    jira_message = 'Changed JIRA link successfully.'
            else:
                logger.debug('debt_item has no jira issue yet')
                if new_jira_issue_key:
                    logger.debug(
                        'debt_item has no jira issue yet, but jira issue specified in request. trying to link.')
                    jira_helper.debt_item_link_jira(request, debt_item, new_jira_issue_key)
                    jira_message = 'Linked a JIRA issue successfully.'
            # Determine if a message should be added
            if jira_message:
                messages.add_message(
                    request, messages.SUCCESS, jira_message, extra_tags="alert-success"
                )

            return request, True, push_to_jira
        else:
            add_field_errors_to_response(context["jform"])

        return request, False, False

    def process_github_form(self, request: HttpRequest, debt_item: Debt_Item, context: dict):
        if "githubform-push_to_github" not in request.POST:
            return request, True

        if context["gform"].is_valid():
            add_external_issue(debt_item, 'github')

            return request, True
        else:
            add_field_errors_to_response(context["gform"])

        return request, False

    def process_forms(self, request: HttpRequest, debt_test: Debt_Test, context: dict):
        form_success_list = []
        # Set vars for the completed forms
        # Validate debt_item mitigation
        request = self.validate_status_change(request, context)
        # Check the validity of the form overall
        debt_item, request, success = self.process_debt_item_form(request, debt_test, context)
        form_success_list.append(success)
        request, success, push_to_jira = self.process_jira_form(request, debt_item, context)
        form_success_list.append(success)
        request, success = self.process_github_form(request, debt_item, context)
        form_success_list.append(success)
        # Determine if all forms were successful
        all_forms_valid = all(form_success_list)
        # Check the validity of all the forms
        if all_forms_valid:
            # if we're removing the "duplicate" in the edit debt_item screen
            debt_item_helper.save_vulnerability_ids(debt_item, context["form"].cleaned_data["vulnerability_ids"].split())
            # Push things to jira if needed
            debt_item.save(push_to_jira=push_to_jira)
            # Save the burp req resp
            #if "request" in context["form"].cleaned_data or "response" in context["form"].cleaned_data:
            #    burp_rr = BurpRawRequestResponse(
            #        debt_item=debt_item,
            #        burpRequestBase64=base64.b64encode(context["form"].cleaned_data["request"].encode()),
            #        burpResponseBase64=base64.b64encode(context["form"].cleaned_data["response"].encode()),
            #    )
            #    burp_rr.clean()
            #    burp_rr.save()

            # Add a success message
            messages.add_message(
                request,
                messages.SUCCESS,
                _('Debt Item added successfully.'),
                extra_tags='alert-success')

        return debt_item, request, all_forms_valid

    def get_template(self):
        return "dojo/debt_ad_hoc_debt_items.html"

    def get(self, request: HttpRequest, debt_context_id: int):
        # Get the initial objects
        debt_context = self.get_debt_context(debt_context_id)
        # Make sure the user is authorized
        user_has_permission_or_403(request.user, debt_context, Permissions.Debt_Item_Add)
        # Create the necessary nested objects
        debt_test = self.create_nested_objects(debt_context)
        # Set up the initial context
        context = self.get_initial_context(request, debt_test)
        # Render the form
        return render(request, self.get_template(), context)

    def post(self, request: HttpRequest, debt_context_id: int):
        # Get the initial objects
        debt_context = self.get_debt_context(debt_context_id)
        # Make sure the user is authorized
        user_has_permission_or_403(request.user, debt_context, Permissions.Debt_Item_Add)
        # Create the necessary nested objects
        debt_test = self.create_nested_objects(debt_context)
        # Set up the initial context
        context = self.get_initial_context(request, debt_test)
        # Process the form
        _, request, success = self.process_forms(request, debt_test, context)
        # Handle the case of a successful form
        if success:
            if '_Finished' in request.POST:
                return HttpResponseRedirect(reverse('view_debt_test', args=(debt_test.id,)))
            else:
                return HttpResponseRedirect(reverse('add_debt_items', args=(debt_test.id,)))
        else:
            context["form_error"] = True
        # Render the form
        return render(request, self.get_template(), context)


@user_is_authorized(Debt_Context, Permissions.Debt_Context_View, 'pid')
def debt_engagement_presets(request, pid):
    debt_context = get_object_or_404(Debt_Context, id=pid)
    presets = Engagement_Presets.objects.filter(debt_context=debt_context).all()

    debt_context_tab = Debt_Context_Tab(debt_context, title=_("Debt Engagement Presets"), tab="settings")

    return render(request, 'dojo/view_presets.html',
                  {'debt_context_tab': debt_context_tab,
                   'presets': presets,
                   'debt_context': debt_context})


@user_is_authorized(Debt_Context, Permissions.Debt_Context_Edit, 'pid')
def edit_debt_engagement_presets(request, pid, eid):
    debt_context = get_object_or_404(Debt_Context, id=pid)
    preset = get_object_or_404(Engagement_Presets, id=eid)

    debt_context_tab = Debt_Context_Tab(debt_context, title=_("Edit Debt Engagement Preset"), tab="settings")

    if request.method == 'POST':
        tform = EngagementPresetsForm(request.POST, instance=preset)
        if tform.is_valid():
            tform.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                _('Debt Engagement Preset Successfully Updated.'),
                extra_tags='alert-success')
            return HttpResponseRedirect(reverse('debt_engagement_presets', args=(pid,)))
    else:
        tform = EngagementPresetsForm(instance=preset)

    return render(request, 'dojo/edit_presets.html',
                  {'debt_context_tab': debt_context_tab,
                   'tform': tform,
                   'debt_context': debt_context})


@user_is_authorized(Debt_Context, Permissions.Debt_Context_Edit, 'pid')
def add_debt_engagement_presets(request, pid):
    debt_context = get_object_or_404(Debt_Context, id=pid)
    if request.method == 'POST':
        tform = EngagementPresetsForm(request.POST)
        if tform.is_valid():
            form_copy = tform.save(commit=False)
            form_copy.debt_context = debt_context
            form_copy.save()
            tform.save_m2m()
            messages.add_message(
                request,
                messages.SUCCESS,
                _('Debt Engagement Preset Successfully Created.'),
                extra_tags='alert-success')
            return HttpResponseRedirect(reverse('debt_engagement_presets', args=(pid,)))
    else:
        tform = EngagementPresetsForm()

    debt_context_tab = Debt_Context_Tab(debt_context, title=_("New Debt Engagement Preset"), tab="settings")
    return render(request, 'dojo/new_params.html', {'tform': tform, 'pid': pid, 'debt_context_tab': debt_context_tab})


@user_is_authorized(Debt_Context, Permissions.Debt_Context_Edit, 'pid')
def delete_debt_engagement_presets(request, pid, eid):
    debt_context = get_object_or_404(Debt_Context, id=pid)
    preset = get_object_or_404(Engagement_Presets, id=eid)
    form = DeleteEngagementPresetsForm(instance=preset)

    if request.method == 'POST':
        if 'id' in request.POST:
            form = DeleteEngagementPresetsForm(request.POST, instance=preset)
            if form.is_valid():
                preset.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     _('Debt Engagement presets and debt engagement relationships removed.'),
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('debt_engagement_presets', args=(pid,)))

    collector = NestedObjects(using=DEFAULT_DB_ALIAS)
    collector.collect([preset])
    rels = collector.nested()

    debt_context_tab = Debt_Context_Tab(debt_context, title=_("Delete Debt Engagement Preset"), tab="settings")
    return render(request, 'dojo/delete_presets.html',
                  {'debt_context': debt_context,
                   'form': form,
                   'debt_context_tab': debt_context_tab,
                   'rels': rels,
                   })


@user_is_authorized(Debt_Context, Permissions.Debt_Context_View, 'pid')
def edit_notifications(request, pid):
    debt_context = get_object_or_404(Debt_Context, id=pid)
    if request.method == 'POST':
        debt_context_notifications = Debt_Notifications.objects.filter(user=request.user).filter(debt_context=debt_context).first()
        if not debt_context_notifications:
            debt_context_notifications = Debt_Notifications(user=request.user, debt_context=debt_context)
            logger.debug('no existing debt_context notifications found')
        else:
            logger.debug('existing debt_context notifications found')

        form = DebtContextNotificationsForm(request.POST, instance=debt_context_notifications)
        # print(vars(form))

        if form.is_valid():
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 _('Notification settings updated.'),
                                 extra_tags='alert-success')

    return HttpResponseRedirect(reverse('view_debt_context', args=(pid,)))


@user_is_authorized(Debt_Context, Permissions.Debt_Context_Manage_Members, 'pid')
def add_debt_context_member(request, pid):
    debt_context = get_object_or_404(Debt_Context, pk=pid)
    memberform = Add_Debt_Context_MemberForm(initial={'debt_context': debt_context.id})
    if request.method == 'POST':
        memberform = Add_Debt_Context_MemberForm(request.POST, initial={'debt_context': debt_context.id})
        if memberform.is_valid():
            if memberform.cleaned_data['role'].is_owner and not user_has_permission(request.user, debt_context,
                                                                                    Permissions.Debt_Context_Member_Add_Owner):
                messages.add_message(request,
                                     messages.WARNING,
                                     _('You are not permitted to add users as owners.'),
                                     extra_tags='alert-warning')
            else:
                if 'users' in memberform.cleaned_data and len(memberform.cleaned_data['users']) > 0:
                    for user in memberform.cleaned_data['users']:
                        existing_members = Debt_Context_Member.objects.filter(debt_context=debt_context, user=user)
                        if existing_members.count() == 0:
                            debt_context_member = Debt_Context_Member()
                            debt_context_member.debt_context = debt_context
                            debt_context_member.user = user
                            debt_context_member.role = memberform.cleaned_data['role']
                            debt_context_member.save()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     _('debt_context members added successfully.'),
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('view_debt_context', args=(pid,)))
    debt_context_tab = Debt_Context_Tab(Debt_Context, title=_("Add Debt Context Member"), tab="settings")
    return render(request, 'dojo/new_debt_context_member.html', {
        'debt_context': debt_context,
        'form': memberform,
        'debt_context_tab': debt_context_tab,
    })


@user_is_authorized(Debt_Context_Member, Permissions.Debt_Context_Manage_Members, 'memberid')
def edit_debt_context_member(request, memberid):
    member = get_object_or_404(Debt_Context_Member, pk=memberid)
    memberform = Edit_Debt_Context_MemberForm(instance=member)
    if request.method == 'POST':
        memberform = Edit_Debt_Context_MemberForm(request.POST, instance=member)
        if memberform.is_valid():
            if member.role.is_owner and not user_has_permission(request.user, member.debt_context,
                                                                Permissions.Debt_Context_Member_Add_Owner):
                messages.add_message(request,
                                     messages.WARNING,
                                     _('You are not permitted to make users to owners.'),
                                     extra_tags='alert-warning')
            else:
                memberform.save()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     _('debt_context member updated successfully.'),
                                     extra_tags='alert-success')
                if is_title_in_breadcrumbs('View User'):
                    return HttpResponseRedirect(reverse('view_user', args=(member.user.id,)))
                else:
                    return HttpResponseRedirect(reverse('view_debt_context', args=(member.debt_context.id,)))
    debt_context_tab = Debt_Context_Tab(member.debt_context, title=_("Edit Debt Context Member"), tab="settings")
    return render(request, 'dojo/edit_debt_context_member.html', {
        'memberid': memberid,
        'form': memberform,
        'debt_context_tab': debt_context_tab,
    })


@user_is_authorized(Debt_Context_Member, Permissions.Debt_Context_Member_Delete, 'memberid')
def delete_debt_context_member(request, memberid):
    member = get_object_or_404(Debt_Context_Member, pk=memberid)
    memberform = Delete_Debt_Context_MemberForm(instance=member)
    if request.method == 'POST':
        memberform = Delete_Debt_Context_MemberForm(request.POST, instance=member)
        member = memberform.instance
        user = member.user
        member.delete()
        messages.add_message(request,
                             messages.SUCCESS,
                             _('debt_context member deleted successfully.'),
                             extra_tags='alert-success')
        if is_title_in_breadcrumbs('View User'):
            return HttpResponseRedirect(reverse('view_user', args=(member.user.id,)))
        else:
            if user == request.user:
                return HttpResponseRedirect(reverse('debt_context'))
            else:
                return HttpResponseRedirect(reverse('view_debt_context', args=(member.debt_context.id,)))
    debt_context_tab = Debt_Context_Tab(member.debt_context, title=_("Delete Debt Context Member"), tab="settings")
    return render(request, 'dojo/delete_debt_context_member.html', {
        'memberid': memberid,
        'form': memberform,
        'debt_context_tab': debt_context_tab,
    })


@user_is_authorized(Debt_Context, Permissions.Debt_Context_API_Scan_Configuration_Add, 'pid')
def add_api_scan_configuration(request, pid):
    debt_context = get_object_or_404(Debt_Context, id=pid)
    if request.method == 'POST':
        form = Debt_Context_API_Scan_ConfigurationForm(request.POST)
        if form.is_valid():
            debt_context_api_scan_configuration = form.save(commit=False)
            debt_context_api_scan_configuration.debt_context = debt_context
            try:
                api = create_API(debt_context_api_scan_configuration.tool_configuration)
                if api and hasattr(api, 'test_debt_context_connection'):
                    result = api.test_debt_context_connection(debt_context_api_scan_configuration)
                    messages.add_message(request,
                                         messages.SUCCESS,
                                         _('API connection successful with message: %(result)s.') % {'result': result},
                                         extra_tags='alert-success')
                debt_context_api_scan_configuration.save()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     _('API Scan Configuration added successfully.'),
                                     extra_tags='alert-success')
                if 'add_another' in request.POST:
                    return HttpResponseRedirect(reverse('add_api_scan_configuration', args=(pid,)))
                else:
                    return HttpResponseRedirect(reverse('view_api_scan_configurations', args=(pid,)))
            except Exception as e:
                logger.exception(e)
                messages.add_message(request,
                                     messages.ERROR,
                                     str(e),
                                     extra_tags='alert-danger')
    else:
        form = Debt_Context_API_Scan_ConfigurationForm()

    debt_context_tab = Debt_Context_Tab(Debt_Context, title=_("Add API Scan Configuration"), tab="settings")

    return render(request,
                  'dojo/add_debt_context_api_scan_configuration.html',
                  {'form': form,
                   'debt_context_tab': debt_context_tab,
                   'debt_context': debt_context,
                   'api_scan_configuration_hints': get_api_scan_configuration_hints(),
                   })


@user_is_authorized(Debt_Context, Permissions.Debt_Context_View, 'pid')
def view_api_scan_configurations(request, pid):
    debt_context_api_scan_configurations = Debt_Context_API_Scan_Configuration.objects.filter(debt_context=pid)

    debt_context_tab = Debt_Context_Tab(get_object_or_404(Debt_Context, id=pid), title=_("API Scan Configurations"), tab="settings")
    return render(request,
                  'dojo/view_debt_context_api_scan_configurations.html',
                  {
                      'debt_context_api_scan_configurations': debt_context_api_scan_configurations,
                      'debt_context_tab': debt_context_tab,
                      'pid': pid
                  })


@user_is_authorized(Debt_Context_API_Scan_Configuration, Permissions.Debt_Context_API_Scan_Configuration_Edit, 'pascid')
def edit_api_scan_configuration(request, pid, pascid):
    debt_context_api_scan_configuration = get_object_or_404(Debt_Context_API_Scan_Configuration, id=pascid)

    if debt_context_api_scan_configuration.debt_context.pk != int(
            pid):  # user is trying to edit Tool Configuration from another debt_context (trying to by-pass auth)
        raise Http404()

    if request.method == 'POST':
        form = Debt_Context_API_Scan_ConfigurationForm(request.POST, instance=debt_context_api_scan_configuration)
        if form.is_valid():
            try:
                form_copy = form.save(commit=False)
                api = create_API(form_copy.tool_configuration)
                if api and hasattr(api, 'test_debt_context_connection'):
                    result = api.test_debt_context_connection(form_copy)
                    messages.add_message(request,
                                         messages.SUCCESS,
                                         _('API connection successful with message: %(result)s.') % {'result': result},
                                         extra_tags='alert-success')
                form.save()

                messages.add_message(request,
                                     messages.SUCCESS,
                                     _('API Scan Configuration successfully updated.'),
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('view_api_scan_configurations', args=(pid,)))
            except Exception as e:
                logger.info(e)
                messages.add_message(request,
                                     messages.ERROR,
                                     str(e),
                                     extra_tags='alert-danger')
    else:
        form = Debt_Context_API_Scan_ConfigurationForm(instance=debt_context_api_scan_configuration)

    debt_context_tab = Debt_Context_Tab(get_object_or_404(Debt_Context, id=pid), title=_("Edit API Scan Configuration"), tab="settings")
    return render(request,
                  'dojo/edit_debt_context_api_scan_configuration.html',
                  {
                      'form': form,
                      'debt_context_tab': debt_context_tab,
                      'api_scan_configuration_hints': get_api_scan_configuration_hints(),
                  })


@user_is_authorized(Debt_Context_API_Scan_Configuration, Permissions.Debt_Context_API_Scan_Configuration_Delete, 'pascid')
def delete_api_scan_configuration(request, pid, pascid):
    debt_context_api_scan_configuration = get_object_or_404(Debt_Context_API_Scan_Configuration, id=pascid)

    if debt_context_api_scan_configuration.debt_context.pk != int(
            pid):  # user is trying to delete Tool Configuration from another debt_context (trying to by-pass auth)
        raise Http404()

    if request.method == 'POST':
        form = Debt_Context_API_Scan_ConfigurationForm(request.POST)
        debt_context_api_scan_configuration.delete()
        messages.add_message(request,
                             messages.SUCCESS,
                             _('API Scan Configuration deleted.'),
                             extra_tags='alert-success')
        return HttpResponseRedirect(reverse('view_api_scan_configurations', args=(pid,)))
    else:
        form = DeleteDebt_Context_API_Scan_ConfigurationForm(instance=debt_context_api_scan_configuration)

    debt_context_tab = Debt_Context_Tab(get_object_or_404(Debt_Context, id=pid), title=_("Delete Tool Configuration"), tab="settings")
    return render(request,
                  'dojo/delete_debt_context_api_scan_configuration.html',
                  {
                      'form': form,
                      'debt_context_tab': debt_context_tab
                  })


@user_is_authorized(Debt_Context_Group, Permissions.Debt_Context_Group_Edit, 'groupid')
def edit_debt_context_group(request, groupid):
    logger.exception(groupid)
    group = get_object_or_404(Debt_Context_Group, pk=groupid)
    groupform = Edit_Debt_Context_Group_Form(instance=group)

    if request.method == 'POST':
        groupform = Edit_Debt_Context_Group_Form(request.POST, instance=group)
        if groupform.is_valid():
            if group.role.is_owner and not user_has_permission(request.user, group.debt_context,
                                                               Permissions.Debt_Context_Group_Add_Owner):
                messages.add_message(request,
                                     messages.WARNING,
                                     _('You are not permitted to make groups owners.'),
                                     extra_tags='alert-warning')
            else:
                groupform.save()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     _('debt_context group updated successfully.'),
                                     extra_tags='alert-success')
                if is_title_in_breadcrumbs('View Group'):
                    return HttpResponseRedirect(reverse('view_group', args=(group.group.id,)))
                else:
                    return HttpResponseRedirect(reverse('view_debt_context', args=(group.debt_context.id,)))

    debt_context_tab = Debt_Context_Tab(group.debt_context, title=_("Edit Debt Context Group"), tab="settings")
    return render(request, 'dojo/edit_debt_context_group.html', {
        'groupid': groupid,
        'form': groupform,
        'debt_context_tab': debt_context_tab,
    })


@user_is_authorized(Debt_Context_Group, Permissions.Debt_Context_Group_Delete, 'groupid')
def delete_debt_context_group(request, groupid):
    group = get_object_or_404(Debt_Context_Group, pk=groupid)
    groupform = Delete_Debt_Context_GroupForm(instance=group)

    if request.method == 'POST':
        groupform = Delete_Debt_Context_GroupForm(request.POST, instance=group)
        group = groupform.instance
        group.delete()
        messages.add_message(request,
                             messages.SUCCESS,
                             _('debt_context group deleted successfully.'),
                             extra_tags='alert-success')
        if is_title_in_breadcrumbs('View Group'):
            return HttpResponseRedirect(reverse('view_group', args=(group.group.id,)))
        else:
            # TODO: If user was in the group that was deleted and no longer has access, redirect back to debt_context listing
            #  page
            return HttpResponseRedirect(reverse('view_debt_context', args=(group.debt_context.id,)))

    debt_context_tab = Debt_Context_Tab(group.debt_context, title=_("Delete Debt Context Group"), tab="settings")
    return render(request, 'dojo/delete_debt_context_group.html', {
        'groupid': groupid,
        'form': groupform,
        'debt_context_tab': debt_context_tab,
    })


@user_is_authorized(Debt_Context, Permissions.Debt_Context_Group_Add, 'pid')
def add_debt_context_group(request, pid):
    debt_context = get_object_or_404(Debt_Context, pk=pid)
    group_form = Add_Debt_Context_GroupForm(initial={'debt_context': debt_context.id})

    if request.method == 'POST':
        group_form = Add_Debt_Context_GroupForm(request.POST, initial={'debt_context': debt_context.id})
        if group_form.is_valid():
            if group_form.cleaned_data['role'].is_owner and not user_has_permission(request.user, debt_context,
                                                                                    Permissions.Debt_Context_Group_Add_Owner):
                messages.add_message(request,
                                     messages.WARNING,
                                     _('You are not permitted to add groups as owners.'),
                                     extra_tags='alert-warning')
            else:
                if 'groups' in group_form.cleaned_data and len(group_form.cleaned_data['groups']) > 0:
                    for group in group_form.cleaned_data['groups']:
                        groups = Debt_Context_Group.objects.filter(debt_context=debt_context, group=group)
                        if groups.count() == 0:
                            debt_context_group = Debt_Context_Group()
                            debt_context_group.debt_context = debt_context
                            debt_context_group.group = group
                            debt_context_group.role = group_form.cleaned_data['role']
                            debt_context_group.save()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     _('debt_context groups added successfully.'),
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('view_debt_context', args=(pid,)))
    debt_context_tab = Debt_Context_Tab(Debt_Context, title=_("Edit Debt Context Group"), tab="settings")
    return render(request, 'dojo/new_debt_context_group.html', {
        'debt_context': debt_context,
        'form': group_form,
        'debt_context_tab': debt_context_tab,
    })
