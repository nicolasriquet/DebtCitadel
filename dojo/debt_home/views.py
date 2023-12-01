from collections import defaultdict
from datetime import timedelta
from typing import Dict

from dateutil.relativedelta import relativedelta

from django.urls import reverse
from django.http import HttpResponseRedirect, HttpResponse, HttpRequest
from django.shortcuts import render
from django.utils import timezone

from django.db.models import Count, Q
from dojo.utils import add_breadcrumb, get_punchcard_data
from dojo.models import Debt_Answered_Survey
from dojo.authorization.roles_permissions import Permissions
from dojo.debt_engagement.queries import get_authorized_debt_engagements
from dojo.debt_item.queries import get_authorized_debt_items
from dojo.authorization.authorization import user_has_configuration_permission


def home(request: HttpRequest) -> HttpResponse:
    return HttpResponseRedirect(reverse('debt_dashboard'))


def debt_dashboard(request: HttpRequest) -> HttpResponse:
    debt_engagements = get_authorized_debt_engagements(Permissions.Debt_Engagement_View).distinct()
    debt_items = get_authorized_debt_items(Permissions.Debt_Item_View).distinct()

    debt_items = debt_items.filter(duplicate=False)

    debt_engagement_count = debt_engagements.filter(active=True).count()

    today = timezone.now().date()

    date_range = [today - timedelta(days=6), today]  # 7 days (6 days plus today)
    debt_item_count = debt_items \
        .filter(created__date__range=date_range) \
        .count()
    mitigated_count = debt_items \
        .filter(mitigated__date__range=date_range) \
        .count()
    accepted_count = debt_items \
        .filter(debt_risk_acceptance__created__date__range=date_range) \
        .count()

    severity_count_all = get_severities_all(debt_items)
    severity_count_by_month = get_severities_by_month(debt_items, today)
    punchcard, ticks = get_punchcard_data(debt_items, today - relativedelta(weeks=26), 26)

    if user_has_configuration_permission(request.user, 'dojo.view_debt_engagement_survey'):
        unassigned_surveys = Debt_Answered_Survey.objects.filter(assignee_id__isnull=True, completed__gt=0, ) \
            .filter(Q(debt_engagement__isnull=True) | Q(debt_engagement__in=debt_engagements))
    else:
        unassigned_surveys = None

    add_breadcrumb(request=request, clear=True)
    return render(request, 'dojo/debt_dashboard.html', {
        'debt_engagement_count': debt_engagement_count,
        'debt_item_count': debt_item_count,
        'mitigated_count': mitigated_count,
        'accepted_count': accepted_count,
        'critical': severity_count_all['Critical'],
        'high': severity_count_all['High'],
        'medium': severity_count_all['Medium'],
        'low': severity_count_all['Low'],
        'info': severity_count_all['Info'],
        'by_month': severity_count_by_month,
        'punchcard': punchcard,
        'ticks': ticks,
        'surveys': unassigned_surveys,
    })


def support(request: HttpRequest) -> HttpResponse:
    add_breadcrumb(title="Support", top_level=not len(request.GET), request=request)
    return render(request, 'dojo/debt_support.html', {})


def get_severities_all(debt_items) -> Dict[str, int]:
    severities_all = debt_items.values('severity').annotate(count=Count('severity')).order_by()
    return defaultdict(lambda: 0, {s['severity']: s['count'] for s in severities_all})


def get_severities_by_month(debt_items, today):
    severities_by_month = debt_items\
        .filter(created__date__gte=(today - relativedelta(months=6)))\
        .values('created__year', 'created__month', 'severity')\
        .annotate(count=Count('severity'))\
        .order_by()

    # The chart expects a, b, c, d, e instead of Critical, High, ...
    SEVERITY_MAP = {
        'Critical': 'a',
        'High':     'b',  # noqa: E241
        'Medium':   'c',  # noqa: E241
        'Low':      'd',  # noqa: E241
        'Info':     'e',  # noqa: E241
    }

    results = {}
    for ms in severities_by_month:
        key = f"{ms['created__year']}-{ms['created__month']:02}"
        month_stats = results.setdefault(key, {'y': key, 'a': 0, 'b': 0, 'c': 0, 'd': 0, 'e': 0, None: 0})
        month_stats[SEVERITY_MAP.get(ms['severity'])] += ms['count']

    return [v for k, v in sorted(results.items())]
