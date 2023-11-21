from django import template
from dojo.models import Debt_Endpoint_Status
from django.db.models import Q
register = template.Library()


@register.filter(name='has_debt_endpoints')
def has_debt_endpoints(debt_item):
    return True if debt_item.debt_endpoints.all() else False


@register.filter(name='get_vulnerable_debt_endpoints')
def get_vulnerable_debt_endpoints(debt_item):
    return debt_item.debt_endpoints.filter(
        status_debt_endpoint__mitigated=False,
        status_debt_endpoint__false_positive=False,
        status_debt_endpoint__out_of_scope=False,
        status_debt_endpoint__risk_accepted=False)


@register.filter(name='get_mitigated_debt_endpoints')
def get_mitigated_debt_endpoints(debt_item):
    return debt_item.debt_endpoints.filter(
        Q(status_debt_endpoint__mitigated=True) |
        Q(status_debt_endpoint__false_positive=True) |
        Q(status_debt_endpoint__out_of_scope=True) |
        Q(status_debt_endpoint__risk_accepted=True))


@register.filter
def debt_endpoint_display_status(debt_endpoint, debt_item):
    status = Debt_Endpoint_Status.objects.get(debt_endpoint=debt_endpoint, debt_item=debt_item)
    statuses = []
    if status.false_positive:
        statuses.append("False Positive")
    if status.risk_accepted:
        statuses.append("Risk Accepted")
    if status.out_of_scope:
        statuses.append("Out of Scope")
    if status.mitigated:
        statuses.append("Mitigated")
    if statuses:
        return ', '.join(statuses)
    else:
        return "Active"


@register.filter
def debt_endpoint_update_time(debt_endpoint, debt_item):
    status = Debt_Endpoint_Status.objects.get(debt_endpoint=debt_endpoint, debt_item=debt_item)
    return status.last_modified


@register.filter
def debt_endpoint_date(debt_endpoint, debt_item):
    status = Debt_Endpoint_Status.objects.get(debt_endpoint=debt_endpoint, debt_item=debt_item)
    return status.date


@register.filter
def debt_endpoint_mitigator(debt_endpoint, debt_item):
    status = Debt_Endpoint_Status.objects.get(debt_endpoint=debt_endpoint, debt_item=debt_item)
    return status.mitigated_by


@register.filter
def debt_endpoint_mitigated_time(debt_endpoint, debt_item):
    status = Debt_Endpoint_Status.objects.get(debt_endpoint=debt_endpoint, debt_item=debt_item)
    return status.mitigated_time
