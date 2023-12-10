from crum import get_current_user
from django.db.models import Exists, OuterRef, Q
from dojo.models import Debt_Engagement, Debt_Context_Member, Debt_Context_Type_Member, \
    Debt_Context_Group, Debt_Context_Type_Group
from dojo.authorization.authorization import get_roles_for_permission, user_has_global_permission


def get_authorized_debt_engagements(permission):
    user = get_current_user()

    if user is None:
        return Debt_Engagement.objects.none()

    if user.is_superuser:
        return Debt_Engagement.objects.all()

    if user_has_global_permission(user, permission):
        return Debt_Engagement.objects.all()

    roles = get_roles_for_permission(permission)
    authorized_debt_context_type_roles = Debt_Context_Type_Member.objects.filter(
        debt_context_type=OuterRef('debt_context__debt_context_type_id'),
        user=user,
        role__in=roles)
    authorized_debt_context_roles = Debt_Context_Member.objects.filter(
        debt_context=OuterRef('debt_context_id'),
        user=user,
        role__in=roles)
    authorized_debt_context_type_groups = Debt_Context_Type_Group.objects.filter(
        debt_context_type=OuterRef('debt_context__debt_context_type_id'),
        group__users=user,
        role__in=roles)
    authorized_debt_context_groups = Debt_Context_Group.objects.filter(
        debt_context=OuterRef('debt_context_id'),
        group__users=user,
        role__in=roles)
    debt_engagements = Debt_Engagement.objects.annotate(
        debt_context__debt_context_type__member=Exists(authorized_debt_context_type_roles),
        debt_context__member=Exists(authorized_debt_context_roles),
        debt_context__debt_context_type__authorized_group=Exists(authorized_debt_context_type_groups),
        debt_context__authorized_group=Exists(authorized_debt_context_groups))
    debt_engagements = debt_engagements.filter(
        Q(debt_context__debt_context_type__member=True) | Q(debt_context__member=True) |
        Q(debt_context__debt_context_type__authorized_group=True) | Q(debt_context__authorized_group=True))

    return debt_engagements
