from crum import get_current_user
from django.db.models import Exists, OuterRef, Q
from dojo.models import Tool_Debt_Context_Settings, Debt_Context_Member, Debt_Context_Type_Member, \
    Debt_Context_Group, Debt_Context_Type_Group
from dojo.authorization.authorization import get_roles_for_permission, user_has_global_permission


def get_authorized_tool_debt_context_settings(permission):
    user = get_current_user()

    if user is None:
        return Tool_Debt_Context_Settings.objects.none()

    if user.is_superuser:
        return Tool_Debt_Context_Settings.objects.all()

    if user_has_global_permission(user, permission):
        return Tool_Debt_Context_Settings.objects.all()

    roles = get_roles_for_permission(permission)
    authorized_debt_context_type_roles = Debt_Context_Type_Member.objects.filter(
        debt_context_type=OuterRef('debt_context__prod_type_id'),
        user=user,
        role__in=roles)
    authorized_debt_context_roles = Debt_Context_Member.objects.filter(
        debt_context=OuterRef('debt_context_id'),
        user=user,
        role__in=roles)
    authorized_debt_context_type_groups = Debt_Context_Type_Group.objects.filter(
        debt_context_type=OuterRef('debt_context__prod_type_id'),
        group__users=user,
        role__in=roles)
    authorized_debt_context_groups = Debt_Context_Group.objects.filter(
        debt_context=OuterRef('debt_context_id'),
        group__users=user,
        role__in=roles)
    tool_debt_context_settings = Tool_Debt_Context_Settings.objects.annotate(
        debt_context__prod_type__member=Exists(authorized_debt_context_type_roles),
        debt_context__member=Exists(authorized_debt_context_roles),
        debt_context__prod_type__authorized_group=Exists(authorized_debt_context_type_groups),
        debt_context__authorized_group=Exists(authorized_debt_context_groups))
    tool_debt_context_settings = tool_debt_context_settings.filter(
        Q(debt_context__prod_type__member=True) | Q(debt_context__member=True) |
        Q(debt_context__prod_type__authorized_group=True) | Q(debt_context__authorized_group=True))

    return tool_debt_context_settings