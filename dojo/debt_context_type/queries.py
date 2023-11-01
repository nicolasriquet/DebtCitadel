from crum import get_current_user
from django.db.models import Exists, OuterRef, Q
from dojo.models import Debt_Context_Type, Debt_Context_Type_Member, Debt_Context_Type_Group
from dojo.authorization.authorization import get_roles_for_permission, user_has_global_permission, user_has_permission, \
    role_has_permission
from dojo.group.queries import get_authorized_groups
from dojo.authorization.roles_permissions import Permissions


def get_authorized_debt_context_types(permission):
    user = get_current_user()

    if user is None:
        return Debt_Context_Type.objects.none()

    if user.is_superuser:
        return Debt_Context_Type.objects.all().order_by('name')

    if user_has_global_permission(user, permission):
        return Debt_Context_Type.objects.all().order_by('name')

    roles = get_roles_for_permission(permission)
    authorized_roles = Debt_Context_Type_Member.objects.filter(debt_context_type=OuterRef('pk'),
        user=user,
        role__in=roles)
    authorized_groups = Debt_Context_Type_Group.objects.filter(
        debt_context_type=OuterRef('pk'),
        group__users=user,
        role__in=roles)
    debt_context_types = Debt_Context_Type.objects.annotate(
        member=Exists(authorized_roles),
        authorized_group=Exists(authorized_groups)).order_by('name')
    debt_context_types = debt_context_types.filter(Q(member=True) | Q(authorized_group=True))

    return debt_context_types


def get_authorized_members_for_debt_context_type(debt_context_type, permission):
    user = get_current_user()

    if user.is_superuser or user_has_permission(user, debt_context_type, permission):
        return Debt_Context_Type_Member.objects.filter(debt_context_type=debt_context_type).order_by('user__first_name', 'user__last_name').select_related('role', 'debt_context_type', 'user')
    else:
        return None


def get_authorized_groups_for_debt_context_type(debt_context_type, permission):
    user = get_current_user()

    if user.is_superuser or user_has_permission(user, debt_context_type, permission):
        authorized_groups = get_authorized_groups(Permissions.Group_View)
        return Debt_Context_Type_Group.objects.filter(debt_context_type=debt_context_type, group__in=authorized_groups).order_by('group__name').select_related('role', 'group')
    else:
        return None


def get_authorized_debt_context_type_members(permission):
    user = get_current_user()

    if user is None:
        return Debt_Context_Type_Member.objects.none()

    if user.is_superuser:
        return Debt_Context_Type_Member.objects.all().select_related('role')

    if user_has_global_permission(user, permission):
        return Debt_Context_Type_Member.objects.all().select_related('role')

    debt_context_types = get_authorized_debt_context_types(permission)
    return Debt_Context_Type_Member.objects.filter(debt_context_type__in=debt_context_types).select_related('role')


def get_authorized_debt_context_type_members_for_user(user, permission):
    request_user = get_current_user()

    if request_user is None:
        return Debt_Context_Type_Member.objects.none()

    if request_user.is_superuser:
        return Debt_Context_Type_Member.objects.filter(user=user).select_related('role', 'debt_context_type')

    if hasattr(request_user, 'global_role') and request_user.global_role.role is not None and role_has_permission(request_user.global_role.role.id, permission):
        return Debt_Context_Type_Member.objects.filter(user=user).select_related('role', 'debt_context_type')

    debt_context_types = get_authorized_debt_context_types(permission)
    return Debt_Context_Type_Member.objects.filter(user=user, debt_context_type__in=debt_context_types).select_related('role', 'debt_context_type')


def get_authorized_debt_context_type_groups(permission):
    user = get_current_user()

    if user is None:
        return Debt_Context_Type_Group.objects.none()

    if user.is_superuser:
        return Debt_Context_Type_Group.objects.all().select_related('role')

    debt_context_types = get_authorized_debt_context_types(permission)
    return Debt_Context_Type_Group.objects.filter(debt_context_type__in=debt_context_types).select_related('role')
