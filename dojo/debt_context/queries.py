from crum import get_current_user
from django.db.models import Exists, OuterRef, Q
from dojo.models import Debt_Context, Debt_Context_Member, Debt_Context_Type_Member, App_Analysis, \
    DojoMeta, Debt_Context_Group, Debt_Context_Type_Group, Languages, Engagement_Presets, Debt_Engagement_Presets, \
    Debt_Context_API_Scan_Configuration
from dojo.authorization.authorization import get_roles_for_permission, user_has_global_permission, user_has_permission, \
    role_has_permission

from dojo.group.queries import get_authorized_groups
from dojo.authorization.roles_permissions import Permissions


def get_authorized_debt_contexts(permission, user=None):

    if user is None:
        user = get_current_user()

    if user is None:
        return Debt_Context.objects.none()

    if user.is_superuser:
        return Debt_Context.objects.all().order_by('name')

    if user_has_global_permission(user, permission):
        return Debt_Context.objects.all().order_by('name')

    roles = get_roles_for_permission(permission)
    authorized_debt_context_type_roles = Debt_Context_Type_Member.objects.filter(
        debt_context_type=OuterRef('prod_type_id'),
        user=user,
        role__in=roles)
    authorized_debt_context_roles = Debt_Context_Member.objects.filter(
        debt_context=OuterRef('pk'),
        user=user,
        role__in=roles)
    authorized_debt_context_type_groups = Debt_Context_Type_Group.objects.filter(
        debt_context_type=OuterRef('prod_type_id'),
        group__users=user,
        role__in=roles)
    authorized_debt_context_groups = Debt_Context_Group.objects.filter(
        debt_context=OuterRef('pk'),
        group__users=user,
        role__in=roles)
    debt_contexts = Debt_Context.objects.annotate(
        prod_type__member=Exists(authorized_debt_context_type_roles),
        member=Exists(authorized_debt_context_roles),
        prod_type__authorized_group=Exists(authorized_debt_context_type_groups),
        authorized_group=Exists(authorized_debt_context_groups)).order_by('name')
    debt_contexts = debt_contexts.filter(
        Q(prod_type__member=True) | Q(member=True) |
        Q(prod_type__authorized_group=True) | Q(authorized_group=True))

    return debt_contexts


def get_authorized_members_for_debt_context(debt_context, permission):
    user = get_current_user()

    if user.is_superuser or user_has_permission(user, debt_context, permission):
        return Debt_Context_Member.objects.filter(debt_context=debt_context).order_by('user__first_name', 'user__last_name').select_related('role', 'user')
    else:
        return None


def get_authorized_groups_for_debt_context(debt_context, permission):
    user = get_current_user()

    if user.is_superuser or user_has_permission(user, debt_context, permission):
        authorized_groups = get_authorized_groups(Permissions.Group_View)
        return Debt_Context_Group.objects.filter(debt_context=debt_context, group__in=authorized_groups).order_by('group__name').select_related('role')
    else:
        return None


def get_authorized_debt_context_members(permission):
    user = get_current_user()

    if user is None:
        return Debt_Context_Member.objects.none()

    if user.is_superuser:
        return Debt_Context_Member.objects.all().select_related('role')

    if user_has_global_permission(user, permission):
        return Debt_Context_Member.objects.all().select_related('role')

    debt_contexts = get_authorized_debt_contexts(permission)
    return Debt_Context_Member.objects.filter(debt_context__in=debt_contexts).select_related('role')


def get_authorized_debt_context_members_for_user(user, permission):
    request_user = get_current_user()

    if request_user is None:
        return Debt_Context_Member.objects.none()

    if request_user.is_superuser:
        return Debt_Context_Member.objects.filter(user=user).select_related('role', 'debt_context')

    if hasattr(request_user, 'global_role') and request_user.global_role.role is not None and role_has_permission(request_user.global_role.role.id, permission):
        return Debt_Context_Member.objects.filter(user=user).select_related('role', 'debt_context')

    debt_contexts = get_authorized_debt_contexts(permission)
    return Debt_Context_Member.objects.filter(user=user, debt_context__in=debt_contexts).select_related('role', 'debt_context')


def get_authorized_debt_context_groups(permission):
    user = get_current_user()

    if user is None:
        return Debt_Context_Group.objects.none()

    if user.is_superuser:
        return Debt_Context_Group.objects.all().select_related('role')

    debt_contexts = get_authorized_debt_contexts(permission)
    return Debt_Context_Group.objects.filter(debt_context__in=debt_contexts).select_related('role')


def get_authorized_app_analysis(permission):
    user = get_current_user()

    if user is None:
        return App_Analysis.objects.none()

    if user.is_superuser:
        return App_Analysis.objects.all().order_by('name')

    if user_has_global_permission(user, permission):
        return App_Analysis.objects.all().order_by('name')

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
    app_analysis = App_Analysis.objects.annotate(
        debt_context__prod_type__member=Exists(authorized_debt_context_type_roles),
        debt_context__member=Exists(authorized_debt_context_roles),
        debt_context__prod_type__authorized_group=Exists(authorized_debt_context_type_groups),
        debt_context__authorized_group=Exists(authorized_debt_context_groups)).order_by('name')
    app_analysis = app_analysis.filter(
        Q(debt_context__prod_type__member=True) | Q(debt_context__member=True) |
        Q(debt_context__prod_type__authorized_group=True) | Q(debt_context__authorized_group=True))

    return app_analysis


def get_authorized_dojo_meta(permission):
    user = get_current_user()

    if user is None:
        return DojoMeta.objects.none()

    if user.is_superuser:
        return DojoMeta.objects.all().order_by('name')

    if user_has_global_permission(user, permission):
        return DojoMeta.objects.all().order_by('name')

    roles = get_roles_for_permission(permission)
    debt_context_authorized_debt_context_type_roles = Debt_Context_Type_Member.objects.filter(
        debt_context_type=OuterRef('debt_context__prod_type_id'),
        user=user,
        role__in=roles)
    debt_context_authorized_debt_context_roles = Debt_Context_Member.objects.filter(
        debt_context=OuterRef('debt_context_id'),
        user=user,
        role__in=roles)
    debt_context_authorized_debt_context_type_groups = Debt_Context_Type_Group.objects.filter(
        debt_context_type=OuterRef('debt_context__prod_type_id'),
        group__users=user,
        role__in=roles)
    debt_context_authorized_debt_context_groups = Debt_Context_Group.objects.filter(
        debt_context=OuterRef('debt_context_id'),
        group__users=user,
        role__in=roles)
    endpoint_authorized_debt_context_type_roles = Debt_Context_Type_Member.objects.filter(
        debt_context_type=OuterRef('endpoint__debt_context__prod_type_id'),
        user=user,
        role__in=roles)
    endpoint_authorized_debt_context_roles = Debt_Context_Member.objects.filter(
        debt_context=OuterRef('endpoint__debt_context_id'),
        user=user,
        role__in=roles)
    endpoint_authorized_debt_context_type_groups = Debt_Context_Type_Group.objects.filter(
        debt_context_type=OuterRef('endpoint__debt_context__prod_type_id'),
        group__users=user,
        role__in=roles)
    endpoint_authorized_debt_context_groups = Debt_Context_Group.objects.filter(
        debt_context=OuterRef('endpoint__debt_context_id'),
        group__users=user,
        role__in=roles)
    debt_item_authorized_debt_context_type_roles = Debt_Context_Type_Member.objects.filter(
        debt_context_type=OuterRef('debt_item__test__engagement__debt_context__prod_type_id'),
        user=user,
        role__in=roles)
    debt_item_authorized_debt_context_roles = Debt_Context_Member.objects.filter(
        debt_context=OuterRef('debt_item__test__engagement__debt_context_id'),
        user=user,
        role__in=roles)
    debt_item_authorized_debt_context_type_groups = Debt_Context_Type_Group.objects.filter(
        debt_context_type=OuterRef('debt_item__test__engagement__debt_context__prod_type_id'),
        group__users=user,
        role__in=roles)
    debt_item_authorized_debt_context_groups = Debt_Context_Group.objects.filter(
        debt_context=OuterRef('debt_item__test__engagement__debt_context_id'),
        group__users=user,
        role__in=roles)
    dojo_meta = DojoMeta.objects.annotate(
        debt_context__prod_type__member=Exists(debt_context_authorized_debt_context_type_roles),
        debt_context__member=Exists(debt_context_authorized_debt_context_roles),
        debt_context__prod_type__authorized_group=Exists(debt_context_authorized_debt_context_type_groups),
        debt_context__authorized_group=Exists(debt_context_authorized_debt_context_groups),
        endpoint__debt_context__prod_type__member=Exists(endpoint_authorized_debt_context_type_roles),
        endpoint__debt_context__member=Exists(endpoint_authorized_debt_context_roles),
        endpoint__debt_context__prod_type__authorized_group=Exists(endpoint_authorized_debt_context_type_groups),
        endpoint__debt_context__authorized_group=Exists(endpoint_authorized_debt_context_groups),
        debt_item__test__engagement__debt_context__prod_type__member=Exists(debt_item_authorized_debt_context_type_roles),
        debt_item__test__engagement__debt_context__member=Exists(debt_item_authorized_debt_context_roles),
        debt_item__test__engagement__debt_context__prod_type__authorized_group=Exists(debt_item_authorized_debt_context_type_groups),
        debt_item__test__engagement__debt_context__authorized_group=Exists(debt_item_authorized_debt_context_groups)
    ).order_by('name')
    dojo_meta = dojo_meta.filter(
        Q(debt_context__prod_type__member=True) |
        Q(debt_context__member=True) |
        Q(debt_context__prod_type__authorized_group=True) |
        Q(debt_context__authorized_group=True) |
        Q(endpoint__debt_context__prod_type__member=True) |
        Q(endpoint__debt_context__member=True) |
        Q(endpoint__debt_context__prod_type__authorized_group=True) |
        Q(endpoint__debt_context__authorized_group=True) |
        Q(debt_item__test__engagement__debt_context__prod_type__member=True) |
        Q(debt_item__test__engagement__debt_context__member=True) |
        Q(debt_item__test__engagement__debt_context__prod_type__authorized_group=True) |
        Q(debt_item__test__engagement__debt_context__authorized_group=True))

    return dojo_meta


def get_authorized_languages(permission):
    user = get_current_user()

    if user is None:
        return Languages.objects.none()

    if user.is_superuser:
        return Languages.objects.all().order_by('language')

    if user_has_global_permission(user, permission):
        return Languages.objects.all().order_by('language')

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
    languages = Languages.objects.annotate(
        debt_context__prod_type__member=Exists(authorized_debt_context_type_roles),
        debt_context__member=Exists(authorized_debt_context_roles),
        debt_context__prod_type__authorized_group=Exists(authorized_debt_context_type_groups),
        debt_context__authorized_group=Exists(authorized_debt_context_groups)).order_by('language')
    languages = languages.filter(
        Q(debt_context__prod_type__member=True) | Q(debt_context__member=True) |
        Q(debt_context__prod_type__authorized_group=True) | Q(debt_context__authorized_group=True))

    return languages


def get_authorized_debt_engagement_presets(permission):
    user = get_current_user()

    if user is None:
        return Debt_Engagement_Presets.objects.none()

    if user.is_superuser:
        return Debt_Engagement_Presets.objects.all().order_by('title')

    if user_has_global_permission(user, permission):
        return Debt_Engagement_Presets.objects.all().order_by('title')

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
    debt_engagement_presets = Debt_Engagement_Presets.objects.annotate(
        debt_context__prod_type__member=Exists(authorized_debt_context_type_roles),
        debt_context__member=Exists(authorized_debt_context_roles),
        debt_context__prod_type__authorized_group=Exists(authorized_debt_context_type_groups),
        debt_context__authorized_group=Exists(authorized_debt_context_groups)).order_by('title')
    debt_engagement_presets = debt_engagement_presets.filter(
        Q(debt_context__prod_type__member=True) | Q(debt_context__member=True) |
        Q(debt_context__prod_type__authorized_group=True) | Q(debt_context__authorized_group=True))

    return debt_engagement_presets


def get_authorized_debt_context_api_scan_configurations(permission):
    user = get_current_user()

    if user is None:
        return Debt_Context_API_Scan_Configuration.objects.none()

    if user.is_superuser:
        return Debt_Context_API_Scan_Configuration.objects.all()

    if user_has_global_permission(user, permission):
        return Debt_Context_API_Scan_Configuration.objects.all()

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
    debt_context_api_scan_configurations = Debt_Context_API_Scan_Configuration.objects.annotate(
        debt_context__prod_type__member=Exists(authorized_debt_context_type_roles),
        debt_context__member=Exists(authorized_debt_context_roles),
        debt_context__prod_type__authorized_group=Exists(authorized_debt_context_type_groups),
        debt_context__authorized_group=Exists(authorized_debt_context_groups))
    debt_context_api_scan_configurations = debt_context_api_scan_configurations.filter(
        Q(debt_context__prod_type__member=True) | Q(debt_context__member=True) |
        Q(debt_context__prod_type__authorized_group=True) | Q(debt_context__authorized_group=True))

    return debt_context_api_scan_configurations
