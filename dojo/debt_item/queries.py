from crum import get_current_user
from django.db.models import Exists, OuterRef, Q
from dojo.models import Debt_Item, Debt_Context_Member, Debt_Context_Type_Member, Stub_Debt_Item, \
    Debt_Context_Group, Debt_Context_Type_Group, Vulnerability_Id
from dojo.authorization.authorization import get_roles_for_permission, user_has_global_permission


def get_authorized_groups(permission, user=None):
    roles = get_roles_for_permission(permission)
    authorized_debt_context_type_roles = Debt_Context_Type_Member.objects.filter(
        debt_context_type=OuterRef('debt_test__engagement__debt_context__prod_type_id'),
        user=user,
        role__in=roles)
    authorized_debt_context_roles = Debt_Context_Member.objects.filter(
        debt_context=OuterRef('debt_test__engagement__debt_context_id'),
        user=user,
        role__in=roles)
    authorized_debt_context_type_groups = Debt_Context_Type_Group.objects.filter(
        debt_context_type=OuterRef('debt_test__engagement__debt_context__prod_type_id'),
        group__users=user,
        role__in=roles)
    authorized_debt_context_groups = Debt_Context_Group.objects.filter(
        debt_context=OuterRef('debt_test__engagement__debt_context_id'),
        group__users=user,
        role__in=roles)

    return (
        authorized_debt_context_type_roles,
        authorized_debt_context_roles,
        authorized_debt_context_type_groups,
        authorized_debt_context_groups
    )


def get_authorized_debt_items(permission, queryset=None, user=None):
    if user is None:
        user = get_current_user()
    if user is None:
        return Debt_Item.objects.none()
    if queryset is None:
        debt_items = Debt_Item.objects.all()
    else:
        debt_items = queryset

    if user.is_superuser:
        return debt_items

    if user_has_global_permission(user, permission):
        return debt_items

    (
        authorized_debt_context_type_roles,
        authorized_debt_context_roles,
        authorized_debt_context_type_groups,
        authorized_debt_context_groups
    ) = get_authorized_groups(permission, user=user)

    debt_items = debt_items.annotate(
        debt_test__engagement__debt_context__prod_type__member=Exists(authorized_debt_context_type_roles),
        debt_test__engagement__debt_context__member=Exists(authorized_debt_context_roles),
        debt_test__engagement__debt_context__prod_type__authorized_group=Exists(authorized_debt_context_type_groups),
        debt_test__engagement__debt_context__authorized_group=Exists(authorized_debt_context_groups))
    debt_items = debt_items.filter(
        Q(debt_test__engagement__debt_context__prod_type__member=True) |
        Q(debt_test__engagement__debt_context__member=True) |
        Q(debt_test__engagement__debt_context__prod_type__authorized_group=True) |
        Q(debt_test__engagement__debt_context__authorized_group=True))

    return debt_items


def get_authorized_stub_debt_items(permission):
    user = get_current_user()

    if user is None:
        return Stub_Debt_Item.objects.none()

    if user.is_superuser:
        return Stub_Debt_Item.objects.all()

    if user_has_global_permission(user, permission):
        return Stub_Debt_Item.objects.all()

    (
        authorized_debt_context_type_roles,
        authorized_debt_context_roles,
        authorized_debt_context_type_groups,
        authorized_debt_context_groups
    ) = get_authorized_groups(permission, user=user)

    debt_items = Stub_Debt_Item.objects.annotate(
        debt_test__engagement__debt_context__prod_type__member=Exists(authorized_debt_context_type_roles),
        debt_test__engagement__debt_context__member=Exists(authorized_debt_context_roles),
        debt_test__engagement__debt_context__prod_type__authorized_group=Exists(authorized_debt_context_type_groups),
        debt_test__engagement__debt_context__authorized_group=Exists(authorized_debt_context_groups))
    debt_items = debt_items.filter(
        Q(debt_test__engagement__debt_context__prod_type__member=True) |
        Q(debt_test__engagement__debt_context__member=True) |
        Q(debt_test__engagement__debt_context__prod_type__authorized_group=True) |
        Q(debt_test__engagement__debt_context__authorized_group=True))

    return debt_items


def get_authorized_vulnerability_ids(permission, queryset=None, user=None):

    if user is None:
        user = get_current_user()

    if user is None:
        return Vulnerability_Id.objects.none()

    if queryset is None:
        vulnerability_ids = Vulnerability_Id.objects.all()
    else:
        vulnerability_ids = queryset

    if user.is_superuser:
        return vulnerability_ids

    if user_has_global_permission(user, permission):
        return vulnerability_ids

    roles = get_roles_for_permission(permission)
    authorized_debt_context_type_roles = Debt_Context_Type_Member.objects.filter(
        debt_context_type=OuterRef('debt_item__debt_test__engagement__debt_context__prod_type_id'),
        user=user,
        role__in=roles)
    authorized_debt_context_roles = Debt_Context_Member.objects.filter(
        debt_context=OuterRef('debt_item__debt_test__engagement__debt_context_id'),
        user=user,
        role__in=roles)
    authorized_debt_context_type_groups = Debt_Context_Type_Group.objects.filter(
        debt_context_type=OuterRef('debt_item__debt_test__engagement__debt_context__prod_type_id'),
        group__users=user,
        role__in=roles)
    authorized_debt_context_groups = Debt_Context_Group.objects.filter(
        debt_context=OuterRef('debt_item__debt_test__engagement__debt_context_id'),
        group__users=user,
        role__in=roles)
    vulnerability_ids = vulnerability_ids.annotate(
        debt_item__debt_test__engagement__debt_context__prod_type__member=Exists(authorized_debt_context_type_roles),
        debt_item__debt_test__engagement__debt_context__member=Exists(authorized_debt_context_roles),
        debt_item__debt_test__engagement__debt_context__prod_type__authorized_group=Exists(authorized_debt_context_type_groups),
        debt_item__debt_test__engagement__debt_context__authorized_group=Exists(authorized_debt_context_groups))
    vulnerability_ids = vulnerability_ids.filter(
        Q(debt_item__debt_test__engagement__debt_context__prod_type__member=True) |
        Q(debt_item__debt_test__engagement__debt_context__member=True) |
        Q(debt_item__debt_test__engagement__debt_context__prod_type__authorized_group=True) |
        Q(debt_item__debt_test__engagement__debt_context__authorized_group=True))

    return vulnerability_ids
