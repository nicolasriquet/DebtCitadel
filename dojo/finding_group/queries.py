from crum import get_current_user
from django.db.models import Exists, OuterRef, Q
from dojo.models import Finding_Group, Debt_Item_Group, Product_Member, Debt_Context_Member, Product_Type_Member, \
    Debt_Context_Type_Member, Product_Group, Debt_Context_Group, Product_Type_Group, Debt_Context_Type_Group
from dojo.authorization.authorization import get_roles_for_permission, user_has_global_permission


def get_authorized_finding_groups(permission, queryset=None, user=None):

    if user is None:
        user = get_current_user()

    if user is None:
        return Finding_Group.objects.none()

    if queryset is None:
        finding_groups = Finding_Group.objects.all()
    else:
        finding_groups = queryset

    if user.is_superuser:
        return finding_groups

    if user_has_global_permission(user, permission):
        return finding_groups

    roles = get_roles_for_permission(permission)
    authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef('test__engagement__product__prod_type_id'),
        user=user,
        role__in=roles)
    authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef('test__engagement__product_id'),
        user=user,
        role__in=roles)
    authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef('test__engagement__product__prod_type_id'),
        group__users=user,
        role__in=roles)
    authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef('test__engagement__product_id'),
        group__users=user,
        role__in=roles)
    finding_groups = finding_groups.annotate(
        test__engagement__product__prod_type__member=Exists(authorized_product_type_roles),
        test__engagement__product__member=Exists(authorized_product_roles),
        test__engagement__product__prod_type__authorized_group=Exists(authorized_product_type_groups),
        test__engagement__product__authorized_group=Exists(authorized_product_groups))
    finding_groups = finding_groups.filter(
        Q(test__engagement__product__prod_type__member=True) |
        Q(test__engagement__product__member=True) |
        Q(test__engagement__product__prod_type__authorized_group=True) |
        Q(test__engagement__product__authorized_group=True))

    return finding_groups


def get_authorized_debt_item_groups(permission, queryset=None, user=None):

    if user is None:
        user = get_current_user()

    if user is None:
        return Debt_Item_Group.objects.none()

    if queryset is None:
        debt_item_groups = Debt_Item_Group.objects.all()
    else:
        debt_item_groups = queryset

    if user.is_superuser:
        return debt_item_groups

    if user_has_global_permission(user, permission):
        return debt_item_groups

    roles = get_roles_for_permission(permission)
    authorized_debt_context_type_roles = Debt_Context_Type_Member.objects.filter(
        debt_context_type=OuterRef('test__engagement__debt_context__prod_type_id'),
        user=user,
        role__in=roles)
    authorized_debt_context_roles = Debt_Context_Member.objects.filter(
        debt_context=OuterRef('test__engagement__debt_context_id'),
        user=user,
        role__in=roles)
    authorized_debt_context_type_groups = Debt_Context_Type_Group.objects.filter(
        debt_context_type=OuterRef('test__engagement__debt_context__prod_type_id'),
        group__users=user,
        role__in=roles)
    authorized_debt_context_groups = Debt_Context_Group.objects.filter(
        debt_context=OuterRef('test__engagement__debt_context_id'),
        group__users=user,
        role__in=roles)
    debt_item_groups = debt_item_groups.annotate(
        test__engagement__debt_context__prod_type__member=Exists(authorized_debt_context_type_roles),
        test__engagement__debt_context__member=Exists(authorized_debt_context_roles),
        test__engagement__debt_context__prod_type__authorized_group=Exists(authorized_debt_context_type_groups),
        test__engagement__debt_context__authorized_group=Exists(authorized_debt_context_groups))
    debt_item_groups = debt_item_groups.filter(
        Q(test__engagement__debt_context__prod_type__member=True) |
        Q(test__engagement__debt_context__member=True) |
        Q(test__engagement__debt_context__prod_type__authorized_group=True) |
        Q(test__engagement__debt_context__authorized_group=True))

    return debt_item_groups