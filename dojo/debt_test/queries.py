from crum import get_current_user
from django.db.models import Exists, OuterRef, Q
from dojo.models import Debt_Test, Debt_Context_Member, Debt_Context_Type_Member, Debt_Test_Import, \
    Debt_Context_Group, Debt_Context_Type_Group
from dojo.authorization.authorization import get_roles_for_permission, user_has_global_permission


def get_authorized_debt_tests(permission, debt_context=None):
    user = get_current_user()

    if user is None:
        return Debt_Test.objects.none()

    debt_tests = Debt_Test.objects.all()
    if debt_context:
        debt_tests = debt_tests.filter(debt_engagement__debt_context=debt_context)

    if user.is_superuser:
        return debt_tests

    if user_has_global_permission(user, permission):
        return Debt_Test.objects.all()

    roles = get_roles_for_permission(permission)
    authorized_debt_context_type_roles = Debt_Context_Type_Member.objects.filter(
        debt_context_type=OuterRef('debt_engagement__debt_context__prod_type_id'),
        user=user,
        role__in=roles)
    authorized_debt_context_roles = Debt_Context_Member.objects.filter(
        debt_context=OuterRef('debt_engagement__debt_context_id'),
        user=user,
        role__in=roles)

    authorized_debt_context_type_groups = Debt_Context_Type_Group.objects.filter(
        debt_context_type=OuterRef('debt_engagement__debt_context__prod_type_id'),
        group__users=user,
        role__in=roles)
    authorized_debt_context_groups = Debt_Context_Group.objects.filter(
        debt_context=OuterRef('debt_engagement__debt_context_id'),
        group__users=user,
        role__in=roles)

    debt_tests = debt_tests.annotate(
        debt_engagement__debt_context__prod_type__member=Exists(authorized_debt_context_type_roles),
        debt_engagement__debt_context__member=Exists(authorized_debt_context_roles),
        debt_engagement__debt_context__prod_type__authorized_group=Exists(authorized_debt_context_type_groups),
        debt_engagement__debt_context__authorized_group=Exists(authorized_debt_context_groups))

    debt_tests = debt_tests.filter(
        Q(debt_engagement__debt_context__prod_type__member=True) |
        Q(debt_engagement__debt_context__member=True) |
        Q(debt_engagement__debt_context__prod_type__authorized_group=True) |
        Q(debt_engagement__debt_context__authorized_group=True))

    return debt_tests


def get_authorized_debt_test_imports(permission):
    user = get_current_user()

    if user is None:
        return Debt_Test_Import.objects.none()

    if user.is_superuser:
        return Debt_Test_Import.objects.all()

    if user_has_global_permission(user, permission):
        return Debt_Test_Import.objects.all()

    roles = get_roles_for_permission(permission)
    authorized_debt_context_type_roles = Debt_Context_Type_Member.objects.filter(
        debt_context_type=OuterRef('debt_test__debt_engagement__debt_context__prod_type_id'),
        user=user,
        role__in=roles)
    authorized_debt_context_roles = Debt_Context_Member.objects.filter(
        debt_context=OuterRef('debt_test__debt_engagement__debt_context_id'),
        user=user,
        role__in=roles)
    authorized_debt_context_type_groups = Debt_Context_Type_Group.objects.filter(
        debt_context_type=OuterRef('debt_test__debt_engagement__debt_context__prod_type_id'),
        group__users=user,
        role__in=roles)
    authorized_debt_context_groups = Debt_Context_Group.objects.filter(
        debt_context=OuterRef('debt_test__debt_engagement__debt_context_id'),
        group__users=user,
        role__in=roles)
    debt_test_imports = Debt_Test_Import.objects.annotate(
        debt_test__debt_engagement__debt_context__prod_type__member=Exists(authorized_debt_context_type_roles),
        debt_test__debt_engagement__debt_context__member=Exists(authorized_debt_context_roles),
        debt_test__debt_engagement__debt_context__prod_type__authorized_group=Exists(authorized_debt_context_type_groups),
        debt_test__debt_engagement__debt_context__authorized_group=Exists(authorized_debt_context_groups))
    debt_test_imports = debt_test_imports.filter(
        Q(debt_test__debt_engagement__debt_context__prod_type__member=True) |
        Q(debt_test__debt_engagement__debt_context__member=True) |
        Q(debt_test__debt_engagement__debt_context__prod_type__authorized_group=True) |
        Q(debt_test__debt_engagement__debt_context__authorized_group=True))

    return debt_test_imports
