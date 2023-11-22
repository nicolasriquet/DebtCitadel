import logging

from django.contrib.admin.utils import NestedObjects
from django.db import DEFAULT_DB_ALIAS
from django.contrib import messages
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render, get_object_or_404
from django.utils.translation import gettext as _
from dojo.filters import DebtContextTypeFilter
from dojo.forms import Debt_Context_TypeForm, Delete_Debt_Context_TypeForm, Add_Debt_Context_Type_MemberForm, \
    Edit_Debt_Context_Type_MemberForm, Delete_Debt_Context_Type_MemberForm, Add_Debt_Context_Type_GroupForm, \
    Edit_Debt_Context_Type_Group_Form, Delete_Debt_Context_Type_GroupForm
from dojo.models import Debt_Context_Type, Debt_Context_Type_Member, Role, Debt_Context_Type_Group
from dojo.utils import get_page_items, add_breadcrumb, is_title_in_breadcrumbs, get_setting, async_delete
from dojo.debt_notifications.helper import create_notification
from django.db.models import Count, Q
from django.db.models.query import QuerySet
from dojo.authorization.authorization import user_has_permission
from dojo.authorization.roles_permissions import Permissions
from dojo.authorization.authorization_decorators import user_has_global_permission, user_is_authorized
from dojo.debt_context_type.queries import get_authorized_debt_context_types, get_authorized_members_for_debt_context_type, \
    get_authorized_groups_for_debt_context_type
from dojo.debt_context.queries import get_authorized_debt_contexts

logger = logging.getLogger(__name__)

"""
Jay
Status: in debt_context
debt_context Type views
"""


def debt_context_type(request):

    debt_context_types = get_authorized_debt_context_types(Permissions.Debt_Context_Type_View)
    name_words = debt_context_types.values_list('name', flat=True)

    ptl = DebtContextTypeFilter(request.GET, queryset=debt_context_types)
    pts = get_page_items(request, ptl.qs, 25)

    pts.object_list = prefetch_for_debt_context_type(pts.object_list)

    page_name = _("Debt Context Type List")
    add_breadcrumb(title=page_name, top_level=True, request=request)

    return render(request, 'dojo/debt_context_type.html', {
        'name': page_name,
        'pts': pts,
        'ptl': ptl,
        'name_words': name_words})


def prefetch_for_debt_context_type(debt_context_types):
    prefetch_debt_context_types = debt_context_types

    if isinstance(prefetch_debt_context_types, QuerySet):  # old code can arrive here with debt_contexts being a list because the query was already executed
        active_debt_items_query = Q(debt_context_type__debt_engagement__debt_test__debt_item__active=True)
        active_verified_debt_items_query = Q(debt_context_type__debt_engagement__debt_test__debt_item__active=True,
                                debt_context_type__debt_engagement__debt_test__debt_item__verified=True)
        prefetch_debt_context_types = prefetch_debt_context_types.annotate(
            active_debt_items_count=Count('debt_context_type__debt_engagement__debt_test__debt_item__id', filter=active_debt_items_query))
        prefetch_debt_context_types = prefetch_debt_context_types.annotate(
            active_verified_debt_items_count=Count('debt_context_type__debt_engagement__debt_test__debt_item__id', filter=active_verified_debt_items_query))
        prefetch_debt_context_types = prefetch_debt_context_types.annotate(debt_context_count=Count('debt_context_type', distinct=True))
    else:
        logger.debug('unable to prefetch because query was already executed')

    return prefetch_debt_context_types


@user_has_global_permission(Permissions.Debt_Context_Type_Add)
def add_debt_context_type(request):
    page_name = _("Add Debt Context Type")
    form = Debt_Context_TypeForm()
    if request.method == 'POST':
        form = Debt_Context_TypeForm(request.POST)
        if form.is_valid():
            debt_context_type = form.save()
            member = Debt_Context_Type_Member()
            member.user = request.user
            member.debt_context_type = debt_context_type
            member.role = Role.objects.get(is_owner=True)
            member.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 _('debt_context type added successfully.'),
                                 extra_tags='alert-success')
            create_notification(event='debt_context_type_added', title=debt_context_type.name,
                                debt_context_type=debt_context_type,
                                url=reverse('view_debt_context_type', args=(debt_context_type.id,)))
            return HttpResponseRedirect(reverse('debt_context_type'))
    add_breadcrumb(title=page_name, top_level=False, request=request)

    return render(request, 'dojo/debt_new_debt_context_type.html', {
        'name': page_name,
        'form': form,
    })


@user_is_authorized(Debt_Context_Type, Permissions.Debt_Context_Type_View, 'ptid')
def view_debt_context_type(request, ptid):
    page_name = _("View debt_context Type")
    pt = get_object_or_404(Debt_Context_Type, pk=ptid)
    members = get_authorized_members_for_debt_context_type(pt, Permissions.Debt_Context_Type_View)
    groups = get_authorized_groups_for_debt_context_type(pt, Permissions.Debt_Context_Type_View)
    debt_contexts = get_authorized_debt_contexts(Permissions.Debt_Context_View).filter(debt_context_type=pt)
    debt_contexts = get_page_items(request, debt_contexts, 25)
    add_breadcrumb(title=page_name, top_level=False, request=request)
    return render(request, 'dojo/debt_view_debt_context_type.html', {
        'name': page_name,
        'pt': pt,
        'debt_contexts': debt_contexts,
        'groups': groups,
        'members': members})


@user_is_authorized(Debt_Context_Type, Permissions.Debt_Context_Type_Delete, 'ptid')
def delete_debt_context_type(request, ptid):
    debt_context_type = get_object_or_404(Debt_Context_Type, pk=ptid)
    form = Delete_Debt_Context_TypeForm(instance=debt_context_type)

    if request.method == 'POST':
        if 'id' in request.POST and str(debt_context_type.id) == request.POST['id']:
            form = Delete_Debt_Context_TypeForm(request.POST, instance=debt_context_type)
            if form.is_valid():
                if get_setting("ASYNC_OBJECT_DELETE"):
                    async_del = async_delete()
                    async_del.delete(debt_context_type)
                    message = 'debt_context Type and relationships will be removed in the background.'
                else:
                    message = 'debt_context Type and relationships removed.'
                    debt_context_type.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     message,
                                     extra_tags='alert-success')
                create_notification(event='other',
                                title='Deletion of %s' % debt_context_type.name,
                                no_users=True,
                                description='The debt_context type "%s" was deleted by %s' % (debt_context_type.name, request.user),
                                url=request.build_absolute_uri(reverse('debt_context_type')),
                                icon="exclamation-triangle")
                return HttpResponseRedirect(reverse('debt_context_type'))

    rels = [_('Previewing the relationships has been disabled.'), '']
    display_preview = get_setting('DELETE_PREVIEW')
    if display_preview:
        collector = NestedObjects(using=DEFAULT_DB_ALIAS)
        collector.collect([debt_context_type])
        rels = collector.nested()

    add_breadcrumb(title=_("Delete Debt Context Type"), top_level=False, request=request)
    return render(request, 'dojo/debt_delete_debt_context_type.html',
                  {'debt_context_type': debt_context_type,
                   'form': form,
                   'rels': rels,
                   })


@user_is_authorized(Debt_Context_Type, Permissions.Debt_Context_Type_Edit, 'ptid')
def edit_debt_context_type(request, ptid):
    page_name = "Edit debt_context Type"
    pt = get_object_or_404(Debt_Context_Type, pk=ptid)
    members = get_authorized_members_for_debt_context_type(pt, Permissions.Debt_Context_Type_Manage_Members)
    pt_form = Debt_Context_TypeForm(instance=pt)
    if request.method == "POST" and request.POST.get('edit_debt_context_type'):
        pt_form = Debt_Context_TypeForm(request.POST, instance=pt)
        if pt_form.is_valid():
            pt = pt_form.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                _('debt_context type updated successfully.'),
                extra_tags="alert-success",
            )
            return HttpResponseRedirect(reverse("debt_context_type"))

    add_breadcrumb(title=page_name, top_level=False, request=request)
    return render(request, 'dojo/edit_debt_context_type.html', {
        'name': page_name,
        'pt_form': pt_form,
        'pt': pt,
        'members': members})


@user_is_authorized(Debt_Context_Type, Permissions.Debt_Context_Type_Manage_Members, 'ptid')
def add_debt_context_type_member(request, ptid):
    pt = get_object_or_404(Debt_Context_Type, pk=ptid)
    memberform = Add_Debt_Context_Type_MemberForm(initial={'debt_context_type': pt.id})
    if request.method == 'POST':
        memberform = Add_Debt_Context_Type_MemberForm(request.POST, initial={'debt_context_type': pt.id})
        if memberform.is_valid():
            if memberform.cleaned_data['role'].is_owner and not user_has_permission(request.user, pt, Permissions.Debt_Context_Type_Member_Add_Owner):
                messages.add_message(request,
                                    messages.WARNING,
                                    _('You are not permitted to add users as owners.'),
                                    extra_tags='alert-warning')
            else:
                if 'users' in memberform.cleaned_data and len(memberform.cleaned_data['users']) > 0:
                    for user in memberform.cleaned_data['users']:
                        members = Debt_Context_Type_Member.objects.filter(debt_context_type=pt, user=user)
                        if members.count() == 0:
                            debt_context_type_member = Debt_Context_Type_Member()
                            debt_context_type_member.debt_context_type = pt
                            debt_context_type_member.user = user
                            debt_context_type_member.role = memberform.cleaned_data['role']
                            debt_context_type_member.save()
                messages.add_message(request,
                                    messages.SUCCESS,
                                    _('debt_context type members added successfully.'),
                                    extra_tags='alert-success')
                return HttpResponseRedirect(reverse('view_debt_context_type', args=(ptid, )))
    add_breadcrumb(title=_("Add Debt Context Type Member"), top_level=False, request=request)
    return render(request, 'dojo/new_debt_context_type_member.html', {
        'pt': pt,
        'form': memberform,
    })


@user_is_authorized(Debt_Context_Type_Member, Permissions.Debt_Context_Type_Manage_Members, 'memberid')
def edit_debt_context_type_member(request, memberid):
    page_name = _("Edit debt_context Type Member")
    member = get_object_or_404(Debt_Context_Type_Member, pk=memberid)
    memberform = Edit_Debt_Context_Type_MemberForm(instance=member)
    if request.method == 'POST':
        memberform = Edit_Debt_Context_Type_MemberForm(request.POST, instance=member)
        if memberform.is_valid():
            if not member.role.is_owner:
                owners = Debt_Context_Type_Member.objects.filter(debt_context_type=member.debt_context_type, role__is_owner=True).exclude(id=member.id).count()
                if owners < 1:
                    messages.add_message(request, messages.SUCCESS,
                                         _('There must be at least one owner for debt_context Type %(debt_context_type_name)s.') % {'debt_context_type_name': member.debt_context_type.name},
                                        extra_tags='alert-warning')
                    if is_title_in_breadcrumbs('View User'):
                        return HttpResponseRedirect(reverse('view_user', args=(member.user.id, )))
                    else:
                        return HttpResponseRedirect(reverse('view_debt_context_type', args=(member.debt_context_type.id, )))
            if member.role.is_owner and not user_has_permission(request.user, member.debt_context_type, Permissions.Debt_Context_Type_Member_Add_Owner):
                messages.add_message(request,
                                    messages.WARNING,
                                    'You are not permitted to make users to owners.',
                                    extra_tags='alert-warning')
            else:
                memberform.save()
                messages.add_message(request,
                                    messages.SUCCESS,
                                    _('debt_context type member updated successfully.'),
                                    extra_tags='alert-success')
                if is_title_in_breadcrumbs('View User'):
                    return HttpResponseRedirect(reverse('view_user', args=(member.user.id, )))
                else:
                    return HttpResponseRedirect(reverse('view_debt_context_type', args=(member.debt_context_type.id, )))
    add_breadcrumb(title=page_name, top_level=False, request=request)
    return render(request, 'dojo/edit_debt_context_type_member.html', {
        'name': page_name,
        'memberid': memberid,
        'form': memberform,
    })


@user_is_authorized(Debt_Context_Type_Member, Permissions.Debt_Context_Type_Member_Delete, 'memberid')
def delete_debt_context_type_member(request, memberid):
    page_name = "Delete debt_context Type Member"
    member = get_object_or_404(Debt_Context_Type_Member, pk=memberid)
    memberform = Delete_Debt_Context_Type_MemberForm(instance=member)
    if request.method == 'POST':
        memberform = Delete_Debt_Context_Type_MemberForm(request.POST, instance=member)
        member = memberform.instance
        if member.role.is_owner:
            owners = Debt_Context_Type_Member.objects.filter(debt_context_type=member.debt_context_type, role__is_owner=True).count()
            if owners <= 1:
                messages.add_message(request,
                                    messages.SUCCESS,
                                    _('There must be at least one owner.'),
                                    extra_tags='alert-warning')
                return HttpResponseRedirect(reverse('view_debt_context_type', args=(member.debt_context_type.id, )))

        user = member.user
        member.delete()
        messages.add_message(request,
                            messages.SUCCESS,
                            _('debt_context type member deleted successfully.'),
                            extra_tags='alert-success')
        if is_title_in_breadcrumbs('View User'):
            return HttpResponseRedirect(reverse('view_user', args=(member.user.id, )))
        else:
            if user == request.user:
                return HttpResponseRedirect(reverse('debt_context_type'))
            else:
                return HttpResponseRedirect(reverse('view_debt_context_type', args=(member.debt_context_type.id, )))
    add_breadcrumb(title=page_name, top_level=False, request=request)
    return render(request, 'dojo/delete_debt_context_type_member.html', {
        'name': page_name,
        'memberid': memberid,
        'form': memberform,
    })


@user_is_authorized(Debt_Context_Type, Permissions.Debt_Context_Type_Group_Add, 'ptid')
def add_debt_context_type_group(request, ptid):
    page_name = "Add debt_context Type Group"
    pt = get_object_or_404(Debt_Context_Type, pk=ptid)
    group_form = Add_Debt_Context_Type_GroupForm(initial={'debt_context_type': pt.id})

    if request.method == 'POST':
        group_form = Add_Debt_Context_Type_GroupForm(request.POST, initial={'debt_context_type': pt.id})
        if group_form.is_valid():
            if group_form.cleaned_data['role'].is_owner and not user_has_permission(request.user, pt, Permissions.Debt_Context_Type_Group_Add_Owner):
                messages.add_message(request,
                                    messages.WARNING,
                                    _('You are not permitted to add groups as owners.'),
                                    extra_tags='alert-warning')
            else:
                if 'groups' in group_form.cleaned_data and len(group_form.cleaned_data['groups']) > 0:
                    for group in group_form.cleaned_data['groups']:
                        groups = Debt_Context_Type_Group.objects.filter(debt_context_type=pt, group=group)
                        if groups.count() == 0:
                            debt_context_type_group = Debt_Context_Type_Group()
                            debt_context_type_group.debt_context_type = pt
                            debt_context_type_group.group = group
                            debt_context_type_group.role = group_form.cleaned_data['role']
                            debt_context_type_group.save()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     _('debt_context type groups added successfully.'),
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('view_debt_context_type', args=(ptid,)))

    add_breadcrumb(title=page_name, top_level=False, request=request)
    return render(request, 'dojo/new_debt_context_type_group.html', {
        'name': page_name,
        'pt': pt,
        'form': group_form,
    })


@user_is_authorized(Debt_Context_Type_Group, Permissions.Debt_Context_Type_Group_Edit, 'groupid')
def edit_debt_context_type_group(request, groupid):
    page_name = "Edit debt_context Type Group"
    group = get_object_or_404(Debt_Context_Type_Group, pk=groupid)
    groupform = Edit_Debt_Context_Type_Group_Form(instance=group)

    if request.method == 'POST':
        groupform = Edit_Debt_Context_Type_Group_Form(request.POST, instance=group)
        if groupform.is_valid():
            if group.role.is_owner and not user_has_permission(request.user, group.debt_context_type, Permissions.Debt_Context_Type_Group_Add_Owner):
                messages.add_message(request,
                                     messages.WARNING,
                                     _('You are not permitted to make groups owners.'),
                                     extra_tags='alert-warning')
            else:
                groupform.save()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     _('debt_context type group updated successfully.'),
                                     extra_tags='alert-success')
                if is_title_in_breadcrumbs('View Group'):
                    return HttpResponseRedirect(reverse('view_group', args=(group.group.id,)))
                else:
                    return HttpResponseRedirect(reverse('view_debt_context_type', args=(group.debt_context_type.id,)))

    add_breadcrumb(title=page_name, top_level=False, request=request)
    return render(request, 'dojo/edit_debt_context_type_group.html', {
        'name': page_name,
        'groupid': groupid,
        'form': groupform
    })


@user_is_authorized(Debt_Context_Type_Group, Permissions.Debt_Context_Type_Group_Delete, 'groupid')
def delete_debt_context_type_group(request, groupid):
    page_name = "Delete debt_context Type Group"
    group = get_object_or_404(Debt_Context_Type_Group, pk=groupid)
    groupform = Delete_Debt_Context_Type_GroupForm(instance=group)

    if request.method == 'POST':
        groupform = Delete_Debt_Context_Type_GroupForm(request.POST, instance=group)
        group = groupform.instance
        group.delete()
        messages.add_message(request,
                             messages.SUCCESS,
                             _('debt_context type group deleted successfully.'),
                             extra_tags='alert-success')
        if is_title_in_breadcrumbs('View Group'):
            return HttpResponseRedirect(reverse('view_group', args=(group.group.id, )))
        else:
            # TODO: If user was in the group that was deleted and no longer has access, redirect them to the debt_context
            #  types page
            return HttpResponseRedirect(reverse('view_debt_context_type', args=(group.debt_context_type.id, )))

    add_breadcrumb(page_name, top_level=False, request=request)
    return render(request, 'dojo/delete_debt_context_type_group.html', {
        'name': page_name,
        'groupid': groupid,
        'form': groupform
    })
