# #  debt_context
import logging
from django.contrib import messages
from django.core.exceptions import BadRequest
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.shortcuts import render, get_object_or_404
from django.utils.translation import gettext as _

from dojo.forms import DeleteToolDebtContextSettingsForm, ToolDebtContextSettingsForm
from dojo.models import Debt_Context, Tool_Debt_Context_Settings
from dojo.utils import Debt_Context_Tab
from dojo.authorization.authorization_decorators import user_is_authorized
from dojo.authorization.roles_permissions import Permissions

logger = logging.getLogger(__name__)


@user_is_authorized(Debt_Context, Permissions.Debt_Context_Edit, 'pid')
def new_tool_debt_context(request, pid):
    prod = get_object_or_404(Debt_Context, id=pid)
    if request.method == 'POST':
        tform = ToolDebtContextSettingsForm(request.POST)
        if tform.is_valid():
            # form.tool_type = tool_type
            new_prod = tform.save(commit=False)
            new_prod.debt_context = prod
            new_prod.save()

            messages.add_message(
                request,
                messages.SUCCESS,
                _('Debt_Context Tool Configuration Successfully Created.'),
                extra_tags='alert-success')
            return HttpResponseRedirect(
                reverse('all_tool_debt_context', args=(pid, )))
    else:
        tform = ToolDebtContextSettingsForm()
    debt_context_tab = Debt_Context_Tab(prod, title=_("Tool Configurations"), tab="settings")
    return render(request, 'dojo/new_tool_debt_context.html', {
        'tform': tform,
        'debt_context_tab': debt_context_tab,
        'pid': pid
    })


@user_is_authorized(Debt_Context, Permissions.Debt_Context_Edit, 'pid')
def all_tool_debt_context(request, pid):
    prod = get_object_or_404(Debt_Context, id=pid)
    tools = Tool_Debt_Context_Settings.objects.filter(debt_context=prod).order_by('name')
    debt_context_tab = Debt_Context_Tab(prod, title=_("Tool Configurations"), tab="settings")
    return render(request, 'dojo/view_tool_debt_context_all.html', {
        'prod': prod,
        'tools': tools,
        'debt_context_tab': debt_context_tab
    })


@user_is_authorized(Debt_Context, Permissions.Debt_Context_Edit, 'pid')
def edit_tool_debt_context(request, pid, ttid):
    debt_context = get_object_or_404(Debt_Context, id=pid)
    tool_debt_context = Tool_Debt_Context_Settings.objects.get(pk=ttid)
    if tool_debt_context.debt_context != debt_context:
        raise BadRequest(f'Debt_Context {pid} does not fit to debt_context of Tool_Debt_Context {tool_debt_context.debt_context.id}')

    if request.method == 'POST':
        tform = ToolDebtContextSettingsForm(request.POST, instance=tool_debt_context)
        if tform.is_valid():
            tform.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                _('Tool Debt_Context Configuration Successfully Updated.'),
                extra_tags='alert-success')
            return HttpResponseRedirect(reverse('all_tool_debt_context', args=(pid, )))
    else:
        tform = ToolDebtContextSettingsForm(instance=tool_debt_context)

    debt_context_tab = Debt_Context_Tab(debt_context, title=_("Edit Debt_Context Tool Configuration"), tab="settings")
    return render(request, 'dojo/edit_tool_debt_context.html', {
        'tform': tform,
        'debt_context_tab': debt_context_tab
    })


@user_is_authorized(Debt_Context, Permissions.Debt_Context_Edit, 'pid')
def delete_tool_debt_context(request, pid, ttid):
    tool_debt_context = Tool_Debt_Context_Settings.objects.get(pk=ttid)
    debt_context = get_object_or_404(Debt_Context, id=pid)
    if tool_debt_context.debt_context != debt_context:
        raise BadRequest(f'Debt_Context {pid} does not fit to debt_context of Tool_Debt_Context {tool_debt_context.debt_context.id}')

    if request.method == 'POST':
        DeleteToolDebtContextSettingsForm(request.POST, instance=tool_debt_context)
        tool_debt_context.delete()
        messages.add_message(
            request,
            messages.SUCCESS,
            _('Tool Debt_Context Successfully Deleted.'),
            extra_tags='alert-success')
        return HttpResponseRedirect(reverse('all_tool_debt_context', args=(pid, )))
    else:
        tform = ToolDebtContextSettingsForm(instance=tool_debt_context)

    debt_context_tab = Debt_Context_Tab(debt_context, title=_("Delete Debt_Context Tool Configuration"), tab="settings")

    return render(request, 'dojo/delete_tool_debt_context.html', {
        'tform': tform,
        'debt_context_tab': debt_context_tab
    })
