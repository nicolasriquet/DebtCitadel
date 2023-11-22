import logging
from django.contrib import messages
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render, get_object_or_404
from django.utils import timezone
from dojo.models import Debt_Item, Debt_Context, Debt_Engagement, Cred_User, Cred_Mapping, Debt_Test
from dojo.utils import add_breadcrumb, Debt_Context_Tab
from dojo.forms import CredUserForm, NoteForm, CredMappingFormProd, CredMappingForm

from dojo.utils import dojo_crypto_encrypt, prepare_for_view
from dojo.authorization.authorization_decorators import user_is_authorized
from dojo.authorization.roles_permissions import Permissions
from dojo.authorization.authorization_decorators import user_is_configuration_authorized
from dojo.cred.queries import get_authorized_cred_mappings


logger = logging.getLogger(__name__)


@user_is_configuration_authorized(Permissions.Credential_Add)
def new_cred(request):
    if request.method == 'POST':
        tform = CredUserForm(request.POST)
        if tform.is_valid():
            form_copy = tform.save(commit=False)
            form_copy.password = dojo_crypto_encrypt(
                tform.cleaned_data['password'])
            form_copy.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                'Credential Successfully Created.',
                extra_tags='alert-success')
            return HttpResponseRedirect(reverse('cred', ))
    else:
        tform = CredUserForm()
        add_breadcrumb(
            title="New Credential", top_level=False, request=request)
    return render(request, 'dojo/new_cred.html', {'tform': tform})


@user_is_authorized(Debt_Context, Permissions.Debt_Context_View, 'pid')
def all_cred_debt_context(request, pid):
    prod = get_object_or_404(Debt_Context, id=pid)
    creds = Cred_Mapping.objects.filter(debt_context=prod).order_by('cred_id__name')

    debt_context_tab = Debt_Context_Tab(prod, title="Credentials", tab="settings")
    return render(request, 'dojo/view_cred_prod.html', {'debt_context_tab': debt_context_tab, 'creds': creds, 'prod': prod})


@user_is_authorized(Cred_User, Permissions.Credential_Edit, 'ttid')
def edit_cred(request, ttid):
    tool_config = Cred_User.objects.get(pk=ttid)
    if request.method == 'POST':
        tform = CredUserForm(request.POST, request.FILES, instance=tool_config)
        if tform.is_valid():
            form_copy = tform.save(commit=False)
            form_copy.password = dojo_crypto_encrypt(
                tform.cleaned_data['password'])
            # handle_uploaded_selenium(request.FILES['selenium_script'], tool_config)
            form_copy.save()

            messages.add_message(
                request,
                messages.SUCCESS,
                'Credential Successfully Updated.',
                extra_tags='alert-success')
            return HttpResponseRedirect(reverse('cred', ))
    else:
        tool_config.password = prepare_for_view(tool_config.password)

        tform = CredUserForm(instance=tool_config)
    add_breadcrumb(
        title="Edit Credential Configuration",
        top_level=False,
        request=request)

    return render(request, 'dojo/edit_cred.html', {
        'tform': tform,
    })


@user_is_authorized(Cred_User, Permissions.Credential_View, 'ttid')
def view_cred_details(request, ttid):
    cred = Cred_User.objects.get(pk=ttid)
    notes = cred.notes.all()
    cred_debt_contexts = Cred_Mapping.objects.select_related('debt_context').filter(
        debt_context_id__isnull=False, cred_id=ttid).order_by('debt_context__name')
    cred_debt_contexts = get_authorized_cred_mappings(Permissions.Debt_Context_View, cred_debt_contexts)

    if request.method == 'POST':
        form = NoteForm(request.POST)

        if form.is_valid():
            new_note = form.save(commit=False)
            new_note.author = request.user
            new_note.date = timezone.now()
            new_note.save()
            cred.notes.add(new_note)
            form = NoteForm()

            messages.add_message(
                request,
                messages.SUCCESS,
                'Note added successfully.',
                extra_tags='alert-success')
    else:
        form = NoteForm()

    add_breadcrumb(title="View", top_level=False, request=request)

    return render(request, 'dojo/view_cred_details.html', {
        'cred': cred,
        'form': form,
        'notes': notes,
        'cred_debt_contexts': cred_debt_contexts
    })


@user_is_configuration_authorized(Permissions.Credential_View)
def cred(request):
    confs = Cred_User.objects.all().order_by('name', 'environment', 'username')
    add_breadcrumb(title="Credential Manager", top_level=True, request=request)
    return render(request, 'dojo/view_cred.html', {
        'confs': confs,
    })


@user_is_authorized(Debt_Context, Permissions.Debt_Context_View, 'pid')
@user_is_authorized(Cred_User, Permissions.Credential_View, 'ttid')
def view_cred_debt_context(request, pid, ttid):
    cred = get_object_or_404(
        Cred_Mapping.objects.select_related('cred_id'), id=ttid)
    notes = cred.cred_id.notes.all()

    if request.method == 'POST':
        form = NoteForm(request.POST)

        if form.is_valid():
            new_note = form.save(commit=False)
            new_note.author = request.user
            new_note.date = timezone.now()
            new_note.save()
            cred.cred_id.notes.add(new_note)
            form = NoteForm()
            messages.add_message(
                request,
                messages.SUCCESS,
                'Note added successfully.',
                extra_tags='alert-success')
    else:
        form = NoteForm()

    add_breadcrumb(
        title="Credential Manager", top_level=False, request=request)
    cred_type = "Debt_Context"
    view_link = reverse(
        'view_cred_debt_context', args=(
            cred.debt_context.id,
            cred.id,
        ))
    edit_link = reverse(
        'edit_cred_debt_context', args=(
            cred.debt_context.id,
            cred.id,
        ))
    delete_link = reverse(
        'delete_cred_debt_context', args=(
            cred.debt_context.id,
            cred.id,
        ))

    return render(
        request, 'dojo/view_cred_all_details.html', {
            'cred': cred,
            'form': form,
            'notes': notes,
            'cred_type': cred_type,
            'edit_link': edit_link,
            'delete_link': delete_link,
            'view_link': view_link
        })


@user_is_authorized(Debt_Context, Permissions.Debt_Engagement_View, 'eid')
@user_is_authorized(Cred_User, Permissions.Credential_View, 'ttid')
def view_cred_debt_context_debt_engagement(request, eid, ttid):
    cred = get_object_or_404(
        Cred_Mapping.objects.select_related('cred_id'), id=ttid)
    cred_debt_context = Cred_Mapping.objects.filter(
        cred_id=cred.cred_id.id, debt_context=cred.debt_engagement.debt_context.id).first()
    notes = cred.cred_id.notes.all()

    if request.method == 'POST':
        form = NoteForm(request.POST)

        if form.is_valid():
            new_note = form.save(commit=False)
            new_note.author = request.user
            new_note.date = timezone.now()
            new_note.save()
            cred.cred_id.notes.add(new_note)
            form = NoteForm()
            messages.add_message(
                request,
                messages.SUCCESS,
                'Note added successfully.',
                extra_tags='alert-success')
    else:
        form = NoteForm()

    add_breadcrumb(
        title="Credential Manager", top_level=False, request=request)
    cred_type = "Debt_Engagement"
    edit_link = ""
    view_link = reverse(
        'view_cred_debt_context_debt_engagement', args=(
            eid,
            cred.id,
        ))
    delete_link = reverse(
        'delete_cred_debt_engagement', args=(
            eid,
            cred.id,
        ))

    return render(
        request, 'dojo/view_cred_all_details.html', {
            'cred': cred,
            'form': form,
            'notes': notes,
            'cred_type': cred_type,
            'edit_link': edit_link,
            'delete_link': delete_link,
            'cred_debt_context': cred_debt_context
        })


@user_is_authorized(Debt_Context, Permissions.Debt_Test_View, 'tid')
@user_is_authorized(Cred_User, Permissions.Credential_View, 'ttid')
def view_cred_debt_engagement_debt_test(request, tid, ttid):
    cred = get_object_or_404(
        Cred_Mapping.objects.select_related('cred_id'), id=ttid)
    cred_debt_context = Cred_Mapping.objects.filter(
        cred_id=cred.cred_id.id,
        debt_context=cred.debt_test.debt_engagement.debt_context.id).first()

    notes = cred.cred_id.notes.all()

    if request.method == 'POST':
        form = NoteForm(request.POST)

        if form.is_valid():
            new_note = form.save(commit=False)
            new_note.author = request.user
            new_note.date = timezone.now()
            new_note.save()
            cred.cred_id.notes.add(new_note)
            form = NoteForm()
            messages.add_message(
                request,
                messages.SUCCESS,
                'Note added successfully.',
                extra_tags='alert-success')
    else:
        form = NoteForm()

    add_breadcrumb(
        title="Credential Manager", top_level=False, request=request)
    cred_type = "Debt_Test"
    edit_link = None
    view_link = reverse(
        'view_cred_debt_engagement_debt_test', args=(
            tid,
            cred.id,
        ))
    delete_link = reverse(
        'delete_cred_debt_test', args=(
            tid,
            cred.id,
        ))

    return render(
        request, 'dojo/view_cred_all_details.html', {
            'cred': cred,
            'form': form,
            'notes': notes,
            'cred_type': cred_type,
            'edit_link': edit_link,
            'delete_link': delete_link,
            'cred_debt_context': cred_debt_context
        })


@user_is_authorized(Debt_Context, Permissions.Debt_Item_View, 'fid')
@user_is_authorized(Cred_User, Permissions.Credential_View, 'ttid')
def view_cred_debt_item(request, fid, ttid):
    cred = get_object_or_404(
        Cred_Mapping.objects.select_related('cred_id'), id=ttid)
    cred_debt_context = Cred_Mapping.objects.filter(
        cred_id=cred.cred_id.id,
        debt_context=cred.debt_item.debt_test.debt_engagement.debt_context.id).first()

    notes = cred.cred_id.notes.all()

    if request.method == 'POST':
        form = NoteForm(request.POST)

        if form.is_valid():
            new_note = form.save(commit=False)
            new_note.author = request.user
            new_note.date = timezone.now()
            new_note.save()
            cred.cred_id.notes.add(new_note)
            form = NoteForm()
            messages.add_message(
                request,
                messages.SUCCESS,
                'Note added successfully.',
                extra_tags='alert-success')
    else:
        form = NoteForm()

    add_breadcrumb(
        title="Credential Manager", top_level=False, request=request)
    cred_type = "Debt_Item"
    edit_link = None
    view_link = reverse(
        'view_cred_debt_item', args=(
            fid,
            cred.id,
        ))
    delete_link = reverse(
        'delete_cred_debt_item', args=(
            fid,
            cred.id,
        ))

    return render(
        request, 'dojo/view_cred_all_details.html', {
            'cred': cred,
            'form': form,
            'notes': notes,
            'cred_type': cred_type,
            'edit_link': edit_link,
            'delete_link': delete_link,
            'cred_debt_context': cred_debt_context
        })


@user_is_authorized(Debt_Context, Permissions.Debt_Context_Edit, 'pid')
@user_is_authorized(Cred_User, Permissions.Credential_Edit, 'ttid')
def edit_cred_debt_context(request, pid, ttid):
    cred = get_object_or_404(
        Cred_Mapping.objects.select_related('cred_id'), id=ttid)

    prod = get_object_or_404(Debt_Context, pk=pid)
    if request.method == 'POST':
        tform = CredMappingFormProd(request.POST, instance=cred)
        if tform.is_valid():
            tform.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                'Credential Successfully Updated.',
                extra_tags='alert-success')
            return HttpResponseRedirect(reverse('all_cred_debt_context', args=(pid, )))
    else:
        tform = CredMappingFormProd(instance=cred)

    debt_context_tab = Debt_Context_Tab(prod, title="Edit Debt_Context Credential", tab="settings")
    return render(request, 'dojo/edit_cred_all.html', {
        'tform': tform,
        'debt_context_tab': debt_context_tab,
        'cred_type': "Debt_Context"
    })


@user_is_authorized(Debt_Engagement, Permissions.Debt_Engagement_Edit, 'eid')
@user_is_authorized(Cred_User, Permissions.Credential_Edit, 'ttid')
def edit_cred_debt_context_debt_engagement(request, eid, ttid):
    cred = get_object_or_404(
        Cred_Mapping.objects.select_related('cred_id'), id=ttid)
    eng = get_object_or_404(Debt_Engagement, pk=eid)

    if request.method == 'POST':
        tform = CredMappingForm(request.POST, instance=cred)
        if tform.is_valid():
            tform.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                'Credential Successfully Updated.',
                extra_tags='alert-success')
            return HttpResponseRedirect(
                reverse('view_debt_engagement', args=(eid, )))
    else:
        tform = CredMappingFormProd(instance=cred)
        tform.fields["cred_id"].queryset = Cred_Mapping.objects.filter(
            debt_context=eng.debt_context).order_by('cred_id')

    add_breadcrumb(
        title="Edit Credential Configuration",
        top_level=False,
        request=request)

    return render(request, 'dojo/edit_cred_all.html', {
        'tform': tform,
        'cred_type': "Debt_Engagement"
    })


@user_is_authorized(Debt_Context, Permissions.Debt_Context_Edit, 'pid')
def new_cred_debt_context(request, pid):
    prod = get_object_or_404(Debt_Context, pk=pid)
    if request.method == 'POST':
        tform = CredMappingFormProd(request.POST)
        if tform.is_valid():
            # Select the credential mapping object from the selected list and only allow if the credential is associated with the debt_context
            cred_user = Cred_Mapping.objects.filter(
                cred_id=tform.cleaned_data['cred_id'].id, debt_context=pid).first()
            message = "Credential already associated."
            status_tag = 'alert-danger'

            if cred_user is None:
                prod = Debt_Context.objects.get(id=pid)
                new_f = tform.save(commit=False)
                new_f.debt_context = prod
                new_f.save()
                message = 'Credential Successfully Updated.'
                status_tag = 'alert-success'

            messages.add_message(
                request, messages.SUCCESS, message, extra_tags=status_tag)
            return HttpResponseRedirect(reverse('all_cred_debt_context', args=(pid, )))
    else:
        tform = CredMappingFormProd()

    debt_context_tab = Debt_Context_Tab(prod, title="Add Credential Configuration", tab="settings")

    return render(request, 'dojo/new_cred_debt_context.html', {
        'tform': tform,
        'pid': pid,
        'debt_context_tab': debt_context_tab
    })


@user_is_authorized(Debt_Engagement, Permissions.Debt_Engagement_Edit, 'eid')
def new_cred_debt_context_debt_engagement(request, eid):
    eng = get_object_or_404(Debt_Engagement, pk=eid)

    if request.method == 'POST':
        tform = CredMappingForm(request.POST)
        tform.fields["cred_user"].queryset = Cred_Mapping.objects.filter(
            debt_context=eng.debt_context).order_by('cred_id')
        if tform.is_valid() and tform.cleaned_data['cred_user']:
            # Select the credential mapping object from the selected list and only allow if the credential is associated with the debt_context
            cred_user = Cred_Mapping.objects.filter(
                pk=tform.cleaned_data['cred_user'].id,
                debt_context=eng.debt_context.id).order_by('cred_id').first()
            # search for cred_user and debt_engagement id
            cred_lookup = Cred_Mapping.objects.filter(
                cred_id=cred_user.cred_id, debt_engagement=eng.id)

            message = "Credential already associated."
            status_tag = 'alert-danger'

            if not cred_user:
                message = "Credential must first be associated with this debt_context."

            if not cred_lookup and cred_user:
                new_f = tform.save(commit=False)
                new_f.debt_engagement = eng
                new_f.cred_id = cred_user.cred_id
                new_f.save()
                message = 'Credential Successfully Updated.'
                status_tag = 'alert-success'

            messages.add_message(
                request, messages.SUCCESS, message, extra_tags=status_tag)
            return HttpResponseRedirect(
                reverse('view_debt_engagement', args=(eid, )))
    else:
        tform = CredMappingForm()
        tform.fields["cred_user"].queryset = Cred_Mapping.objects.filter(
            debt_context=eng.debt_context).order_by('cred_id')

    add_breadcrumb(
        title="Add Credential Configuration", top_level=False, request=request)

    return render(
        request, 'dojo/new_cred_mapping.html', {
            'tform': tform,
            'eid': eid,
            'formlink': reverse('new_cred_debt_context_debt_engagement', args=(eid, ))
        })


@user_is_authorized(Debt_Test, Permissions.Debt_Test_Edit, 'tid')
def new_cred_debt_engagement_debt_test(request, tid):
    debt_test = get_object_or_404(Debt_Test, pk=tid)

    if request.method == 'POST':
        tform = CredMappingForm(request.POST)
        tform.fields["cred_user"].queryset = Cred_Mapping.objects.filter(
            debt_engagement=debt_test.debt_engagement).order_by('cred_id')
        if tform.is_valid() and tform.cleaned_data['cred_user']:
            # Select the credential mapping object from the selected list and only allow if the credential is associated with the debt_context
            cred_user = Cred_Mapping.objects.filter(
                pk=tform.cleaned_data['cred_user'].id,
                debt_engagement=debt_test.debt_engagement.id).first()
            # search for cred_user and debt_test id
            cred_lookup = Cred_Mapping.objects.filter(
                cred_id=cred_user.cred_id, debt_test=debt_test.id)

            message = "Credential already associated."
            status_tag = 'alert-danger'

            if not cred_user:
                message = "Credential must first be associated with this debt_context."

            if not cred_lookup and cred_user:
                new_f = tform.save(commit=False)
                new_f.debt_test = debt_test
                new_f.cred_id = cred_user.cred_id
                new_f.save()
                message = 'Credential Successfully Updated.'
                status_tag = 'alert-success'

            messages.add_message(
                request, messages.SUCCESS, message, extra_tags=status_tag)
            return HttpResponseRedirect(reverse('view_debt_test', args=(tid, )))
    else:
        tform = CredMappingForm()
        tform.fields["cred_user"].queryset = Cred_Mapping.objects.filter(
            debt_engagement=debt_test.debt_engagement).order_by('cred_id')

    add_breadcrumb(
        title="Add Credential Configuration", top_level=False, request=request)

    return render(
        request, 'dojo/new_cred_mapping.html', {
            'tform': tform,
            'eid': tid,
            'formlink': reverse('new_cred_debt_engagement_debt_test', args=(tid, ))
        })


@user_is_authorized(Debt_Item, Permissions.Debt_Item_Edit, 'fid')
def new_cred_debt_item(request, fid):
    debt_item = get_object_or_404(Debt_Item, pk=fid)

    if request.method == 'POST':
        tform = CredMappingForm(request.POST)
        tform.fields["cred_user"].queryset = Cred_Mapping.objects.filter(
            debt_engagement=debt_item.debt_test.debt_engagement).order_by('cred_id')

        if tform.is_valid() and tform.cleaned_data['cred_user']:
            # Select the credential mapping object from the selected list and only allow if the credential is associated with the debt_context
            cred_user = Cred_Mapping.objects.filter(
                pk=tform.cleaned_data['cred_user'].id,
                debt_engagement=debt_item.debt_test.debt_engagement.id).first()
            # search for cred_user and debt_test id
            cred_lookup = Cred_Mapping.objects.filter(
                cred_id=cred_user.cred_id, debt_item=debt_item.id)

            message = "Credential already associated."
            status_tag = 'alert-danger'

            if not cred_user:
                message = "Credential must first be associated with this debt_context."

            if not cred_lookup and cred_user:
                new_f = tform.save(commit=False)
                new_f.debt_item = debt_item
                new_f.cred_id = cred_user.cred_id
                new_f.save()
                message = 'Credential Successfully Updated.'
                status_tag = 'alert-success'

            messages.add_message(
                request, messages.SUCCESS, message, extra_tags=status_tag)
            return HttpResponseRedirect(reverse('view_debt_item', args=(fid, )))
    else:
        tform = CredMappingForm()
        tform.fields["cred_user"].queryset = Cred_Mapping.objects.filter(
            debt_engagement=debt_item.debt_test.debt_engagement).order_by('cred_id')

    add_breadcrumb(
        title="Add Credential Configuration", top_level=False, request=request)

    return render(
        request, 'dojo/new_cred_mapping.html', {
            'tform': tform,
            'eid': fid,
            'formlink': reverse('new_cred_debt_item', args=(fid, ))
        })


@user_is_authorized(Cred_User, Permissions.Credential_Delete, 'ttid')
def delete_cred_controller(request, destination_url, id, ttid):
    cred = None
    try:
        cred = Cred_Mapping.objects.get(pk=ttid)
    except:
        pass
    if request.method == 'POST':
        tform = CredMappingForm(request.POST, instance=cred)
        message = ""
        status_tag = ""
        delete_cred = False

        # Determine if the credential can be deleted
        if destination_url == "cred":
            if cred is None:
                delete_cred = True
            else:
                cred_lookup = Cred_Mapping.objects.filter(
                    cred_id=cred.cred_id).exclude(debt_context__isnull=True)
                message = "Credential is associated with debt_context(s). Remove the credential from the debt_context(s) before this credential can be deleted."
                if cred_lookup.exists() is False:
                    delete_cred = True
        elif destination_url == "all_cred_debt_context":
            cred_lookup = Cred_Mapping.objects.filter(
                cred_id=cred.cred_id).exclude(debt_engagement__isnull=True)
            message = "Credential is associated with debt_engagement(s). Remove the credential from the debt_engagement(s) before this credential can be deleted."
            if cred_lookup.exists() is False:
                delete_cred = True
        elif destination_url == "view_debt_engagement":
            cred_lookup = Cred_Mapping.objects.filter(
                cred_id=cred.cred_id).exclude(debt_test__isnull=True)
            message = "Credential is associated with debt_test(s). Remove the debt_test(s) before this credential can be deleted."
            if cred_lookup.exists() is False:
                cred_lookup = Cred_Mapping.objects.filter(
                    cred_id=cred.cred_id).exclude(debt_item__isnull=True)
                message = "Credential is associated with debt_item(s). Remove the debt_item(s) before this credential can be deleted."
                delete_cred = True
        elif destination_url == "view_debt_test" or destination_url == "view_debt_item":
            delete_cred = True

        # Allow deletion if no credentials are associated
        if delete_cred is True:
            message = "Credential Successfully Deleted."
            status_tag = "alert-success"
            # check if main cred delete
            if destination_url == "cred":
                cred = Cred_User.objects.get(pk=ttid)
                cred.delete()
            else:
                cred.delete()
        else:
            status_tag = 'alert-danger'

        messages.add_message(
            request, messages.SUCCESS, message, extra_tags=status_tag)

        if destination_url == "cred":
            return HttpResponseRedirect(reverse(destination_url))
        else:
            return HttpResponseRedirect(reverse(destination_url, args=(id, )))
    else:
        tform = CredMappingForm(instance=cred)

    add_breadcrumb(title="Delete Credential", top_level=False, request=request)
    debt_context_tab = None
    if id:
        debt_context = None
        if destination_url == "all_cred_debt_context":
            debt_context = get_object_or_404(Debt_Context, id)
        elif destination_url == "view_debt_engagement":
            debt_engagement = get_object_or_404(Debt_Engagement, id=id)
            debt_context = debt_engagement.debt_context
        elif destination_url == "view_debt_test":
            debt_test = get_object_or_404(Debt_Test, id=id)
            debt_context = debt_test.debt_engagement.debt_context
        elif destination_url == "view_debt_item":
            debt_item = get_object_or_404(Debt_Item, id=id)
            debt_context = debt_item.debt_test.debt_engagement.debt_context
        debt_context_tab = Debt_Context_Tab(debt_context, title="Delete Credential Mapping", tab="settings")
    return render(request, 'dojo/delete_cred_all.html', {
        'tform': tform,
        'debt_context_tab': debt_context_tab
    })


@user_is_authorized(Cred_User, Permissions.Credential_Delete, 'ttid')
def delete_cred(request, ttid):
    return delete_cred_controller(request, "cred", 0, ttid)


@user_is_authorized(Debt_Context, Permissions.Debt_Context_Edit, 'pid')
@user_is_authorized(Cred_User, Permissions.Credential_Delete, 'ttid')
def delete_cred_debt_context(request, pid, ttid):
    return delete_cred_controller(request, "all_cred_debt_context", pid, ttid)


@user_is_authorized(Debt_Engagement, Permissions.Debt_Engagement_Edit, 'eid')
@user_is_authorized(Cred_User, Permissions.Credential_Delete, 'ttid')
def delete_cred_debt_engagement(request, eid, ttid):
    return delete_cred_controller(request, "view_debt_engagement", eid, ttid)


@user_is_authorized(Debt_Test, Permissions.Debt_Test_Edit, 'tid')
@user_is_authorized(Cred_User, Permissions.Credential_Delete, 'ttid')
def delete_cred_debt_test(request, tid, ttid):
    return delete_cred_controller(request, "view_debt_test", tid, ttid)


@user_is_authorized(Debt_Item, Permissions.Debt_Item_Edit, 'fid')
@user_is_authorized(Cred_User, Permissions.Credential_Delete, 'ttid')
def delete_cred_debt_item(request, fid, ttid):
    return delete_cred_controller(request, "view_debt_item", fid, ttid)
