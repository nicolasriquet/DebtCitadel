# #  debt_tests
from django.db.models.query import Prefetch
from dojo.debt_engagement.queries import get_authorized_debt_engagements
from dojo.importers.utils import construct_imported_message
import logging
import operator
import base64
from datetime import datetime
from django.conf import settings
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.urls import reverse, Resolver404
from django.db.models import Q, QuerySet, Count
from django.http import HttpResponseRedirect, HttpResponse, HttpRequest
from django.shortcuts import render, get_object_or_404
from django.views.decorators.cache import cache_page
from django.utils import timezone
from django.utils.translation import gettext as _
from django.contrib.admin.utils import NestedObjects
from django.db import DEFAULT_DB_ALIAS

from dojo.filters import TemplateDebtItemFilter, DebtItemFilter, DebtTestImportFilter
from dojo.forms import NoteForm, DebtTestForm, \
    DeleteDebtTestForm, AddDebtItemForm, TypedNoteForm, \
    ReImportScanForm, JIRADebtItemForm, JIRAImportScanForm, \
    DebtItemBulkUpdateForm, CopyDebtTestForm
from dojo.models import IMPORT_UNTOUCHED_FINDING, Debt_Item, Debt_Item_Group, Debt_Test, Note_Type, BurpRawRequestResponse, Endpoint, Stub_Debt_Item, \
    Debt_Item_Template, Cred_Mapping, Debt_Test_Import, Debt_Context_API_Scan_Configuration, Debt_Test_Import_Debt_Item_Action

from dojo.tools.factory import get_choices_sorted, get_scan_types_sorted
from dojo.utils import add_error_message_to_response, add_field_errors_to_response, add_success_message_to_response, get_page_items, get_page_items_and_count, add_breadcrumb, get_cal_event, process_notifications, get_system_setting, \
    Debt_Context_Tab, is_scan_file_too_large, get_words_for_field, get_setting, async_delete, redirect_to_return_url_or_else, calculate_grade
from dojo.debt_notifications.helper import create_notification
from dojo.debt_item.views import find_available_notetypes
from functools import reduce
import dojo.jira_link.helper as jira_helper
import dojo.debt_item.helper as debt_item_helper
from django.views.decorators.vary import vary_on_cookie
from django.views import View
from dojo.authorization.authorization_decorators import user_is_authorized
from dojo.authorization.authorization import user_has_permission_or_403
from dojo.authorization.roles_permissions import Permissions
from dojo.debt_test.queries import get_authorized_debt_tests
from dojo.user.queries import get_authorized_users
from dojo.importers.reimporter.reimporter import DojoDefaultReImporter as ReImporter


logger = logging.getLogger(__name__)
parse_logger = logging.getLogger('dojo')
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")


def prefetch_for_debt_items(debt_items):
    prefetched_debt_items = debt_items
    if isinstance(debt_items, QuerySet):  # old code can arrive here with prods being a list because the query was already executed
        prefetched_debt_items = prefetched_debt_items.select_related('reporter')
        prefetched_debt_items = prefetched_debt_items.prefetch_related('jira_issue__jira_project__jira_instance')
        prefetched_debt_items = prefetched_debt_items.prefetch_related('debt_test__debt_test_type')
        prefetched_debt_items = prefetched_debt_items.prefetch_related('debt_test__debt_engagement__jira_project__jira_instance')
        prefetched_debt_items = prefetched_debt_items.prefetch_related('debt_test__debt_engagement__debt_context__jira_project_set__jira_instance')
        prefetched_debt_items = prefetched_debt_items.prefetch_related('found_by')
        prefetched_debt_items = prefetched_debt_items.prefetch_related('risk_acceptance_set')
        # we could try to prefetch only the ladebt_test note with SubQuery and OuterRef, but I'm getting that MySql doesn't support limits in subqueries.
        prefetched_debt_items = prefetched_debt_items.prefetch_related('notes')
        prefetched_debt_items = prefetched_debt_items.prefetch_related('tags')
        # filter out noop reimport actions from debt_item status history
        prefetched_debt_items = prefetched_debt_items.prefetch_related(Prefetch('debt_test_import_debt_item_action_set',
                                                                            queryset=Debt_Test_Import_Debt_Item_Action.objects.exclude(action=IMPORT_UNTOUCHED_FINDING)))

        prefetched_debt_items = prefetched_debt_items.prefetch_related('endpoints')
        prefetched_debt_items = prefetched_debt_items.prefetch_related('status_debt_item')
        prefetched_debt_items = prefetched_debt_items.annotate(active_endpoint_count=Count('status_debt_item__id', filter=Q(status_debt_item__mitigated=False)))
        prefetched_debt_items = prefetched_debt_items.annotate(mitigated_endpoint_count=Count('status_debt_item__id', filter=Q(status_debt_item__mitigated=True)))
        prefetched_debt_items = prefetched_debt_items.prefetch_related('debt_item_group_set__jira_issue')
        prefetched_debt_items = prefetched_debt_items.prefetch_related('duplicate_debt_item')
        prefetched_debt_items = prefetched_debt_items.prefetch_related('vulnerability_id_set')
    else:
        logger.debug('unable to prefetch because query was already executed')

    return prefetched_debt_items


class ViewDebtTest(View):
    def get_debt_test(self, debt_test_id: int):
        debt_test_prefetched = get_authorized_debt_tests(Permissions.Debt_Test_View)
        debt_test_prefetched = debt_test_prefetched.annotate(total_reimport_count=Count('debt_test_import__id', distinct=True))
        return get_object_or_404(debt_test_prefetched, pk=debt_test_id)

    def get_debt_test_import_data(self, request: HttpRequest, debt_test: Debt_Test):
        debt_test_imports = Debt_Test_Import.objects.filter(debt_test=debt_test)
        debt_test_import_filter = DebtTestImportFilter(request.GET, debt_test_imports)

        paged_debt_test_imports = get_page_items_and_count(request, debt_test_import_filter.qs, 5, prefix="debt_test_imports")
        paged_debt_test_imports.object_list = paged_debt_test_imports.object_list.prefetch_related("debt_test_import_debt_item_action_set")

        return {
            "paged_debt_test_imports": paged_debt_test_imports,
            "debt_test_import_filter": debt_test_import_filter,
        }

    def get_stub_debt_items(self, request: HttpRequest, debt_test: Debt_Test):
        stub_debt_items = Stub_Debt_Item.objects.filter(debt_test=debt_test)
        paged_stub_debt_items = get_page_items(request, stub_debt_items, 25)

        return {
            "stub_debt_items": paged_stub_debt_items,
        }

    def get_debt_items(self, request: HttpRequest, debt_test: Debt_Test):
        debt_items = Debt_Item.objects.filter(debt_test=debt_test).order_by("numerical_severity")
        debt_items = DebtItemFilter(request.GET, queryset=debt_items)
        paged_debt_items = get_page_items_and_count(request, prefetch_for_debt_items(debt_items.qs), 25, prefix='debt_items')

        return {
            "debt_items": paged_debt_items,
            "filtered": debt_items,
        }

    def get_note_form(self, request: HttpRequest):
        # Set up the args for the form
        args = [request.POST] if request.method == "POST" else []
        # Set the initial form args
        kwargs = {}

        return NoteForm(*args, **kwargs)

    def get_typed_note_form(self, request: HttpRequest, context: dict):
        # Set up the args for the form
        args = [request.POST] if request.method == "POST" else []
        # Set the initial form args
        kwargs = {
            "available_note_types": context.get("available_note_types")
        }

        return TypedNoteForm(*args, **kwargs)

    def get_form(self, request: HttpRequest, context: dict):
        return (
            self.get_typed_note_form(request, context)
            if context.get("note_type_activation", 0)
            else self.get_note_form(request)
        )

    def get_initial_context(self, request: HttpRequest, debt_test: Debt_Test):
        # Set up the debt_context tab
        debt_context_tab = Debt_Context_Tab(debt_test.debt_engagement.debt_context, title=_("Debt_Test"), tab="debt_engagements")
        debt_context_tab.setDebt_Engagement(debt_test.debt_engagement)
        # Set up the notes and associated info to generate the form with
        notes = debt_test.notes.all()
        note_type_activation = Note_Type.objects.filter(is_active=True).count()
        available_note_types = None
        if note_type_activation:
            available_note_types = find_available_notetypes(notes)
        # Set the current context
        context = {
            "debt_test": debt_test,
            "prod": debt_test.debt_engagement.debt_context,
            "debt_context_tab": debt_context_tab,
            "title_words": get_words_for_field(Debt_Item, 'title'),
            "component_words": get_words_for_field(Debt_Item, 'component_name'),
            "notes": notes,
            "note_type_activation": note_type_activation,
            "available_note_types": available_note_types,
            "files": debt_test.files.all(),
            "person": request.user.username,
            "request": request,
            "show_re_upload": any(debt_test.debt_test_type.name in code for code in get_choices_sorted()),
            "creds": Cred_Mapping.objects.filter(debt_engagement=debt_test.debt_engagement).select_related("cred_id").order_by("cred_id"),
            "cred_debt_test": Cred_Mapping.objects.filter(debt_test=debt_test).select_related("cred_id").order_by("cred_id"),
            "jira_project": jira_helper.get_jira_project(debt_test),
            "bulk_edit_form": DebtItemBulkUpdateForm(request.GET),
            'debt_item_groups': debt_test.debt_item_group_set.all().prefetch_related("debt_items", "jira_issue", "creator", "debt_items__vulnerability_id_set"),
            'debt_item_group_by_options': Debt_Item_Group.GROUP_BY_OPTIONS,

        }
        # Set the form using the context, and then update the context
        form = self.get_form(request, context)
        context["form"] = form
        # Add some of the related objects
        context |= self.get_debt_items(request, debt_test)
        context |= self.get_stub_debt_items(request, debt_test)
        context |= self.get_debt_test_import_data(request, debt_test)

        return context

    def process_form(self, request: HttpRequest, debt_test: Debt_Test, context: dict):
        if context["form"].is_valid():
            # Save the note
            new_note = context["form"].save(commit=False)
            new_note.author = request.user
            new_note.date = timezone.now()
            new_note.save()
            debt_test.notes.add(new_note)
            # Make a notification for this actions
            url = request.build_absolute_uri(reverse("view_debt_test", args=(debt_test.id,)))
            title = f"Debt_Test: {debt_test.debt_test_type.name} on {debt_test.debt_engagement.debt_context.name}"
            process_notifications(request, new_note, url, title)
            messages.add_message(
                request,
                messages.SUCCESS,
                _('Note added successfully.'),
                extra_tags='alert-success')

            return request, True
        return request, False

    def get_template(self):
        return "dojo/view_debt_test.html"

    def get(self, request: HttpRequest, debt_test_id: int):
        # Get the initial objects
        debt_test = self.get_debt_test(debt_test_id)
        # Make sure the user is authorized
        user_has_permission_or_403(request.user, debt_test, Permissions.Debt_Test_View)
        # Quick perms check to determine if the user has access to add a note to the debt_test
        user_has_permission_or_403(request.user, debt_test, Permissions.Note_Add)
        # Set up the initial context
        context = self.get_initial_context(request, debt_test)
        # Render the form
        return render(request, self.get_template(), context)

    def post(self, request: HttpRequest, debt_test_id: int):
        # Get the initial objects
        debt_test = self.get_debt_test(debt_test_id)
        # Make sure the user is authorized
        user_has_permission_or_403(request.user, debt_test, Permissions.Debt_Test_View)
        # Quick perms check to determine if the user has access to add a note to the debt_test
        user_has_permission_or_403(request.user, debt_test, Permissions.Note_Add)
        # Set up the initial context
        context = self.get_initial_context(request, debt_test)
        # Determine the validity of the form
        request, success = self.process_form(request, debt_test, context)
        # Handle the case of a successful form
        if success:
            return redirect_to_return_url_or_else(request, reverse("view_debt_test", args=(debt_test_id,)))
        # Render the form
        return render(request, self.get_template(), context)


# def prefetch_for_debt_test_imports(debt_test_imports):
#     prefetched_debt_test_imports = debt_test_imports
#     if isinstance(debt_test_imports, QuerySet):  # old code can arrive here with prods being a list because the query was already executed
#         #could we make this dynamic, i.e for action_type in IMPORT_ACTIONS: prefetch
#         prefetched_debt_test_imports = prefetched_debt_test_imports.annotate(created_debt_items_count=Count('debt_items', filter=Q(debt_test_import_debt_item_action__action=IMPORT_CREATED_FINDING)))
#         prefetched_debt_test_imports = prefetched_debt_test_imports.annotate(closed_debt_items_count=Count('debt_items', filter=Q(debt_test_import_debt_item_action__action=IMPORT_CLOSED_FINDING)))
#         prefetched_debt_test_imports = prefetched_debt_test_imports.annotate(reactivated_debt_items_count=Count('debt_items', filter=Q(debt_test_import_debt_item_action__action=IMPORT_REACTIVATED_FINDING)))
#         prefetched_debt_test_imports = prefetched_debt_test_imports.annotate(updated_debt_items_count=Count('debt_items', filter=Q(debt_test_import_debt_item_action__action=IMPORT_UNTOUCHED_FINDING)))

#     return prefetch_for_debt_test_imports


@user_is_authorized(Debt_Test, Permissions.Debt_Test_Edit, 'tid')
def edit_debt_test(request, tid):
    debt_test = get_object_or_404(Debt_Test, pk=tid)
    form = DebtTestForm(instance=debt_test)
    if request.method == 'POST':
        form = DebtTestForm(request.POST, instance=debt_test)
        if form.is_valid():
            new_debt_test = form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 _('Debt_Test saved.'),
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_debt_engagement', args=(debt_test.debt_engagement.id,)))

    form.initial['target_start'] = debt_test.target_start.date()
    form.initial['target_end'] = debt_test.target_end.date()
    form.initial['description'] = debt_test.description

    debt_context_tab = Debt_Context_Tab(debt_test.debt_engagement.debt_context, title=_("Edit Debt_Test"), tab="debt_engagements")
    debt_context_tab.setDebt_Engagement(debt_test.debt_engagement)
    return render(request, 'dojo/edit_debt_test.html',
                  {'debt_test': debt_test,
                   'debt_context_tab': debt_context_tab,
                   'form': form,
                   })


@user_is_authorized(Debt_Test, Permissions.Debt_Test_Delete, 'tid')
def delete_debt_test(request, tid):
    debt_test = get_object_or_404(Debt_Test, pk=tid)
    eng = debt_test.debt_engagement
    form = DeleteDebtTestForm(instance=debt_test)

    if request.method == 'POST':
        if 'id' in request.POST and str(debt_test.id) == request.POST['id']:
            form = DeleteDebtTestForm(request.POST, instance=debt_test)
            if form.is_valid():
                debt_context = debt_test.debt_engagement.debt_context
                if get_setting("ASYNC_OBJECT_DELETE"):
                    async_del = async_delete()
                    async_del.delete(debt_test)
                    message = _('Debt_Test and relationships will be removed in the background.')
                else:
                    message = _('Debt_Test and relationships removed.')
                    debt_test.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     message,
                                     extra_tags='alert-success')
                create_notification(event='other',
                                    title=_('Deletion of %(title)s') % {"title": debt_test.title},
                                    debt_context=debt_context,
                                    description=_('The debt_test "%(title)s" was deleted by %(user)s') % {"title": debt_test.title, "user": request.user},
                                    url=request.build_absolute_uri(reverse('view_debt_engagement', args=(eng.id, ))),
                                    recipients=[debt_test.debt_engagement.lead],
                                    icon="exclamation-triangle")
                return HttpResponseRedirect(reverse('view_debt_engagement', args=(eng.id,)))

    rels = ['Previewing the relationships has been disabled.', '']
    display_preview = get_setting('DELETE_PREVIEW')
    if display_preview:
        collector = NestedObjects(using=DEFAULT_DB_ALIAS)
        collector.collect([debt_test])
        rels = collector.nested()

    debt_context_tab = Debt_Context_Tab(debt_test.debt_engagement.debt_context, title=_("Delete Debt_Test"), tab="debt_engagements")
    debt_context_tab.setDebt_Engagement(debt_test.debt_engagement)
    return render(request, 'dojo/delete_debt_test.html',
                  {'debt_test': debt_test,
                   'debt_context_tab': debt_context_tab,
                   'form': form,
                   'rels': rels,
                   'deletable_objects': rels,
                   })


@user_is_authorized(Debt_Test, Permissions.Debt_Test_Edit, 'tid')
def copy_debt_test(request, tid):
    debt_test = get_object_or_404(Debt_Test, id=tid)
    debt_context = debt_test.debt_engagement.debt_context
    debt_engagement_list = get_authorized_debt_engagements(Permissions.Debt_Engagement_Edit).filter(debt_context=debt_context)
    form = CopyDebtTestForm(debt_engagements=debt_engagement_list)

    if request.method == 'POST':
        form = CopyDebtTestForm(request.POST, debt_engagements=debt_engagement_list)
        if form.is_valid():
            debt_engagement = form.cleaned_data.get('debt_engagement')
            debt_context = debt_test.debt_engagement.debt_context
            debt_test_copy = debt_test.copy(debt_engagement=debt_engagement)
            calculate_grade(debt_context)
            messages.add_message(
                request,
                messages.SUCCESS,
                'Debt_Test Copied successfully.',
                extra_tags='alert-success')
            create_notification(event='other',
                                title='Copying of %s' % debt_test.title,
                                description='The debt_test "%s" was copied by %s to %s' % (debt_test.title, request.user, debt_engagement.name),
                                debt_context=debt_context,
                                url=request.build_absolute_uri(reverse('view_debt_test', args=(debt_test_copy.id,))),
                                recipients=[debt_test.debt_engagement.lead],
                                icon="exclamation-triangle")
            return redirect_to_return_url_or_else(request, reverse('view_debt_engagement', args=(debt_engagement.id, )))
        else:
            messages.add_message(
                request,
                messages.ERROR,
                'Unable to copy debt_test, please try again.',
                extra_tags='alert-danger')

    debt_context_tab = Debt_Context_Tab(debt_context, title="Copy Debt_Test", tab="debt_engagements")
    return render(request, 'dojo/copy_object.html', {
        'source': debt_test,
        'source_label': 'Debt_Test',
        'destination_label': 'Debt_Engagement',
        'debt_context_tab': debt_context_tab,
        'form': form,
    })


@cache_page(60 * 5)  # cache for 5 minutes
@vary_on_cookie
def debt_test_calendar(request):

    if not get_system_setting('enable_calendar'):
        raise Resolver404()

    if 'lead' not in request.GET or '0' in request.GET.getlist('lead'):
        debt_tests = get_authorized_debt_tests(Permissions.Debt_Test_View)
    else:
        filters = []
        leads = request.GET.getlist('lead', '')
        if '-1' in request.GET.getlist('lead'):
            leads.remove('-1')
            filters.append(Q(lead__isnull=True))
        filters.append(Q(lead__in=leads))
        debt_tests = get_authorized_debt_tests(Permissions.Debt_Test_View).filter(reduce(operator.or_, filters))

    debt_tests = debt_tests.prefetch_related('debt_test_type', 'lead', 'debt_engagement__debt_context')

    add_breadcrumb(title=_("Debt_Test Calendar"), top_level=True, request=request)
    return render(request, 'dojo/calendar.html', {
        'caltype': 'debt_tests',
        'leads': request.GET.getlist('lead', ''),
        'debt_tests': debt_tests,
        'users': get_authorized_users(Permissions.Debt_Test_View)})


@user_is_authorized(Debt_Test, Permissions.Debt_Test_View, 'tid')
def debt_test_ics(request, tid):
    debt_test = get_object_or_404(Debt_Test, id=tid)
    start_date = datetime.combine(debt_test.target_start, datetime.min.time())
    end_date = datetime.combine(debt_test.target_end, datetime.max.time())
    uid = "dojo_debt_test_%d_%d_%d" % (debt_test.id, debt_test.debt_engagement.id, debt_test.debt_engagement.debt_context.id)
    cal = get_cal_event(start_date,
                        end_date,
                        _("Debt_Test: %(debt_test_type_name)s (%(debt_context_name)s)") % {
                            'debt_test_type_name': debt_test.debt_test_type.name,
                            'debt_context_name': debt_test.debt_engagement.debt_context.name
                        },
                        _("Set aside for debt_test %(debt_test_type_name)s, on debt_context %(debt_context_name)s. Additional detail can be found at %(detail_url)s") % {
                            'debt_test_type_name': debt_test.debt_test_type.name,
                            'debt_context_name': debt_test.debt_engagement.debt_context.name,
                            'detail_url': request.build_absolute_uri((reverse("view_debt_test", args=(debt_test.id,))))
                        },
                        uid)
    output = cal.serialize()
    response = HttpResponse(content=output)
    response['Content-Type'] = 'text/calendar'
    response['Content-Disposition'] = 'attachment; filename=%s.ics' % debt_test.debt_test_type.name
    return response


class AddDebtItemView(View):
    def get_debt_test(self, debt_test_id: int):
        return get_object_or_404(Debt_Test, id=debt_test_id)

    def get_initial_context(self, request: HttpRequest, debt_test: Debt_Test):
        # Get the debt_item form first since it is used in another place
        debt_item_form = self.get_debt_item_form(request, debt_test)
        debt_context_tab = Debt_Context_Tab(debt_test.debt_engagement.debt_context, title=_("Add Debt_Item"), tab="debt_engagements")
        debt_context_tab.setDebtEngagement(debt_test.debt_engagement)
        return {
            "form": debt_item_form,
            "debt_context_tab": debt_context_tab,
            "temp": False,
            'debt_test': debt_test,
            "tid": debt_test.id,
            "pid": debt_test.debt_engagement.debt_context.id,
            "form_error": False,
            "jform": self.get_jira_form(request, debt_test, debt_item_form=debt_item_form),
        }

    def get_debt_item_form(self, request: HttpRequest, debt_test: Debt_Test):
        # Set up the args for the form
        args = [request.POST] if request.method == "POST" else []
        # Set the initial form args
        kwargs = {
            "initial": {'date': timezone.now().date(), 'verified': True},
            "req_resp": None,
            "debt_context": debt_test.debt_engagement.debt_context,
        }
        # Remove the initial state on post
        if request.method == "POST":
            kwargs.pop("initial")

        return AddDebtItemForm(*args, **kwargs)

    def get_jira_form(self, request: HttpRequest, debt_test: Debt_Test, debt_item_form: AddDebtItemForm = None):
        # Determine if jira should be used
        if (jira_project := jira_helper.get_jira_project(debt_test)) is not None:
            # Set up the args for the form
            args = [request.POST] if request.method == "POST" else []
            # Set the initial form args
            kwargs = {
                "push_all": jira_helper.is_push_all_issues(debt_test),
                "prefix": "jiraform",
                "jira_project": jira_project,
                "debt_item_form": debt_item_form,
            }

            return JIRADebtItemForm(*args, **kwargs)
        return None

    def validate_status_change(self, request: HttpRequest, context: dict):
        if ((context["form"]['active'].value() is False or
             context["form"]['false_p'].value()) and
             context["form"]['duplicate'].value() is False):

            closing_disabled = Note_Type.objects.filter(is_mandatory=True, is_active=True).count()
            if closing_disabled != 0:
                error_inactive = ValidationError(
                    _('Can not set a debt_item as inactive without adding all mandatory notes'),
                    code='inactive_without_mandatory_notes')
                error_false_p = ValidationError(
                    _('Can not set a debt_item as false positive without adding all mandatory notes'),
                    code='false_p_without_mandatory_notes')
                if context["form"]['active'].value() is False:
                    context["form"].add_error('active', error_inactive)
                if context["form"]['false_p'].value():
                    context["form"].add_error('false_p', error_false_p)
                messages.add_message(
                    request,
                    messages.ERROR,
                    _('Can not set a debt_item as inactive or false positive without adding all mandatory notes'),
                    extra_tags='alert-danger')

        return request

    def process_debt_item_form(self, request: HttpRequest, debt_test: Debt_Test, context: dict):
        debt_item = None
        if context["form"].is_valid():
            debt_item = context["form"].save(commit=False)
            debt_item.debt_test = debt_test
            debt_item.reporter = request.user
            debt_item.numerical_severity = Debt_Item.get_numerical_severity(debt_item.severity)
            debt_item.tags = context["form"].cleaned_data['tags']
            debt_item.save()
            # Save and add new endpoints
            debt_item_helper.add_endpoints(debt_item, context["form"])
            # Save the debt_item at the end and return
            debt_item.save()

            return debt_item, request, True
        else:
            add_error_message_to_response("The form has errors, please correct them below.")
            add_field_errors_to_response(context["form"])

        return debt_item, request, False

    def process_jira_form(self, request: HttpRequest, debt_item: Debt_Item, context: dict):
        # Capture case if the jira not being enabled
        if context["jform"] is None:
            return request, True, False

        if context["jform"] and context["jform"].is_valid():
            # can't use helper as when push_all_jira_issues is True, the checkbox gets disabled and is always false
            # push_to_jira = jira_helper.is_push_to_jira(debt_item, jform.cleaned_data.get('push_to_jira'))
            push_to_jira = jira_helper.is_push_all_issues(debt_item) or context["jform"].cleaned_data.get('push_to_jira')
            jira_message = None
            # if the jira issue key was changed, update database
            new_jira_issue_key = context["jform"].cleaned_data.get('jira_issue')
            if debt_item.has_jira_issue:
                jira_issue = debt_item.jira_issue
                # everything in DD around JIRA integration is based on the internal id of the issue in JIRA
                # instead of on the public jira issue key.
                # I have no idea why, but it means we have to retrieve the issue from JIRA to get the internal JIRA id.
                # we can assume the issue exist, which is already checked in the validation of the jform
                if not new_jira_issue_key:
                    jira_helper.debt_item_unlink_jira(request, debt_item)
                    jira_message = 'Link to JIRA issue removed successfully.'

                elif new_jira_issue_key != debt_item.jira_issue.jira_key:
                    jira_helper.debt_item_unlink_jira(request, debt_item)
                    jira_helper.debt_item_link_jira(request, debt_item, new_jira_issue_key)
                    jira_message = 'Changed JIRA link successfully.'
            else:
                logger.debug('debt_item has no jira issue yet')
                if new_jira_issue_key:
                    logger.debug('debt_item has no jira issue yet, but jira issue specified in request. trying to link.')
                    jira_helper.debt_item_link_jira(request, debt_item, new_jira_issue_key)
                    jira_message = 'Linked a JIRA issue successfully.'
            # Determine if a message should be added
            if jira_message:
                messages.add_message(
                    request, messages.SUCCESS, jira_message, extra_tags="alert-success"
                )

            return request, True, push_to_jira
        else:
            add_field_errors_to_response(context["jform"])

        return request, False, False

    def process_forms(self, request: HttpRequest, debt_test: Debt_Test, context: dict):
        form_success_list = []
        debt_item = None
        # Set vars for the completed forms
        # Validate debt_item mitigation
        request = self.validate_status_change(request, context)
        # Check the validity of the form overall
        debt_item, request, success = self.process_debt_item_form(request, debt_test, context)
        form_success_list.append(success)
        request, success, push_to_jira = self.process_jira_form(request, debt_item, context)
        form_success_list.append(success)
        # Determine if all forms were successful
        all_forms_valid = all(form_success_list)
        # Check the validity of all the forms
        if all_forms_valid:
            # if we're removing the "duplicate" in the edit debt_item screen
            debt_item_helper.save_vulnerability_ids(debt_item, context["form"].cleaned_data["vulnerability_ids"].split())
            # Push things to jira if needed
            debt_item.save(push_to_jira=push_to_jira)
            # Save the burp req resp
            if "request" in context["form"].cleaned_data or "response" in context["form"].cleaned_data:
                burp_rr = BurpRawRequestResponse(
                    debt_item=debt_item,
                    burpRequestBase64=base64.b64encode(context["form"].cleaned_data["request"].encode()),
                    burpResponseBase64=base64.b64encode(context["form"].cleaned_data["response"].encode()),
                )
                burp_rr.clean()
                burp_rr.save()
            # Create a notification
            create_notification(
                event='other',
                title=_('Addition of %(title)s') % {'title': debt_item.title},
                debt_item=debt_item,
                description=_('Debt_Item "%(title)s" was added by %(user)s') % {
                    'title': debt_item.title, 'user': request.user
                },
                url=reverse("view_debt_item", args=(debt_item.id,)),
                icon="exclamation-triangle")
            # Add a success message
            messages.add_message(
                request,
                messages.SUCCESS,
                _('Debt_Item added successfully.'),
                extra_tags='alert-success')

        return debt_item, request, all_forms_valid

    def get_template(self):
        return "dojo/add_debt_items.html"

    def get(self, request: HttpRequest, debt_test_id: int):
        # Get the initial objects
        debt_test = self.get_debt_test(debt_test_id)
        # Make sure the user is authorized
        user_has_permission_or_403(request.user, debt_test, Permissions.Debt_Item_Add)
        # Set up the initial context
        context = self.get_initial_context(request, debt_test)
        # Render the form
        return render(request, self.get_template(), context)

    def post(self, request: HttpRequest, debt_test_id: int):
        # Get the initial objects
        debt_test = self.get_debt_test(debt_test_id)
        # Make sure the user is authorized
        user_has_permission_or_403(request.user, debt_test, Permissions.Debt_Item_Add)
        # Set up the initial context
        context = self.get_initial_context(request, debt_test)
        # Process the form
        _, request, success = self.process_forms(request, debt_test, context)
        # Handle the case of a successful form
        if success:
            if '_Finished' in request.POST:
                return HttpResponseRedirect(reverse('view_debt_test', args=(debt_test.id,)))
            else:
                return HttpResponseRedirect(reverse('add_debt_items', args=(debt_test.id,)))
        else:
            context["form_error"] = True
        # Render the form
        return render(request, self.get_template(), context)


@user_is_authorized(Debt_Test, Permissions.Debt_Item_Add, 'tid')
def add_temp_debt_item(request, tid, fid):
    jform = None
    debt_test = get_object_or_404(Debt_Test, id=tid)
    debt_item = get_object_or_404(Debt_Item_Template, id=fid)
    debt_items = Debt_Item_Template.objects.all()
    push_all_jira_issues = jira_helper.is_push_all_issues(debt_item)

    if request.method == 'POST':

        form = AddDebtItemForm(request.POST, req_resp=None, debt_context=debt_test.debt_engagement.debt_context)
        if jira_helper.get_jira_project(debt_test):
            jform = JIRADebtItemForm(push_all=jira_helper.is_push_all_issues(debt_test), prefix='jiraform', jira_project=jira_helper.get_jira_project(debt_test), debt_item_form=form)
            logger.debug('jform valid: %s', jform.is_valid())

        if (form['active'].value() is False or form['false_p'].value()) and form['duplicate'].value() is False:
            closing_disabled = Note_Type.objects.filter(is_mandatory=True, is_active=True).count()
            if closing_disabled != 0:
                error_inactive = ValidationError(
                    _('Can not set a debt_item as inactive without adding all mandatory notes'),
                    code='not_active_or_false_p_true')
                error_false_p = ValidationError(
                    _('Can not set a debt_item as false positive without adding all mandatory notes'),
                    code='not_active_or_false_p_true')
                if form['active'].value() is False:
                    form.add_error('active', error_inactive)
                if form['false_p'].value():
                    form.add_error('false_p', error_false_p)
                messages.add_message(request,
                                     messages.ERROR,
                                     _('Can not set a debt_item as inactive or false positive without adding all mandatory notes'),
                                     extra_tags='alert-danger')
        if form.is_valid():
            debt_item.last_used = timezone.now()
            debt_item.save()
            new_debt_item = form.save(commit=False)
            new_debt_item.debt_test = debt_test
            new_debt_item.reporter = request.user
            new_debt_item.numerical_severity = Debt_Item.get_numerical_severity(
                new_debt_item.severity)

            new_debt_item.tags = form.cleaned_data['tags']
            new_debt_item.date = form.cleaned_data['date'] or datetime.today()

            debt_item_helper.update_debt_item_status(new_debt_item, request.user)

            new_debt_item.save(dedupe_option=False)

            # Save and add new endpoints
            debt_item_helper.add_endpoints(new_debt_item, form)

            new_debt_item.save()
            if 'jiraform-push_to_jira' in request.POST:
                jform = JIRADebtItemForm(request.POST, prefix='jiraform', instance=new_debt_item, push_all=push_all_jira_issues, jira_project=jira_helper.get_jira_project(debt_test), debt_item_form=form)
                if jform.is_valid():
                    if jform.cleaned_data.get('push_to_jira'):
                        jira_helper.push_to_jira(new_debt_item)
                else:
                    add_error_message_to_response('jira form validation failed: %s' % jform.errors)
            if 'request' in form.cleaned_data or 'response' in form.cleaned_data:
                burp_rr = BurpRawRequestResponse(
                    debt_item=new_debt_item,
                    burpRequestBase64=base64.b64encode(form.cleaned_data.get('request', '').encode("utf-8")),
                    burpResponseBase64=base64.b64encode(form.cleaned_data.get('response', '').encode("utf-8")),
                )
                burp_rr.clean()
                burp_rr.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 _('Debt_Item from template added successfully.'),
                                 extra_tags='alert-success')

            return HttpResponseRedirect(reverse('view_debt_test', args=(debt_test.id,)))
        else:
            messages.add_message(request,
                                 messages.ERROR,
                                 _('The form has errors, please correct them below.'),
                                 extra_tags='alert-danger')

    else:
        form = AddDebtItemForm(req_resp=None, debt_context=debt_test.debt_engagement.debt_context, initial={'active': False,
                                    'date': timezone.now().date(),
                                    'verified': False,
                                    'false_p': False,
                                    'duplicate': False,
                                    'out_of_scope': False,
                                    'title': debt_item.title,
                                    'description': debt_item.description,
                                    'cwe': debt_item.cwe,
                                    'severity': debt_item.severity,
                                    'mitigation': debt_item.mitigation,
                                    'impact': debt_item.impact,
                                    'references': debt_item.references,
                                    'numerical_severity': debt_item.numerical_severity})

        if jira_helper.get_jira_project(debt_test):
            jform = JIRADebtItemForm(push_all=jira_helper.is_push_all_issues(debt_test), prefix='jiraform', jira_project=jira_helper.get_jira_project(debt_test), debt_item_form=form)

    # logger.debug('form valid: %s', form.is_valid())
    # logger.debug('jform valid: %s', jform.is_valid())
    # logger.debug('form errors: %s', form.errors)
    # logger.debug('jform errors: %s', jform.errors)
    # logger.debug('jform errors: %s', vars(jform))

    debt_context_tab = Debt_Context_Tab(debt_test.debt_engagement.debt_context, title=_("Add Debt_Item"), tab="debt_engagements")
    debt_context_tab.setDebt_Engagement(debt_test.debt_engagement)
    return render(request, 'dojo/add_debt_items.html',
                  {'form': form,
                   'debt_context_tab': debt_context_tab,
                   'jform': jform,
                   'debt_items': debt_items,
                   'temp': True,
                   'fid': debt_item.id,
                   'tid': debt_test.id,
                   'debt_test': debt_test,
                   })


@user_is_authorized(Debt_Test, Permissions.Debt_Test_View, 'tid')
def search(request, tid):
    debt_test = get_object_or_404(Debt_Test, id=tid)
    templates = Debt_Item_Template.objects.all()
    templates = TemplateDebtItemFilter(request.GET, queryset=templates)
    paged_templates = get_page_items(request, templates.qs, 25)

    title_words = get_words_for_field(Debt_Item_Template, 'title')

    add_breadcrumb(parent=debt_test, title=_("Add From Template"), top_level=False, request=request)
    return render(request, 'dojo/templates.html',
                  {'templates': paged_templates,
                   'filtered': templates,
                   'title_words': title_words,
                   'tid': tid,
                   'add_from_template': True,
                   })


@user_is_authorized(Debt_Test, Permissions.Import_Scan_Result, 'tid')
def re_import_scan_results(request, tid):
    additional_message = _("When re-uploading a scan, any debt_items not found in original scan will be updated as "
                           "mitigated.  The process attempts to identify the differences, however manual verification "
                           "is highly recommended.")
    debt_test = get_object_or_404(Debt_Test, id=tid)
    # by default we keep a trace of the scan_type used to create the debt_test
    # if it's not here, we use the "name" of the debt_test type
    # this feature exists to provide custom label for debt_tests for some parsers
    if debt_test.scan_type:
        scan_type = debt_test.scan_type
    else:
        scan_type = debt_test.debt_test_type.name
    debt_engagement = debt_test.debt_engagement
    form = ReImportScanForm(debt_test=debt_test)
    jform = None
    jira_project = jira_helper.get_jira_project(debt_test)
    push_all_jira_issues = jira_helper.is_push_all_issues(debt_test)

    # Decide if we need to present the Push to JIRA form
    if get_system_setting('enable_jira') and jira_project:
        jform = JIRAImportScanForm(push_all=push_all_jira_issues, prefix='jiraform')

    if request.method == "POST":
        form = ReImportScanForm(request.POST, request.FILES, debt_test=debt_test)
        if jira_project:
            jform = JIRAImportScanForm(request.POST, push_all=push_all_jira_issues, prefix='jiraform')
        if form.is_valid() and (jform is None or jform.is_valid()):
            scan_date = form.cleaned_data['scan_date']

            minimum_severity = form.cleaned_data['minimum_severity']
            scan = request.FILES.get('file', None)
            activeChoice = form.cleaned_data.get('active', None)
            verifiedChoice = form.cleaned_data.get('verified', None)
            do_not_reactivate = form.cleaned_data['do_not_reactivate']
            tags = form.cleaned_data['tags']
            version = form.cleaned_data.get('version', None)
            branch_tag = form.cleaned_data.get('branch_tag', None)
            build_id = form.cleaned_data.get('build_id', None)
            commit_hash = form.cleaned_data.get('commit_hash', None)
            api_scan_configuration = form.cleaned_data.get('api_scan_configuration', None)
            service = form.cleaned_data.get('service', None)

            endpoints_to_add = None  # not available on reimport UI

            close_old_debt_items = form.cleaned_data.get('close_old_debt_items', True)

            group_by = form.cleaned_data.get('group_by', None)
            create_debt_item_groups_for_all_debt_items = form.cleaned_data.get('create_debt_item_groups_for_all_debt_items')

            active = None
            if activeChoice:
                if activeChoice == 'force_to_true':
                    active = True
                elif activeChoice == 'force_to_false':
                    active = False
            verified = None
            if verifiedChoice:
                if verifiedChoice == 'force_to_true':
                    verified = True
                elif verifiedChoice == 'force_to_false':
                    verified = False

            # Tags are replaced, same behaviour as with django-tagging
            debt_test.tags = tags
            debt_test.version = version
            if scan and is_scan_file_too_large(scan):
                messages.add_message(request,
                                     messages.ERROR,
                                     _("Report file is too large. Maximum supported size is %(size)d MB") % {'size': settings.SCAN_FILE_MAX_SIZE},
                                     extra_tags='alert-danger')
                return HttpResponseRedirect(reverse('re_import_scan_results', args=(debt_test.id,)))

            push_to_jira = push_all_jira_issues or (jform and jform.cleaned_data.get('push_to_jira'))
            error = False
            debt_item_count, new_debt_item_count, closed_debt_item_count, reactivated_debt_item_count, untouched_debt_item_count = 0, 0, 0, 0, 0
            reimporter = ReImporter()
            try:
                debt_test, debt_item_count, new_debt_item_count, closed_debt_item_count, reactivated_debt_item_count, untouched_debt_item_count, debt_test_import = \
                    reimporter.reimport_scan(scan, scan_type, debt_test, active=active, verified=verified,
                                                tags=None, minimum_severity=minimum_severity,
                                                endpoints_to_add=endpoints_to_add, scan_date=scan_date,
                                                version=version, branch_tag=branch_tag, build_id=build_id,
                                                commit_hash=commit_hash, push_to_jira=push_to_jira,
                                                close_old_debt_items=close_old_debt_items, group_by=group_by,
                                                api_scan_configuration=api_scan_configuration, service=service, do_not_reactivate=do_not_reactivate,
                                                create_debt_item_groups_for_all_debt_items=create_debt_item_groups_for_all_debt_items)
            except Exception as e:
                logger.exception(e)
                add_error_message_to_response('An exception error occurred during the report import:%s' % str(e))
                error = True

            if not error:
                message = construct_imported_message(scan_type, debt_item_count, new_debt_item_count=new_debt_item_count,
                                                        closed_debt_item_count=closed_debt_item_count,
                                                        reactivated_debt_item_count=reactivated_debt_item_count,
                                                        untouched_debt_item_count=untouched_debt_item_count)
                add_success_message_to_response(message)

            return HttpResponseRedirect(reverse('view_debt_test', args=(debt_test.id,)))

    debt_context_tab = Debt_Context_Tab(debt_engagement.debt_context, title=_("Re-upload a %(scan_type)s") % {"scan_type": scan_type}, tab="debt_engagements")
    debt_context_tab.setDebt_Engagement(debt_engagement)
    form.fields['endpoints'].queryset = Endpoint.objects.filter(debt_context__id=debt_context_tab.debt_context.id)
    form.initial['api_scan_configuration'] = debt_test.api_scan_configuration
    form.fields['api_scan_configuration'].queryset = Debt_Context_API_Scan_Configuration.objects.filter(debt_context__id=debt_context_tab.debt_context.id)
    return render(request,
                  'dojo/import_scan_results.html',
                  {'form': form,
                   'debt_context_tab': debt_context_tab,
                   'eid': debt_engagement.id,
                   'additional_message': additional_message,
                   'jform': jform,
                   'scan_types': get_scan_types_sorted(),
                   })
