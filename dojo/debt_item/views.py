# #  debt_items
import base64
import json
import logging
import mimetypes
import contextlib
from collections import OrderedDict, defaultdict
from django.db import models
from django.db.models.functions import Length
from django.conf import settings
from django.contrib import messages
from django.core.exceptions import PermissionDenied, ValidationError
from django.core import serializers
from django.urls import reverse
from django.http import Http404, HttpResponse, JsonResponse, HttpRequest
from django.http import HttpResponseRedirect
from django.http import StreamingHttpResponse
from django.shortcuts import render, get_object_or_404
from django.utils import formats
from django.utils.safestring import mark_safe
from django.utils import timezone
from django.views.decorators.http import require_POST
from django.views import View
from itertools import chain
from imagekit import ImageSpec
from imagekit.processors import ResizeToFill
from dojo.utils import (
    add_error_message_to_response,
    add_field_errors_to_response,
    add_success_message_to_response,
    close_external_issue,
    redirect,
    reopen_external_issue,
    do_false_positive_history,
    match_debt_item_to_existing_debt_items,
    get_page_items_and_count,
)
import copy
from dojo.filters import (
    TemplateDebtItemFilter,
    SimilarDebtItemFilter,
    DebtItemFilter,
    AcceptedDebtItemFilter,
    TestImportDebtItemActionFilter,
    TestImportFilter,
)
from dojo.forms import (
    EditPlannedRemediationDateDebtItemForm,
    NoteForm,
    TypedNoteForm,
    CloseDebtItemForm,
    DebtItemForm,
    PromoteDebtItemForm,
    DebtItemTemplateForm,
    DeleteDebtItemTemplateForm,
    JIRADebtItemForm,
    GITHUBDebtItemForm,
    ReviewDebtItemForm,
    ClearDebtItemReviewForm,
    DefectDebtItemForm,
    StubDebtItemForm,
    DeleteDebtItemForm,
    DeleteStubDebtItemForm,
    ApplyDebtItemTemplateForm,
    DebtItemFormID,
    DebtItemBulkUpdateForm,
    MergeDebtItems,
    CopyDebtItemForm,
)
from dojo.models import (
    IMPORT_UNTOUCHED_DEBT_ITEM,
    Debt_Item,
    Debt_Item_Group,
    Notes,
    NoteHistory,
    Note_Type,
    BurpRawRequestResponse,
    Stub_Debt_Item,
    Endpoint,
    Debt_Item_Template,
    Endpoint_Status,
    FileAccessToken,
    GITHUB_PKey,
    GITHUB_Issue,
    Dojo_User,
    Cred_Mapping,
    Test,
    Product,
    Test_Import,
    Test_Import_Debt_Item_Action,
    User,
    Engagement,
    Vulnerability_Id_Template,
    System_Settings,
)
from dojo.utils import (
    get_page_items,
    add_breadcrumb,
    FileIterWrapper,
    process_notifications,
    get_system_setting,
    apply_cwe_to_template,
    Product_Tab,
    debt_calculate_grade,
    redirect_to_return_url_or_else,
    get_return_url,
    add_external_issue,
    update_external_issue,
    get_words_for_field,
)
from dojo.notifications.helper import create_notification

from django.template.defaultfilters import pluralize
from django.db.models import Q, QuerySet, Count
from django.db.models.query import Prefetch
import dojo.jira_link.helper as jira_helper
import dojo.risk_acceptance.helper as ra_helper
import dojo.debt_item.helper as debt_item_helper
from dojo.authorization.authorization import user_has_permission_or_403
from dojo.authorization.authorization_decorators import (
    user_is_authorized,
    user_has_global_permission,
)
from dojo.authorization.roles_permissions import Permissions
from dojo.debt_item.queries import get_authorized_debt_items
from dojo.test.queries import get_authorized_tests

JFORM_PUSH_TO_JIRA_MESSAGE = "jform.push_to_jira: %s"

logger = logging.getLogger(__name__)


def prefetch_for_debt_items(debt_items, prefetch_type="all", exclude_untouched=True):
    prefetched_debt_items = debt_items
    if isinstance(
        debt_items, QuerySet
    ):  # old code can arrive here with debt_contexts being a list because the query was already executed
        prefetched_debt_items = prefetched_debt_items.prefetch_related("reporter")
        prefetched_debt_items = prefetched_debt_items.prefetch_related(
            "jira_issue__jira_project__jira_instance"
        )
        prefetched_debt_items = prefetched_debt_items.prefetch_related("test__test_type")
        prefetched_debt_items = prefetched_debt_items.prefetch_related(
            "test__engagement__jira_project__jira_instance"
        )
        prefetched_debt_items = prefetched_debt_items.prefetch_related(
            "test__engagement__debt_context__jira_project_set__jira_instance"
        )
        prefetched_debt_items = prefetched_debt_items.prefetch_related("found_by")

        # for open/active debt_items the following 4 prefetches are not needed
        if prefetch_type != "open":
            prefetched_debt_items = prefetched_debt_items.prefetch_related(
                "risk_acceptance_set"
            )
            prefetched_debt_items = prefetched_debt_items.prefetch_related(
                "risk_acceptance_set__accepted_debt_items"
            )
            prefetched_debt_items = prefetched_debt_items.prefetch_related(
                "original_debt_item"
            )
            prefetched_debt_items = prefetched_debt_items.prefetch_related(
                "duplicate_debt_item"
            )

        if exclude_untouched:
            # filter out noop reimport actions from debt_item status history
            prefetched_debt_items = prefetched_debt_items.prefetch_related(
                Prefetch(
                    "test_import_debt_item_action_set",
                    queryset=Test_Import_Debt_Item_Action.objects.exclude(
                        action=IMPORT_UNTOUCHED_DEBT_ITEM
                    ),
                )
            )
        else:
            prefetched_debt_items = prefetched_debt_items.prefetch_related(
                "test_import_debt_item_action_set"
            )
        """
        we could try to prefetch only the latest note with SubQuery and OuterRef,
        but I'm getting that MySql doesn't support limits in subqueries.
        """
        prefetched_debt_items = prefetched_debt_items.prefetch_related("notes")
        prefetched_debt_items = prefetched_debt_items.prefetch_related("tags")
        prefetched_debt_items = prefetched_debt_items.prefetch_related("endpoints")
        prefetched_debt_items = prefetched_debt_items.prefetch_related("status_debt_item")
        prefetched_debt_items = prefetched_debt_items.annotate(
            active_endpoint_count=Count(
                "status_debt_item__id", filter=Q(status_debt_item__mitigated=False)
            )
        )
        prefetched_debt_items = prefetched_debt_items.annotate(
            mitigated_endpoint_count=Count(
                "status_debt_item__id", filter=Q(status_debt_item__mitigated=True)
            )
        )
        prefetched_debt_items = prefetched_debt_items.prefetch_related("debt_item_group_set")
        prefetched_debt_items = prefetched_debt_items.prefetch_related(
            "test__engagement__debt_context__members"
        )
        prefetched_debt_items = prefetched_debt_items.prefetch_related(
            "test__engagement__debt_context__debt_context_type__members"
        )
        prefetched_debt_items = prefetched_debt_items.prefetch_related(
            "vulnerability_id_set"
        )
    else:
        logger.debug("unable to prefetch because query was already executed")

    return prefetched_debt_items


def prefetch_for_similar_debt_items(debt_items):
    prefetched_debt_items = debt_items
    if isinstance(
        debt_items, QuerySet
    ):  # old code can arrive here with debt_contexts being a list because the query was already executed
        prefetched_debt_items = prefetched_debt_items.prefetch_related("reporter")
        prefetched_debt_items = prefetched_debt_items.prefetch_related(
            "jira_issue__jira_project__jira_instance"
        )
        prefetched_debt_items = prefetched_debt_items.prefetch_related("test__test_type")
        prefetched_debt_items = prefetched_debt_items.prefetch_related(
            "test__engagement__jira_project__jira_instance"
        )
        prefetched_debt_items = prefetched_debt_items.prefetch_related(
            "test__engagement__debt_context__jira_project_set__jira_instance"
        )
        prefetched_debt_items = prefetched_debt_items.prefetch_related("found_by")
        prefetched_debt_items = prefetched_debt_items.prefetch_related(
            "risk_acceptance_set"
        )
        prefetched_debt_items = prefetched_debt_items.prefetch_related(
            "risk_acceptance_set__accepted_debt_items"
        )
        prefetched_debt_items = prefetched_debt_items.prefetch_related("original_debt_item")
        prefetched_debt_items = prefetched_debt_items.prefetch_related("duplicate_debt_item")
        # filter out noop reimport actions from debt_item status history
        prefetched_debt_items = prefetched_debt_items.prefetch_related(
            Prefetch(
                "test_import_debt_item_action_set",
                queryset=Test_Import_Debt_Item_Action.objects.exclude(
                    action=IMPORT_UNTOUCHED_DEBT_ITEM
                ),
            )
        )
        """
        we could try to prefetch only the latest note with SubQuery and OuterRef,
        but I'm getting that MySql doesn't support limits in subqueries.
        """
        prefetched_debt_items = prefetched_debt_items.prefetch_related("notes")
        prefetched_debt_items = prefetched_debt_items.prefetch_related("tags")
        prefetched_debt_items = prefetched_debt_items.prefetch_related(
            "vulnerability_id_set"
        )
    else:
        logger.debug("unable to prefetch because query was already executed")

    return prefetched_debt_items


class BaseListdebt_items:
    def __init__(
        self,
        filter_name: str = "All",
        debt_context_id: int = None,
        engagement_id: int = None,
        test_id: int = None,
        order_by: str = "numerical_severity",
        prefetch_type: str = "all",
    ):
        self.filter_name = filter_name
        self.debt_context_id = debt_context_id
        self.engagement_id = engagement_id
        self.test_id = test_id
        self.order_by = order_by
        self.prefetch_type = prefetch_type

    def get_filter_name(self):
        if not hasattr(self, "filter_name"):
            self.filter_name = "All"
        return self.filter_name

    def get_order_by(self):
        if not hasattr(self, "order_by"):
            self.order_by = "numerical_severity"
        return self.order_by

    def get_prefetch_type(self):
        if not hasattr(self, "prefetch_type"):
            self.prefetch_type = "all"
        return self.prefetch_type

    def get_debt_context_id(self):
        if not hasattr(self, "debt_context_id"):
            self.debt_context_id = None
        return self.debt_context_id

    def get_engagement_id(self):
        if not hasattr(self, "engagement_id"):
            self.engagement_id = None
        return self.engagement_id

    def get_test_id(self):
        if not hasattr(self, "test_id"):
            self.test_id = None
        return self.test_id

    def filter_debt_items_by_object(self, debt_items: QuerySet[Debt_Item]):
        if debt_context_id := self.get_debt_context_id():
            return debt_items.filter(test__engagement__debt_context__id=debt_context_id)
        elif engagement_id := self.get_engagement_id():
            return debt_items.filter(test__engagement=engagement_id)
        elif test_id := self.get_test_id():
            return debt_items.filter(test=test_id)
        else:
            return debt_items

    def filter_debt_items_by_filter_name(self, debt_items: QuerySet[Debt_Item]):
        filter_name = self.get_filter_name()
        if filter_name == "Open":
            return debt_items.filter(debt_item_helper.OPEN_DEBT_ITEMS_QUERY)
        elif filter_name == "Verified":
            return debt_items.filter(debt_item_helper.VERIFIED_DEBT_ITEMS_QUERY)
        elif filter_name == "Out of Scope":
            return debt_items.filter(debt_item_helper.OUT_OF_SCOPE_DEBT_ITEMS_QUERY)
        elif filter_name == "False Positive":
            return debt_items.filter(debt_item_helper.FALSE_POSITIVE_DEBT_ITEMS_QUERY)
        elif filter_name == "Inactive":
            return debt_items.filter(debt_item_helper.INACTIVE_DEBT_ITEMS_QUERY)
        elif filter_name == "Accepted":
            return debt_items.filter(debt_item_helper.ACCEPTED_DEBT_ITEMS_QUERY)
        elif filter_name == "Closed":
            return debt_items.filter(debt_item_helper.CLOSED_DEBT_ITEMS_QUERY)
        else:
            return debt_items

    def filter_debt_items_by_form(self, request: HttpRequest, debt_items: QuerySet[Debt_Item]):
        # Set up the args for the form
        args = [request.GET, debt_items]
        # Set the initial form args
        kwargs = {
            "user": request.user,
            "pid": self.get_debt_context_id(),
        }

        return (
            AcceptedDebtItemFilter(*args, **kwargs)
            if self.get_filter_name() == "Accepted"
            else DebtItemFilter(*args, **kwargs)
        )

    def get_filtered_debt_items(self):
        debt_items = get_authorized_debt_items(Permissions.Debt_Item_View).order_by(self.get_order_by())
        debt_items = self.filter_debt_items_by_object(debt_items)
        debt_items = self.filter_debt_items_by_filter_name(debt_items)

        return debt_items

    def get_fully_filtered_debt_items(self, request: HttpRequest):
        debt_items = self.get_filtered_debt_items()
        return self.filter_debt_items_by_form(request, debt_items)


class Listdebt_items(View, BaseListdebt_items):
    def get_initial_context(self, request: HttpRequest):
        context = {
            "filter_name": self.get_filter_name(),
            "show_debt_context_column": True,
            "custom_breadcrumb": None,
            "debt_context_tab": None,
            "jira_project": None,
            "github_config": None,
            "bulk_edit_form": DebtItemBulkUpdateForm(request.GET),
            "title_words": get_words_for_field(Debt_Item, "title"),
            "component_words": get_words_for_field(Debt_Item, "component_name"),
        }
        # Look to see if the debt_context was used
        if debt_context_id := self.get_debt_context_id():
            debt_context = get_object_or_404(Product, id=debt_context_id)
            user_has_permission_or_403(request.user, debt_context, Permissions.Product_View)
            context["show_debt_context_column"] = False
            context["debt_context_tab"] = Product_Tab(debt_context, title="debt_items", tab="debt_items")
            context["jira_project"] = jira_helper.get_jira_project(debt_context)
            if github_config := GITHUB_PKey.objects.filter(debt_context=debt_context).first():
                context["github_config"] = github_config.git_conf_id
        elif engagement_id := self.get_engagement_id():
            engagement = get_object_or_404(Engagement, id=engagement_id)
            user_has_permission_or_403(request.user, engagement, Permissions.Engagement_View)
            context["show_debt_context_column"] = False
            context["debt_context_tab"] = Product_Tab(engagement.debt_context, title=engagement.name, tab="engagements")
            context["jira_project"] = jira_helper.get_jira_project(engagement)
            if github_config := GITHUB_PKey.objects.filter(debt_context__engagement=engagement).first():
                context["github_config"] = github_config.git_conf_id

        return request, context

    def get_template(self):
        return "dojo/debt_items_list.html"

    def add_breadcrumbs(self, request: HttpRequest, context: dict):
        # show custom breadcrumb if user has filtered by exactly 1 endpoint
        if "endpoints" in request.GET:
            endpoint_ids = request.GET.getlist("endpoints", [])
            if len(endpoint_ids) == 1 and endpoint_ids[0] != '':
                endpoint_id = endpoint_ids[0]
                endpoint = get_object_or_404(Endpoint, id=endpoint_id)
                context["filter_name"] = "Vulnerable Endpoints"
                context["custom_breadcrumb"] = OrderedDict(
                    [
                        ("Endpoints", reverse("vulnerable_endpoints")),
                        (endpoint, reverse("view_endpoint", args=(endpoint.id,))),
                    ]
                )
        # Show the "All debt_items" breadcrumb if nothing is coming from the debt_context or engagement
        elif not self.get_engagement_id() and not self.get_debt_context_id():
            add_breadcrumb(title="debt_items", top_level=not len(request.GET), request=request)

        return request, context

    def get(self, request: HttpRequest, debt_context_id: int = None, engagement_id: int = None):
        # Store the debt_context and engagement ids
        self.debt_context_id = debt_context_id
        self.engagement_id = engagement_id
        # Get the initial context
        request, context = self.get_initial_context(request)
        # Get the filtered debt_items
        filtered_debt_items = self.get_fully_filtered_debt_items(request)
        # trick to prefetch after paging to avoid huge join generated by select count(*) from Paginator
        paged_debt_items = get_page_items(request, filtered_debt_items.qs, 25)
        # prefetch the related objects in the debt_items
        paged_debt_items.object_list = prefetch_for_debt_items(
            paged_debt_items.object_list,
            self.get_prefetch_type())
        # Add some breadcrumbs
        request, context = self.add_breadcrumbs(request, context)
        # Add the filtered and paged debt_items into the context
        context |= {
            "debt_items": paged_debt_items,
            "filtered": filtered_debt_items,
        }
        # Render the view
        return render(request, self.get_template(), context)


class ListOpendebt_items(Listdebt_items):
    def get(self, request: HttpRequest, debt_context_id: int = None, engagement_id: int = None):
        self.filter_name = "Open"
        return super().get(request, debt_context_id=debt_context_id, engagement_id=engagement_id)


class ListVerifieddebt_items(Listdebt_items):
    def get(self, request: HttpRequest, debt_context_id: int = None, engagement_id: int = None):
        self.filter_name = "Verified"
        return super().get(request, debt_context_id=debt_context_id, engagement_id=engagement_id)


class ListOutOfScopedebt_items(Listdebt_items):
    def get(self, request: HttpRequest, debt_context_id: int = None, engagement_id: int = None):
        self.filter_name = "Out of Scope"
        return super().get(request, debt_context_id=debt_context_id, engagement_id=engagement_id)


class ListFalsePositivedebt_items(Listdebt_items):
    def get(self, request: HttpRequest, debt_context_id: int = None, engagement_id: int = None):
        self.filter_name = "False Positive"
        return super().get(request, debt_context_id=debt_context_id, engagement_id=engagement_id)


class ListInactivedebt_items(Listdebt_items):
    def get(self, request: HttpRequest, debt_context_id: int = None, engagement_id: int = None):
        self.filter_name = "Inactive"
        return super().get(request, debt_context_id=debt_context_id, engagement_id=engagement_id)


class ListAccepteddebt_items(Listdebt_items):
    def get(self, request: HttpRequest, debt_context_id: int = None, engagement_id: int = None):
        self.filter_name = "Accepted"
        return super().get(request, debt_context_id=debt_context_id, engagement_id=engagement_id)


class ListCloseddebt_items(Listdebt_items):
    def get(self, request: HttpRequest, debt_context_id: int = None, engagement_id: int = None):
        self.filter_name = "Closed"
        self.order_by = "-mitigated"
        return super().get(request, debt_context_id=debt_context_id, engagement_id=engagement_id)


class Viewdebt_item(View):
    def get_debt_item(self, debt_item_id: int):
        debt_item_qs = prefetch_for_debt_items(Debt_Item.objects.all(), exclude_untouched=False)
        return get_object_or_404(debt_item_qs, id=debt_item_id)

    def get_dojo_user(self, request: HttpRequest):
        user = request.user
        return get_object_or_404(Dojo_User, id=user.id)

    def get_previous_and_next_debt_items(self, debt_item: Debt_Item):
        # Get the whole list of debt_items in the current test
        debt_items = (
            debt_item.objects.filter(test=debt_item.test)
            .order_by("numerical_severity")
            .values_list("id", flat=True)
        )
        logger.debug(debt_items)
        # Set some reasonable defaults
        next_debt_item_id = debt_item.id
        prev_debt_item_id = debt_item.id
        last_pos = (len(debt_items)) - 1
        # get the index of the current debt_item
        current_debt_item_index = list(debt_items).index(debt_item.id)
        # Try to get the previous ID
        with contextlib.suppress(IndexError, ValueError):
            prev_debt_item_id = debt_items[current_debt_item_index - 1]
        # Try to get the next ID
        with contextlib.suppress(IndexError, ValueError):
            next_debt_item_id = debt_items[current_debt_item_index + 1]

        return {
            "prev_debt_item_id": prev_debt_item_id,
            "next_debt_item_id": next_debt_item_id,
            "debt_items_list": debt_items,
            "debt_items_list_lastElement": debt_items[last_pos],
        }

    def get_credential_objects(self, debt_item: Debt_Item):
        cred = (
            Cred_Mapping.objects.filter(test=debt_item.test.id)
            .select_related("cred_id")
            .order_by("cred_id")
        )
        cred_engagement = (
            Cred_Mapping.objects.filter(engagement=debt_item.test.engagement.id)
            .select_related("cred_id")
            .order_by("cred_id")
        )
        cred_debt_item = (
            Cred_Mapping.objects.filter(debt_item=debt_item.id)
            .select_related("cred_id")
            .order_by("cred_id")
        )

        return {
            "cred_debt_item": cred_debt_item,
            "cred": cred,
            "cred_engagement": cred_engagement,
        }

    def get_cwe_template(self, debt_item: Debt_Item):
        cwe_template = None
        with contextlib.suppress(Debt_Item_Template.DoesNotExist):
            cwe_template = Debt_Item_Template.objects.filter(cwe=debt_item.cwe).first()

        return {
            "cwe_template": cwe_template
        }

    def get_request_response(self, debt_item: Debt_Item):
        request_response = None
        burp_request = None
        burp_response = None
        try:
            request_response = BurpRawRequestResponse.objects.filter(debt_item=debt_item).first()
            if request_response is not None:
                burp_request = base64.b64decode(request_response.burpRequestBase64)
                burp_response = base64.b64decode(request_response.burpResponseBase64)
        except Exception as e:
            logger.debug(f"unsuspected error: {e}")

        return {
            "burp_request": burp_request,
            "burp_response": burp_response,
        }

    def get_test_import_data(self, request: HttpRequest, debt_item: Debt_Item):
        test_imports = Test_Import.objects.filter(debt_items_affected=debt_item)
        test_import_filter = TestImportFilter(request.GET, test_imports)

        test_import_debt_item_actions = debt_item.test_import_debt_item_action_set
        test_import_debt_item_actions_count = test_import_debt_item_actions.all().count()
        test_import_debt_item_actions = test_import_debt_item_actions.filter(test_import__in=test_import_filter.qs)
        test_import_debt_item_action_filter = TestImportDebtItemActionFilter(request.GET, test_import_debt_item_actions)

        paged_test_import_debt_item_actions = get_page_items_and_count(request, test_import_debt_item_action_filter.qs, 5, prefix='test_import_debt_item_actions')
        paged_test_import_debt_item_actions.object_list = paged_test_import_debt_item_actions.object_list.prefetch_related('test_import')

        latest_test_import_debt_item_action = debt_item.test_import_debt_item_action_set.order_by('-created').first

        return {
            "test_import_filter": test_import_filter,
            "test_import_debt_item_action_filter": test_import_debt_item_action_filter,
            "paged_test_import_debt_item_actions": paged_test_import_debt_item_actions,
            "latest_test_import_debt_item_action": latest_test_import_debt_item_action,
            "test_import_debt_item_actions_count": test_import_debt_item_actions_count,
        }

    def get_similar_debt_items(self, request: HttpRequest, debt_item: Debt_Item):
        # add related actions for non-similar and non-duplicate cluster members
        debt_item.related_actions = calculate_possible_related_actions_for_similar_debt_item(
            request, debt_item, debt_item
        )
        if debt_item.duplicate_debt_item:
            debt_item.duplicate_debt_item.related_actions = (
                calculate_possible_related_actions_for_similar_debt_item(
                    request, debt_item, debt_item.duplicate_debt_item
                )
            )
        similar_debt_items_filter = SimilarDebtItemFilter(
            request.GET,
            queryset=get_authorized_debt_items(Permissions.Debt_Item_View),
            user=request.user,
            debt_item=debt_item,
        )
        logger.debug("similar query: %s", similar_debt_items_filter.qs.query)
        similar_debt_items = get_page_items(
            request,
            similar_debt_items_filter.qs,
            settings.SIMILAR_debt_itemS_MAX_RESULTS,
            prefix="similar",
        )
        similar_debt_items.object_list = prefetch_for_similar_debt_items(
            similar_debt_items.object_list
        )
        for similar_debt_item in similar_debt_items:
            similar_debt_item.related_actions = (
                calculate_possible_related_actions_for_similar_debt_item(
                    request, debt_item, similar_debt_item
                )
            )

        return {
            "duplicate_cluster": duplicate_cluster(request, debt_item),
            "similar_debt_items": similar_debt_items,
            "similar_debt_items_filter": similar_debt_items_filter,
        }

    def get_jira_data(self, debt_item: Debt_Item):
        (
            can_be_pushed_to_jira,
            can_be_pushed_to_jira_error,
            error_code,
        ) = jira_helper.can_be_pushed_to_jira(debt_item)
        # Check the error code
        if error_code:
            logger.error(error_code)

        return {
            "can_be_pushed_to_jira": can_be_pushed_to_jira,
            "can_be_pushed_to_jira_error": can_be_pushed_to_jira_error,
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

    def process_form(self, request: HttpRequest, debt_item: Debt_Item, context: dict):
        if context["form"].is_valid():
            # Create the note object
            new_note = context["form"].save(commit=False)
            new_note.author = request.user
            new_note.date = timezone.now()
            new_note.save()
            # Add an entry to the note history
            history = NoteHistory(
                data=new_note.entry, time=new_note.date, current_editor=new_note.author
            )
            history.save()
            new_note.history.add(history)
            # Associate the note with the debt_item
            debt_item.notes.add(new_note)
            debt_item.last_reviewed = new_note.date
            debt_item.last_reviewed_by = context["user"]
            debt_item.save()
            # Determine if the note should be sent to jira
            if debt_item.has_jira_issue:
                jira_helper.add_comment(debt_item, new_note)
            elif debt_item.has_jira_group_issue:
                jira_helper.add_comment(debt_item.debt_item_group, new_note)
            # Send the notification of the note being added
            url = request.build_absolute_uri(
                reverse("view_debt_item", args=(debt_item.id,))
            )
            title = f"debt_item: {debt_item.title}"
            process_notifications(request, new_note, url, title)
            # Add a message to the request
            messages.add_message(
                request, messages.SUCCESS, "Note saved.", extra_tags="alert-success"
            )

            return request, True

        return request, False

    def get_initial_context(self, request: HttpRequest, debt_item: Debt_Item, user: Dojo_User):
        notes = debt_item.notes.all()
        note_type_activation = Note_Type.objects.filter(is_active=True).count()
        available_note_types = None
        if note_type_activation:
            available_note_types = find_available_notetypes(notes)
        # Set the current context
        context = {
            "debt_item": debt_item,
            "dojo_user": user,
            "user": request.user,
            "notes": notes,
            "files": debt_item.files.all(),
            "note_type_activation": note_type_activation,
            "available_note_types": available_note_types,
            "debt_context_tab": Product_Tab(
                debt_item.test.engagement.debt_context, title="View debt_item", tab="debt_items"
            )
        }
        # Set the form using the context, and then update the context
        form = self.get_form(request, context)
        context["form"] = form

        return context

    def get_template(self):
        return "dojo/view_debt_item.html"

    def get(self, request: HttpRequest, debt_item_id: int):
        # Get the initial objects
        debt_item = self.get_debt_item(debt_item_id)
        user = self.get_dojo_user(request)
        # Make sure the user is authorized
        user_has_permission_or_403(user, debt_item, Permissions.Debt_Item_View)
        # Set up the initial context
        context = self.get_initial_context(request, debt_item, user)
        # Add in the other extras
        context |= self.get_previous_and_next_debt_items(debt_item)
        context |= self.get_credential_objects(debt_item)
        context |= self.get_cwe_template(debt_item)
        # Add in more of the other extras
        context |= self.get_request_response(debt_item)
        context |= self.get_similar_debt_items(request, debt_item)
        context |= self.get_test_import_data(request, debt_item)
        context |= self.get_jira_data(debt_item)
        # Render the form
        return render(request, self.get_template(), context)

    def post(self, request: HttpRequest, debt_item_id):
        # Get the initial objects
        debt_item = self.get_debt_item(debt_item_id)
        user = self.get_dojo_user(request)
        # Make sure the user is authorized
        user_has_permission_or_403(user, debt_item, Permissions.Debt_Item_View)
        # Quick perms check to determine if the user has access to add a note to the debt_item
        user_has_permission_or_403(user, debt_item, Permissions.Note_Add)
        # Set up the initial context
        context = self.get_initial_context(request, debt_item, user)
        # Determine the validity of the form
        request, success = self.process_form(request, debt_item, context)
        # Handle the case of a successful form
        if success:
            return HttpResponseRedirect(reverse("view_debt_item", args=(debt_item_id,)))
        # Add in more of the other extras
        context |= self.get_request_response(debt_item)
        context |= self.get_similar_debt_items(request, debt_item)
        context |= self.get_test_import_data(request, debt_item)
        context |= self.get_jira_data(debt_item)
        # Render the form
        return render(request, self.get_template(), context)


class Editdebt_item(View):
    def get_debt_item(self, debt_item_id: int):
        return get_object_or_404(Debt_Item, id=debt_item_id)

    def get_request_response(self, debt_item: Debt_Item):
        req_resp = None
        if burp_rr := BurpRawRequestResponse.objects.filter(debt_item=debt_item).first():
            req_resp = (burp_rr.get_request(), burp_rr.get_response())

        return req_resp

    def get_debt_item_form(self, request: HttpRequest, debt_item: Debt_Item):
        # Get the burp request if available
        req_resp = self.get_request_response(debt_item)
        # Set up the args for the form
        args = [request.POST] if request.method == "POST" else []
        # Set the initial form args
        kwargs = {
            "instance": debt_item,
            "req_resp": req_resp,
            "can_edit_mitigated_data": debt_item_helper.can_edit_mitigated_data(request.user),
            "initial": {"vulnerability_ids": "\n".join(debt_item.vulnerability_ids)},
        }

        return DebtItemForm(*args, **kwargs)

    def get_jira_form(self, request: HttpRequest, debt_item: Debt_Item, debt_item_form: DebtItemForm = None):
        # Determine if jira should be used
        if (jira_project := jira_helper.get_jira_project(debt_item)) is not None:
            # Determine if push all debt_items is enabled
            push_all_debt_items = jira_helper.is_push_all_issues(debt_item)
            # Set up the args for the form
            args = [request.POST] if request.method == "POST" else []
            # Set the initial form args
            kwargs = {
                "push_all": push_all_debt_items,
                "prefix": "jiraform",
                "instance": debt_item,
                "jira_project": jira_project,
                "debt_item_form": debt_item_form,
            }

            return JIRADebtItemForm(*args, **kwargs)
        return None

    def get_github_form(self, request: HttpRequest, debt_item: Debt_Item):
        # Determine if github should be used
        if get_system_setting("enable_github"):
            # Ensure there is a github conf correctly configured for the debt_context
            config_present = GITHUB_PKey.objects.filter(debt_context=debt_item.test.engagement.debt_context)
            if config_present := config_present.exclude(git_conf_id=None):
                # Set up the args for the form
                args = [request.POST] if request.method == "POST" else []
                # Set the initial form args
                kwargs = {
                    "enabled": debt_item.has_github_issue(),
                    "prefix": "githubform"
                }

                return GITHUBDebtItemForm(*args, **kwargs)
        return None

    def get_initial_context(self, request: HttpRequest, debt_item: Debt_Item):
        # Get the debt_item form first since it is used in another place
        debt_item_form = self.get_debt_item_form(request, debt_item)
        return {
            "form": debt_item_form,
            "debt_item": debt_item,
            "jform": self.get_jira_form(request, debt_item, debt_item_form=debt_item_form),
            "gform": self.get_github_form(request, debt_item),
            "return_url": get_return_url(request),
            "debt_context_tab": Product_Tab(
                debt_item.test.engagement.debt_context, title="Edit debt_item", tab="debt_items"
            )
        }

    def validate_status_change(self, request: HttpRequest, debt_item: Debt_Item, context: dict):
        # If the debt_item is already not active, skip this extra validation
        if not debt_item.active:
            return request
        # Validate the proper notes are added for mitigation
        if (not context["form"]["active"].value() or context["form"]["false_p"].value() or context["form"]["out_of_scope"].value()) and not context["form"]["duplicate"].value():
            note_type_activation = Note_Type.objects.filter(is_active=True).count()
            closing_disabled = 0
            if note_type_activation:
                closing_disabled = len(get_missing_mandatory_notetypes(debt_item))
            if closing_disabled != 0:
                error_inactive = ValidationError(
                    "Can not set a debt_item as inactive without adding all mandatory notes",
                    code="inactive_without_mandatory_notes",
                )
                error_false_p = ValidationError(
                    "Can not set a debt_item as false positive without adding all mandatory notes",
                    code="false_p_without_mandatory_notes",
                )
                error_out_of_scope = ValidationError(
                    "Can not set a debt_item as out of scope without adding all mandatory notes",
                    code="out_of_scope_without_mandatory_notes",
                )
                if context["form"]["active"].value() is False:
                    context["form"].add_error("active", error_inactive)
                if context["form"]["false_p"].value():
                    context["form"].add_error("false_p", error_false_p)
                if context["form"]["out_of_scope"].value():
                    context["form"].add_error("out_of_scope", error_out_of_scope)
                messages.add_message(
                    request,
                    messages.ERROR,
                    ("Can not set a debt_item as inactive, "
                        "false positive or out of scope without adding all mandatory notes"),
                    extra_tags="alert-danger",
                )

        return request

    def process_mitigated_data(self, request: HttpRequest, debt_item: Debt_Item, context: dict):
        # If active is not checked and CAN_EDIT_MITIGATED_DATA,
        # mitigate the debt_item and the associated endpoints status
        if debt_item_helper.can_edit_mitigated_data(request.user) and ((
            context["form"]["active"].value() is False
            or context["form"]["false_p"].value()
            or context["form"]["out_of_scope"].value()
        ) and context["form"]["duplicate"].value() is False):
            now = timezone.now()
            debt_item.is_mitigated = True
            endpoint_status = debt_item.status_debt_item.all()
            for status in endpoint_status:
                status.mitigated_by = (
                    context["form"].cleaned_data.get("mitigated_by") or request.user
                )
                status.mitigated_time = (
                    context["form"].cleaned_data.get("mitigated") or now
                )
                status.mitigated = True
                status.last_modified = timezone.now()
                status.save()

    def process_false_positive_history(self, debt_item: Debt_Item):
        if get_system_setting("false_positive_history", False):
            # If the debt_item is being marked as a false positive we dont need to call the
            # fp history function because it will be called by the save function
            # If debt_item was a false positive and is being reactivated: retroactively reactivates all equal debt_items
            if debt_item.false_p and not debt_item.false_p and get_system_setting("retroactive_false_positive_history"):
                logger.debug('FALSE_POSITIVE_HISTORY: Reactivating existing debt_items based on: %s', debt_item)

                existing_fp_debt_items = match_debt_item_to_existing_debt_items(
                    debt_item, debt_context=debt_item.test.engagement.debt_context
                ).filter(false_p=True)

                for fp in existing_fp_debt_items:
                    logger.debug('FALSE_POSITIVE_HISTORY: Reactivating false positive %i: %s', fp.id, fp)
                    fp.active = debt_item.active
                    fp.verified = debt_item.verified
                    fp.false_p = False
                    fp.out_of_scope = debt_item.out_of_scope
                    fp.is_mitigated = debt_item.is_mitigated
                    fp.save_no_options()

    def process_burp_request_response(self, debt_item: Debt_Item, context: dict):
        if "request" in context["form"].cleaned_data or "response" in context["form"].cleaned_data:
            try:
                burp_rr, _ = BurpRawRequestResponse.objects.get_or_create(debt_item=debt_item)
            except BurpRawRequestResponse.MultipleObjectsReturned:
                burp_rr = BurpRawRequestResponse.objects.filter(debt_item=debt_item).first()
            burp_rr.burpRequestBase64 = base64.b64encode(
                context["form"].cleaned_data["request"].encode()
            )
            burp_rr.burpResponseBase64 = base64.b64encode(
                context["form"].cleaned_data["response"].encode()
            )
            burp_rr.clean()
            burp_rr.save()

    def process_debt_item_form(self, request: HttpRequest, debt_item: Debt_Item, context: dict):
        if context["form"].is_valid():
            # process some of the easy stuff first
            new_debt_item = context["form"].save(commit=False)
            new_debt_item.test = debt_item.test
            new_debt_item.numerical_severity = debt_item.get_numerical_severity(new_debt_item.severity)
            new_debt_item.last_reviewed = timezone.now()
            new_debt_item.last_reviewed_by = request.user
            new_debt_item.tags = context["form"].cleaned_data["tags"]
            # Handle group related things
            if "group" in context["form"].cleaned_data:
                debt_item_group = context["form"].cleaned_data["group"]
                debt_item_helper.update_debt_item_group(new_debt_item, debt_item_group)
            # Handle risk exception related things
            if "risk_accepted" in context["form"].cleaned_data and context["form"]["risk_accepted"].value():
                if new_debt_item.test.engagement.debt_context.enable_simple_risk_acceptance:
                    ra_helper.simple_risk_accept(new_debt_item, perform_save=False)
            else:
                if new_debt_item.risk_accepted:
                    ra_helper.risk_unaccept(new_debt_item, perform_save=False)
            # Save and add new endpoints
            debt_item_helper.add_endpoints(new_debt_item, context["form"])
            # Remove unrelated endpoints
            endpoint_status_list = Endpoint_Status.objects.filter(debt_item=new_debt_item)
            for endpoint_status in endpoint_status_list:
                if endpoint_status.endpoint not in new_debt_item.endpoints.all():
                    endpoint_status.delete()
            # Handle some of the other steps
            self.process_mitigated_data(request, new_debt_item, context)
            self.process_false_positive_history(new_debt_item)
            self.process_burp_request_response(new_debt_item, context)
            # Save the vulnerability IDs
            debt_item_helper.save_vulnerability_ids(new_debt_item, context["form"].cleaned_data["vulnerability_ids"].split())
            # Add a success message
            messages.add_message(
                request,
                messages.SUCCESS,
                "debt_item saved successfully.",
                extra_tags="alert-success",
            )

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
            jira_message = None
            logger.debug("jform.jira_issue: %s", context["jform"].cleaned_data.get("jira_issue"))
            logger.debug(JFORM_PUSH_TO_JIRA_MESSAGE, context["jform"].cleaned_data.get("push_to_jira"))
            # can't use helper as when push_all_jira_issues is True, the checkbox gets disabled and is always false
            push_all_jira_issues = jira_helper.is_push_all_issues(debt_item)
            push_to_jira = push_all_jira_issues or context["jform"].cleaned_data.get("push_to_jira")
            logger.debug("push_to_jira: %s", push_to_jira)
            logger.debug("push_all_jira_issues: %s", push_all_jira_issues)
            logger.debug("has_jira_group_issue: %s", debt_item.has_jira_group_issue)
            # if the jira issue key was changed, update database
            new_jira_issue_key = context["jform"].cleaned_data.get("jira_issue")
            # we only support linking / changing if there is no group issue
            if not debt_item.has_jira_group_issue:
                if debt_item.has_jira_issue:
                    """
                    everything in DD around JIRA integration is based on the internal id
                    of the issue in JIRA instead of on the public jira issue key.
                    I have no idea why, but it means we have to retrieve the issue from JIRA
                    to get the internal JIRA id. we can assume the issue exist,
                    which is already checked in the validation of the form
                    """
                    if not new_jira_issue_key:
                        jira_helper.debt_item_unlink_jira(request, debt_item)
                        jira_message = "Link to JIRA issue removed successfully."
                    elif new_jira_issue_key != debt_item.jira_issue.jira_key:
                        jira_helper.debt_item_unlink_jira(request, debt_item)
                        jira_helper.debt_item_link_jira(request, debt_item, new_jira_issue_key)
                        jira_message = "Changed JIRA link successfully."
                else:
                    if new_jira_issue_key:
                        jira_helper.debt_item_link_jira(request, debt_item, new_jira_issue_key)
                        jira_message = "Linked a JIRA issue successfully."
            # any existing debt_item should be updated
            push_to_jira = (
                push_to_jira
                and not (push_to_jira and debt_item.debt_item_group)
                and (debt_item.has_jira_issue or jira_helper.get_jira_instance(debt_item).debt_item_jira_sync)
            )
            # Determine if a message should be added
            if jira_message:
                messages.add_message(
                    request, messages.SUCCESS, jira_message, extra_tags="alert-success"
                )

            return request, True, push_to_jira
        else:
            add_field_errors_to_response(context["jform"])

        return request, False, False

    def process_github_form(self, request: HttpRequest, debt_item: Debt_Item, context: dict, old_status: str):
        if "githubform-push_to_github" not in request.POST:
            return request, True

        if context["gform"].is_valid():
            if GITHUB_Issue.objects.filter(debt_item=debt_item).exists():
                update_external_issue(debt_item, old_status, "github")
            else:
                add_external_issue(debt_item, "github")

            return request, True
        else:
            add_field_errors_to_response(context["gform"])

        return request, False

    def process_forms(self, request: HttpRequest, debt_item: Debt_Item, context: dict):
        form_success_list = []
        # Set vars for the completed forms
        old_status = debt_item.status()
        old_debt_item = copy.copy(debt_item)
        # Validate debt_item mitigation
        request = self.validate_status_change(request, debt_item, context)
        # Check the validity of the form overall
        new_debt_item, request, success = self.process_debt_item_form(request, debt_item, context)
        form_success_list.append(success)
        request, success, push_to_jira = self.process_jira_form(request, new_debt_item, context)
        form_success_list.append(success)
        request, success = self.process_github_form(request, new_debt_item, context, old_status)
        form_success_list.append(success)
        # Determine if all forms were successful
        all_forms_valid = all(form_success_list)
        # Check the validity of all the forms
        if all_forms_valid:
            # if we're removing the "duplicate" in the edit debt_item screen
            # do not relaunch deduplication, otherwise, it's never taken into account
            if old_debt_item.duplicate and not new_debt_item.duplicate:
                new_debt_item.duplicate_debt_item = None
                new_debt_item.save(push_to_jira=push_to_jira, dedupe_option=False)
            else:
                new_debt_item.save(push_to_jira=push_to_jira)
            # we only push the group after storing the debt_item to make sure
            # the updated data of the debt_item is pushed as part of the group
            if push_to_jira and debt_item.debt_item_group:
                jira_helper.push_to_jira(debt_item.debt_item_group)

        return request, all_forms_valid

    def get_template(self):
        return "dojo/edit_debt_item.html"

    def get(self, request: HttpRequest, debt_item_id: int):
        # Get the initial objects
        debt_item = self.get_debt_item(debt_item_id)
        # Make sure the user is authorized
        user_has_permission_or_403(request.user, debt_item, Permissions.Debt_Item_Edit)
        # Set up the initial context
        context = self.get_initial_context(request, debt_item)
        # Render the form
        return render(request, self.get_template(), context)

    def post(self, request: HttpRequest, debt_item_id: int):
        # Get the initial objects
        debt_item = self.get_debt_item(debt_item_id)
        # Make sure the user is authorized
        user_has_permission_or_403(request.user, debt_item, Permissions.Debt_Item_Edit)
        # Set up the initial context
        context = self.get_initial_context(request, debt_item)
        # Process the form
        request, success = self.process_forms(request, debt_item, context)
        # Handle the case of a successful form
        if success:
            return redirect_to_return_url_or_else(request, reverse("view_debt_item", args=(debt_item_id,)))
        # Render the form
        return render(request, self.get_template(), context)


class Deletedebt_item(View):
    def get_debt_item(self, debt_item_id: int):
        return get_object_or_404(Debt_Item, id=debt_item_id)

    def process_form(self, request: HttpRequest, debt_item: Debt_Item, context: dict):
        if context["form"].is_valid():
            debt_context = debt_item.test.engagement.debt_context
            debt_item.delete()
            # Update the grade of the debt_context async
            debt_calculate_grade(debt_context)
            # Add a message to the request that the debt_item was successfully deleted
            messages.add_message(
                request,
                messages.SUCCESS,
                "debt_item deleted successfully.",
                extra_tags="alert-success",
            )
            # Send a notification that the debt_item had been deleted
            create_notification(
                event="other",
                title=f"Deletion of {debt_item.title}",
                description=f'The debt_item "{debt_item.title}" was deleted by {request.user}',
                debt_context=debt_context,
                url=request.build_absolute_uri(reverse("all_debt_items")),
                recipients=[debt_item.test.engagement.lead],
                icon="exclamation-triangle",
            )
            # return the request
            return request, True

        # Add a failure message
        messages.add_message(
            request,
            messages.ERROR,
            "Unable to delete debt_item, please try again.",
            extra_tags="alert-danger",
        )

        return request, False

    def post(self, request: HttpRequest, debt_item_id):
        # Get the initial objects
        debt_item = self.get_debt_item(debt_item_id)
        # Make sure the user is authorized
        user_has_permission_or_403(request.user, debt_item, Permissions.Debt_Item_Delete)
        # Get the debt_item form
        context = {
            "form": DeleteDebtItemForm(request.POST, instance=debt_item),
        }
        # Process the form
        request, success = self.process_form(request, debt_item, context)
        # Handle the case of a successful form
        if success:
            return redirect_to_return_url_or_else(request, reverse("view_test", args=(debt_item.test.id,)))
        raise PermissionDenied()


@user_is_authorized(Debt_Item, Permissions.Debt_Item_Edit, "fid")
def close_debt_item(request, fid):
    debt_item = get_object_or_404(Debt_Item, id=fid)
    # in order to close a debt_item, we need to capture why it was closed
    # we can do this with a Note
    note_type_activation = Note_Type.objects.filter(is_active=True)
    if len(note_type_activation):
        missing_note_types = get_missing_mandatory_notetypes(debt_item)
    else:
        missing_note_types = note_type_activation
    form = CloseDebtItemForm(missing_note_types=missing_note_types)
    if request.method == "POST":
        form = CloseDebtItemForm(request.POST, missing_note_types=missing_note_types)

        close_external_issue(debt_item, "Closed by defectdojo", "github")

        if form.is_valid():
            now = timezone.now()
            new_note = form.save(commit=False)
            new_note.author = request.user
            new_note.date = form.cleaned_data.get("mitigated") or now
            new_note.save()
            debt_item.notes.add(new_note)

            messages.add_message(
                request, messages.SUCCESS, "Note Saved.", extra_tags="alert-success"
            )

            if len(missing_note_types) <= 1:
                debt_item.active = False
                now = timezone.now()
                debt_item.mitigated = form.cleaned_data.get("mitigated") or now
                debt_item.mitigated_by = (
                    form.cleaned_data.get("mitigated_by") or request.user
                )
                debt_item.is_mitigated = True
                debt_item.last_reviewed = debt_item.mitigated
                debt_item.last_reviewed_by = request.user
                debt_item.false_p = form.cleaned_data.get("false_p", False)
                debt_item.out_of_scope = form.cleaned_data.get("out_of_scope", False)
                debt_item.duplicate = form.cleaned_data.get("duplicate", False)
                endpoint_status = debt_item.status_debt_item.all()
                for status in endpoint_status:
                    status.mitigated_by = (
                        form.cleaned_data.get("mitigated_by") or request.user
                    )
                    status.mitigated_time = form.cleaned_data.get("mitigated") or now
                    status.mitigated = True
                    status.last_modified = timezone.now()
                    status.save()

                # Manage the jira status changes
                push_to_jira = False
                # Determine if the debt_item is in a group. if so, not push to jira
                debt_item_in_group = debt_item.has_debt_item_group
                # Check if there is a jira issue that needs to be updated
                jira_issue_exists = debt_item.has_jira_issue or (debt_item.debt_item_group and debt_item.debt_item_group.has_jira_issue)
                # Only push if the debt_item is not in a group
                if jira_issue_exists:
                    # Determine if any automatic sync should occur
                    push_to_jira = jira_helper.is_push_all_issues(debt_item) \
                        or jira_helper.get_jira_instance(debt_item).debt_item_jira_sync
                # Add the closing note
                if push_to_jira and not debt_item_in_group:
                    jira_helper.add_comment(debt_item, new_note, force_push=True)
                # Save the debt_item
                debt_item.save(push_to_jira=(push_to_jira and not debt_item_in_group))

                # we only push the group after saving the debt_item to make sure
                # the updated data of the debt_item is pushed as part of the group
                if push_to_jira and debt_item_in_group:
                    jira_helper.push_to_jira(debt_item.debt_item_group)

                messages.add_message(
                    request,
                    messages.SUCCESS,
                    "debt_item closed.",
                    extra_tags="alert-success",
                )
                create_notification(
                    event="other",
                    title="Closing of %s" % debt_item.title,
                    debt_item=debt_item,
                    description='The debt_item "%s" was closed by %s'
                    % (debt_item.title, request.user),
                    url=reverse("view_debt_item", args=(debt_item.id,)),
                )
                return HttpResponseRedirect(
                    reverse("view_test", args=(debt_item.test.id,))
                )
            else:
                return HttpResponseRedirect(
                    reverse("close_debt_item", args=(debt_item.id,))
                )

    debt_context_tab = Product_Tab(
        debt_item.test.engagement.debt_context, title="Close", tab="debt_items"
    )

    return render(
        request,
        "dojo/close_debt_item.html",
        {
            "debt_item": debt_item,
            "debt_context_tab": debt_context_tab,
            "active_tab": "debt_items",
            "user": request.user,
            "form": form,
            "note_types": missing_note_types,
        },
    )


@user_is_authorized(Debt_Item, Permissions.Debt_Item_Edit, "fid")
def defect_debt_item_review(request, fid):
    debt_item = get_object_or_404(Debt_Item, id=fid)
    # in order to close a debt_item, we need to capture why it was closed
    # we can do this with a Note
    if request.method == "POST":
        form = DefectDebtItemForm(request.POST)
        if form.is_valid():
            now = timezone.now()
            new_note = form.save(commit=False)
            new_note.author = request.user
            new_note.date = now
            new_note.save()
            debt_item.notes.add(new_note)
            debt_item.under_review = False
            defect_choice = form.cleaned_data["defect_choice"]

            if defect_choice == "Close debt_item":
                debt_item.active = False
                debt_item.verified = True
                debt_item.mitigated = now
                debt_item.mitigated_by = request.user
                debt_item.is_mitigated = True
                debt_item.last_reviewed = debt_item.mitigated
                debt_item.last_reviewed_by = request.user
                debt_item.endpoints.clear()
            else:
                debt_item.active = True
                debt_item.verified = True
                debt_item.mitigated = None
                debt_item.mitigated_by = None
                debt_item.is_mitigated = False
                debt_item.last_reviewed = now
                debt_item.last_reviewed_by = request.user

            # Manage the jira status changes
            push_to_jira = False
            # Determine if the debt_item is in a group. if so, not push to jira
            debt_item_in_group = debt_item.has_debt_item_group
            # Check if there is a jira issue that needs to be updated
            jira_issue_exists = debt_item.has_jira_issue or (debt_item.debt_item_group and debt_item.debt_item_group.has_jira_issue)
            # Only push if the debt_item is not in a group
            if jira_issue_exists:
                # Determine if any automatic sync should occur
                push_to_jira = jira_helper.is_push_all_issues(debt_item) \
                    or jira_helper.get_jira_instance(debt_item).debt_item_jira_sync
            # Add the closing note
            if push_to_jira and not debt_item_in_group:
                if defect_choice == "Close debt_item":
                    new_note.entry = new_note.entry + "\nJira issue set to resolved."
                else:
                    new_note.entry = new_note.entry + "\nJira issue re-opened."
                jira_helper.add_comment(debt_item, new_note, force_push=True)
            # Save the debt_item
            debt_item.save(push_to_jira=(push_to_jira and not debt_item_in_group))

            # we only push the group after saving the debt_item to make sure
            # the updated data of the debt_item is pushed as part of the group
            if push_to_jira and debt_item_in_group:
                jira_helper.push_to_jira(debt_item.debt_item_group)

            messages.add_message(
                request, messages.SUCCESS, "Defect Reviewed", extra_tags="alert-success"
            )
            return HttpResponseRedirect(reverse("view_test", args=(debt_item.test.id,)))

    else:
        form = DefectDebtItemForm()

    debt_context_tab = Product_Tab(
        debt_item.test.engagement.debt_context, title="Jira Status Review", tab="debt_items"
    )

    return render(
        request,
        "dojo/defect_debt_item_review.html",
        {
            "debt_item": debt_item,
            "debt_context_tab": debt_context_tab,
            "user": request.user,
            "form": form,
        },
    )


@user_is_authorized(
    Debt_Item,
    Permissions.Debt_Item_Edit,
    "fid",
)
def reopen_debt_item(request, fid):
    debt_item = get_object_or_404(Debt_Item, id=fid)
    debt_item.active = True
    debt_item.mitigated = None
    debt_item.mitigated_by = request.user
    debt_item.is_mitigated = False
    debt_item.last_reviewed = debt_item.mitigated
    debt_item.last_reviewed_by = request.user
    endpoint_status = debt_item.status_debt_item.all()
    for status in endpoint_status:
        status.mitigated_by = None
        status.mitigated_time = None
        status.mitigated = False
        status.last_modified = timezone.now()
        status.save()

    # Manage the jira status changes
    push_to_jira = False
    # Determine if the debt_item is in a group. if so, not push to jira
    debt_item_in_group = debt_item.has_debt_item_group
    # Check if there is a jira issue that needs to be updated
    jira_issue_exists = debt_item.has_jira_issue or (debt_item.debt_item_group and debt_item.debt_item_group.has_jira_issue)
    # Only push if the debt_item is not in a group
    if jira_issue_exists:
        # Determine if any automatic sync should occur
        push_to_jira = jira_helper.is_push_all_issues(debt_item) \
            or jira_helper.get_jira_instance(debt_item).debt_item_jira_sync
    # Save the debt_item
    debt_item.save(push_to_jira=(push_to_jira and not debt_item_in_group))

    # we only push the group after saving the debt_item to make sure
    # the updated data of the debt_item is pushed as part of the group
    if push_to_jira and debt_item_in_group:
        jira_helper.push_to_jira(debt_item.debt_item_group)

    reopen_external_issue(debt_item, "re-opened by defectdojo", "github")

    messages.add_message(
        request, messages.SUCCESS, "debt_item Reopened.", extra_tags="alert-success"
    )
    create_notification(
        event="other",
        title="Reopening of %s" % debt_item.title,
        debt_item=debt_item,
        description='The debt_item "%s" was reopened by %s'
        % (debt_item.title, request.user),
        url=reverse("view_debt_item", args=(debt_item.id,)),
    )
    return HttpResponseRedirect(reverse("view_debt_item", args=(debt_item.id,)))


@user_is_authorized(Debt_Item, Permissions.Debt_Item_Edit, "fid")
def apply_template_cwe(request, fid):
    debt_item = get_object_or_404(Debt_Item, id=fid)
    if request.method == "POST":
        form = DebtItemFormID(request.POST, instance=debt_item)
        if form.is_valid():
            debt_item = apply_cwe_to_template(debt_item)
            debt_item.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                "debt_item CWE template applied successfully.",
                extra_tags="alert-success",
            )
            return HttpResponseRedirect(reverse("view_debt_item", args=(fid,)))
        else:
            messages.add_message(
                request,
                messages.ERROR,
                "Unable to apply CWE template debt_item, please try again.",
                extra_tags="alert-danger",
            )
    else:
        raise PermissionDenied()


@user_is_authorized(Debt_Item, Permissions.Debt_Item_Edit, "fid")
def copy_debt_item(request, fid):
    debt_item = get_object_or_404(Debt_Item, id=fid)
    debt_context = debt_item.test.engagement.debt_context
    tests = get_authorized_tests(Permissions.Test_Edit).filter(
        engagement=debt_item.test.engagement
    )
    form = CopyDebtItemForm(tests=tests)

    if request.method == "POST":
        form = CopyDebtItemForm(request.POST, tests=tests)
        if form.is_valid():
            test = form.cleaned_data.get("test")
            debt_context = debt_item.test.engagement.debt_context
            debt_item_copy = debt_item.copy(test=test)
            debt_calculate_grade(debt_context)
            messages.add_message(
                request,
                messages.SUCCESS,
                "debt_item Copied successfully.",
                extra_tags="alert-success",
            )
            create_notification(
                event="other",
                title="Copying of %s" % debt_item.title,
                description='The debt_item "%s" was copied by %s to %s'
                % (debt_item.title, request.user, test.title),
                debt_context=debt_context,
                url=request.build_absolute_uri(
                    reverse("copy_debt_item", args=(debt_item_copy.id,))
                ),
                recipients=[debt_item.test.engagement.lead],
                icon="exclamation-triangle",
            )
            return redirect_to_return_url_or_else(
                request, reverse("view_test", args=(test.id,))
            )
        else:
            messages.add_message(
                request,
                messages.ERROR,
                "Unable to copy debt_item, please try again.",
                extra_tags="alert-danger",
            )

    debt_context_tab = Product_Tab(debt_context, title="Copy debt_item", tab="debt_items")
    return render(
        request,
        "dojo/copy_object.html",
        {
            "source": debt_item,
            "source_label": "debt_item",
            "destination_label": "Test",
            "debt_context_tab": debt_context_tab,
            "form": form,
        },
    )


@user_is_authorized(Debt_Item, Permissions.Debt_Item_Edit, "fid")
def remediation_date(request, fid):
    debt_item = get_object_or_404(Debt_Item, id=fid)
    user = get_object_or_404(Dojo_User, id=request.user.id)

    if request.method == "POST":
        form = EditPlannedRemediationDateDebtItemForm(request.POST)

        if form.is_valid():
            debt_item.planned_remediation_date = request.POST.get(
                "planned_remediation_date", ""
            )
            debt_item.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                "debt_item Planned Remediation Date saved.",
                extra_tags="alert-success",
            )
            return HttpResponseRedirect(reverse("view_debt_item", args=(debt_item.id,)))

    else:
        form = EditPlannedRemediationDateDebtItemForm(debt_item=debt_item)

    debt_context_tab = Product_Tab(
        debt_item.test.engagement.debt_context,
        title="Planned Remediation Date",
        tab="debt_items",
    )

    return render(
        request,
        "dojo/remediation_date.html",
        {"debt_item": debt_item, "debt_context_tab": debt_context_tab, "user": user, "form": form},
    )


@user_is_authorized(Debt_Item, Permissions.Debt_Item_Edit, "fid")
def touch_debt_item(request, fid):
    debt_item = get_object_or_404(Debt_Item, id=fid)
    debt_item.last_reviewed = timezone.now()
    debt_item.last_reviewed_by = request.user
    debt_item.save()
    return redirect_to_return_url_or_else(
        request, reverse("view_debt_item", args=(debt_item.id,))
    )


@user_is_authorized(Debt_Item, Permissions.Risk_Acceptance, "fid")
def simple_risk_accept(request, fid):
    debt_item = get_object_or_404(Debt_Item, id=fid)

    if not debt_item.test.engagement.debt_context.enable_simple_risk_acceptance:
        raise PermissionDenied()

    ra_helper.simple_risk_accept(debt_item)

    messages.add_message(
        request, messages.WARNING, "debt_item risk accepted.", extra_tags="alert-success"
    )

    return redirect_to_return_url_or_else(
        request, reverse("view_debt_item", args=(debt_item.id,))
    )


@user_is_authorized(Debt_Item, Permissions.Risk_Acceptance, "fid")
def risk_unaccept(request, fid):
    debt_item = get_object_or_404(Debt_Item, id=fid)
    ra_helper.risk_unaccept(debt_item)

    messages.add_message(
        request,
        messages.WARNING,
        "debt_item risk unaccepted.",
        extra_tags="alert-success",
    )

    return redirect_to_return_url_or_else(
        request, reverse("view_debt_item", args=(debt_item.id,))
    )


@user_is_authorized(Debt_Item, Permissions.Debt_Item_View, "fid")
def request_debt_item_review(request, fid):
    debt_item = get_object_or_404(Debt_Item, id=fid)
    user = get_object_or_404(Dojo_User, id=request.user.id)
    form = ReviewDebtItemForm(debt_item=debt_item, user=user)
    # in order to review a debt_item, we need to capture why a review is needed
    # we can do this with a Note
    if request.method == "POST":
        form = ReviewDebtItemForm(request.POST, debt_item=debt_item, user=user)

        if form.is_valid():
            now = timezone.now()
            new_note = Notes()
            new_note.entry = "Review Request: " + form.cleaned_data["entry"]
            new_note.private = True
            new_note.author = request.user
            new_note.date = now
            new_note.save()
            debt_item.notes.add(new_note)
            debt_item.active = True
            debt_item.verified = False
            debt_item.is_mitigated = False
            debt_item.under_review = True
            debt_item.review_requested_by = user
            debt_item.last_reviewed = now
            debt_item.last_reviewed_by = request.user

            users = form.cleaned_data["reviewers"]
            debt_item.reviewers.set(users)

            # Manage the jira status changes
            push_to_jira = False
            # Determine if the debt_item is in a group. if so, not push to jira
            debt_item_in_group = debt_item.has_debt_item_group
            # Check if there is a jira issue that needs to be updated
            jira_issue_exists = debt_item.has_jira_issue or (debt_item.debt_item_group and debt_item.debt_item_group.has_jira_issue)
            # Only push if the debt_item is not in a group
            if jira_issue_exists:
                # Determine if any automatic sync should occur
                push_to_jira = jira_helper.is_push_all_issues(debt_item) \
                    or jira_helper.get_jira_instance(debt_item).debt_item_jira_sync
            # Add the closing note
            if push_to_jira and not debt_item_in_group:
                jira_helper.add_comment(debt_item, new_note, force_push=True)
            # Save the debt_item
            debt_item.save(push_to_jira=(push_to_jira and not debt_item_in_group))

            # we only push the group after saving the debt_item to make sure
            # the updated data of the debt_item is pushed as part of the group
            if push_to_jira and debt_item_in_group:
                jira_helper.push_to_jira(debt_item.debt_item_group)

            reviewers = ""
            reviewers_short = []
            for user in form.cleaned_data["reviewers"]:
                full_user = Dojo_User.generate_full_name(
                    Dojo_User.objects.get(id=user)
                )
                logger.debug("Asking %s for review", full_user)
                reviewers += str(full_user) + ", "
                reviewers_short.append(Dojo_User.objects.get(id=user).username)
            reviewers = reviewers[:-2]

            create_notification(
                event="review_requested",
                title="debt_item review requested",
                debt_item=debt_item,
                recipients=reviewers_short,
                description='User %s has requested that user(s) %s review the debt_item "%s" for accuracy:\n\n%s'
                % (user, reviewers, debt_item.title, new_note),
                icon="check",
                url=reverse("view_debt_item", args=(debt_item.id,)),
            )

            messages.add_message(
                request,
                messages.SUCCESS,
                "debt_item marked for review and reviewers notified.",
                extra_tags="alert-success",
            )
            return HttpResponseRedirect(reverse("view_debt_item", args=(debt_item.id,)))

    debt_context_tab = Product_Tab(
        debt_item.test.engagement.debt_context, title="Review debt_item", tab="debt_items"
    )

    return render(
        request,
        "dojo/review_debt_item.html",
        {"debt_item": debt_item, "debt_context_tab": debt_context_tab, "user": user, "form": form},
    )


@user_is_authorized(Debt_Item, Permissions.Debt_Item_Edit, "fid")
def clear_debt_item_review(request, fid):
    debt_item = get_object_or_404(Debt_Item, id=fid)
    user = get_object_or_404(Dojo_User, id=request.user.id)
    # If the user wanting to clear the review is not the user who requested
    # the review or one of the users requested to provide the review, then
    # do not allow the user to clear the review.
    if user != debt_item.review_requested_by and user not in debt_item.reviewers.all():
        raise PermissionDenied()

    # in order to clear a review for a debt_item, we need to capture why and how it was reviewed
    # we can do this with a Note
    if request.method == "POST":
        form = ClearDebtItemReviewForm(request.POST, instance=debt_item)

        if form.is_valid():
            now = timezone.now()
            new_note = Notes()
            new_note.entry = "Review Cleared: " + form.cleaned_data["entry"]
            new_note.author = request.user
            new_note.date = now
            new_note.save()

            debt_item = form.save(commit=False)

            debt_item.under_review = False
            debt_item.last_reviewed = now
            debt_item.last_reviewed_by = request.user

            debt_item.reviewers.set([])
            debt_item.notes.add(new_note)

            # Manage the jira status changes
            push_to_jira = False
            # Determine if the debt_item is in a group. if so, not push to jira
            debt_item_in_group = debt_item.has_debt_item_group
            # Check if there is a jira issue that needs to be updated
            jira_issue_exists = debt_item.has_jira_issue or (debt_item.debt_item_group and debt_item.debt_item_group.has_jira_issue)
            # Only push if the debt_item is not in a group
            if jira_issue_exists:
                # Determine if any automatic sync should occur
                push_to_jira = jira_helper.is_push_all_issues(debt_item) \
                    or jira_helper.get_jira_instance(debt_item).debt_item_jira_sync
            # Add the closing note
            if push_to_jira and not debt_item_in_group:
                jira_helper.add_comment(debt_item, new_note, force_push=True)
            # Save the debt_item
            debt_item.save(push_to_jira=(push_to_jira and not debt_item_in_group))

            # we only push the group after saving the debt_item to make sure
            # the updated data of the debt_item is pushed as part of the group
            if push_to_jira and debt_item_in_group:
                jira_helper.push_to_jira(debt_item.debt_item_group)

            messages.add_message(
                request,
                messages.SUCCESS,
                "debt_item review has been updated successfully.",
                extra_tags="alert-success",
            )
            return HttpResponseRedirect(reverse("view_debt_item", args=(debt_item.id,)))

    else:
        form = ClearDebtItemReviewForm(instance=debt_item)

    debt_context_tab = Product_Tab(
        debt_item.test.engagement.debt_context, title="Clear debt_item Review", tab="debt_items"
    )

    return render(
        request,
        "dojo/clear_debt_item_review.html",
        {"debt_item": debt_item, "debt_context_tab": debt_context_tab, "user": user, "form": form},
    )


@user_has_global_permission(Permissions.Debt_Item_Add)
def mktemplate(request, fid):
    debt_item = get_object_or_404(Debt_Item, id=fid)
    templates = Debt_Item_Template.objects.filter(title=debt_item.title)
    if len(templates) > 0:
        messages.add_message(
            request,
            messages.ERROR,
            "A debt_item template with that title already exists.",
            extra_tags="alert-danger",
        )
    else:
        template = Debt_Item_Template(
            title=debt_item.title,
            cwe=debt_item.cwe,
            cvssv3=debt_item.cvssv3,
            severity=debt_item.severity,
            description=debt_item.description,
            mitigation=debt_item.mitigation,
            impact=debt_item.impact,
            references=debt_item.references,
            numerical_severity=debt_item.numerical_severity,
            tags=debt_item.tags.all(),
        )
        template.save()
        template.tags = debt_item.tags.all()

        for vulnerability_id in debt_item.vulnerability_ids:
            Vulnerability_Id_Template(
                debt_item_template=template, vulnerability_id=vulnerability_id
            ).save()

        messages.add_message(
            request,
            messages.SUCCESS,
            mark_safe(
                'debt_item template added successfully. You may edit it <a href="%s">here</a>.'
                % reverse("edit_template", args=(template.id,))
            ),
            extra_tags="alert-success",
        )
    return HttpResponseRedirect(reverse("view_debt_item", args=(debt_item.id,)))


@user_is_authorized(Debt_Item, Permissions.Debt_Item_Edit, "fid")
def find_template_to_apply(request, fid):
    debt_item = get_object_or_404(Debt_Item, id=fid)
    test = get_object_or_404(Test, id=debt_item.test.id)
    templates_by_cve = (
        Debt_Item_Template.objects.annotate(
            cve_len=Length("cve"), order=models.Value(1, models.IntegerField())
        )
        .filter(cve=debt_item.cve, cve_len__gt=0)
        .order_by("-last_used")
    )
    if templates_by_cve.count() == 0:
        templates_by_last_used = (
            Debt_Item_Template.objects.all()
            .order_by("-last_used")
            .annotate(
                cve_len=Length("cve"), order=models.Value(2, models.IntegerField())
            )
        )
        templates = templates_by_last_used
    else:
        templates_by_last_used = (
            Debt_Item_Template.objects.all()
            .exclude(cve=debt_item.cve)
            .order_by("-last_used")
            .annotate(
                cve_len=Length("cve"), order=models.Value(2, models.IntegerField())
            )
        )
        templates = templates_by_last_used.union(templates_by_cve).order_by(
            "order", "-last_used"
        )

    templates = TemplateDebtItemFilter(request.GET, queryset=templates)
    paged_templates = get_page_items(request, templates.qs, 25)

    # just query all templates as this weird ordering above otherwise breaks Django ORM
    title_words = get_words_for_field(Debt_Item_Template, "title")
    debt_context_tab = Product_Tab(
        test.engagement.debt_context, title="Apply Template to debt_item", tab="debt_items"
    )
    return render(
        request,
        "dojo/templates.html",
        {
            "templates": paged_templates,
            "debt_context_tab": debt_context_tab,
            "filtered": templates,
            "title_words": title_words,
            "tid": test.id,
            "fid": fid,
            "add_from_template": False,
            "apply_template": True,
        },
    )


@user_is_authorized(Debt_Item, Permissions.Debt_Item_Edit, "fid")
def choose_debt_item_template_options(request, tid, fid):
    debt_item = get_object_or_404(Debt_Item, id=fid)
    template = get_object_or_404(Debt_Item_Template, id=tid)
    data = debt_item.__dict__
    # Not sure what's going on here, just leave same as with django-tagging
    data["tags"] = [tag.name for tag in template.tags.all()]
    data["vulnerability_ids"] = "\n".join(debt_item.vulnerability_ids)

    form = ApplyDebtItemTemplateForm(data=data, template=template)
    debt_context_tab = Product_Tab(
        debt_item.test.engagement.debt_context,
        title="debt_item Template Options",
        tab="debt_items",
    )
    return render(
        request,
        "dojo/apply_debt_item_template.html",
        {
            "debt_item": debt_item,
            "debt_context_tab": debt_context_tab,
            "template": template,
            "form": form,
            "debt_item_tags": [tag.name for tag in debt_item.tags.all()],
        },
    )


@user_is_authorized(Debt_Item, Permissions.Debt_Item_Edit, "fid")
def apply_template_to_debt_item(request, fid, tid):
    debt_item = get_object_or_404(Debt_Item, id=fid)
    template = get_object_or_404(Debt_Item_Template, id=tid)

    if request.method == "POST":
        form = ApplyDebtItemTemplateForm(data=request.POST)

        if form.is_valid():
            template.last_used = timezone.now()
            template.save()
            debt_item.title = form.cleaned_data["title"]
            debt_item.cwe = form.cleaned_data["cwe"]
            debt_item.severity = form.cleaned_data["severity"]
            debt_item.description = form.cleaned_data["description"]
            debt_item.mitigation = form.cleaned_data["mitigation"]
            debt_item.impact = form.cleaned_data["impact"]
            debt_item.references = form.cleaned_data["references"]
            debt_item.last_reviewed = timezone.now()
            debt_item.last_reviewed_by = request.user
            debt_item.tags = form.cleaned_data["tags"]

            debt_item.cve = None
            debt_item_helper.save_vulnerability_ids(
                debt_item, form.cleaned_data["vulnerability_ids"].split()
            )

            debt_item.save()
        else:
            messages.add_message(
                request,
                messages.ERROR,
                "There appears to be errors on the form, please correct below.",
                extra_tags="alert-danger",
            )
            debt_context_tab = Product_Tab(
                debt_item.test.engagement.debt_context,
                title="Apply debt_item Template",
                tab="debt_items",
            )
            return render(
                request,
                "dojo/apply_debt_item_template.html",
                {
                    "debt_item": debt_item,
                    "debt_context_tab": debt_context_tab,
                    "template": template,
                    "form": form,
                },
            )

        return HttpResponseRedirect(reverse("view_debt_item", args=(debt_item.id,)))
    else:
        return HttpResponseRedirect(reverse("view_debt_item", args=(debt_item.id,)))


@user_is_authorized(Test, Permissions.Debt_Item_Add, "tid")
def add_stub_debt_item(request, tid):
    test = get_object_or_404(Test, id=tid)
    if request.method == "POST":
        form = StubDebtItemForm(request.POST)
        if form.is_valid():
            stub_debt_item = form.save(commit=False)
            stub_debt_item.test = test
            stub_debt_item.reporter = request.user
            stub_debt_item.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                "Stub debt_item created successfully.",
                extra_tags="alert-success",
            )
            if request.headers.get("x-requested-with") == "XMLHttpRequest":
                data = {
                    "message": "Stub debt_item created successfully.",
                    "id": stub_debt_item.id,
                    "severity": "None",
                    "date": formats.date_format(stub_debt_item.date, "DATE_FORMAT"),
                }
                return HttpResponse(json.dumps(data))
        else:
            if request.headers.get("x-requested-with") == "XMLHttpRequest":
                data = {
                    "message": "Stub debt_item form has error, please revise and try again.",
                }
                return HttpResponse(json.dumps(data))

            messages.add_message(
                request,
                messages.ERROR,
                "Stub debt_item form has error, please revise and try again.",
                extra_tags="alert-danger",
            )
    add_breadcrumb(title="Add Stub debt_item", top_level=False, request=request)
    return HttpResponseRedirect(reverse("view_test", args=(tid,)))


@user_is_authorized(Stub_Debt_Item, Permissions.Debt_Item_Delete, "fid")
def delete_stub_debt_item(request, fid):
    debt_item = get_object_or_404(Stub_Debt_Item, id=fid)

    if request.method == "POST":
        form = DeleteStubDebtItemForm(request.POST, instance=debt_item)
        if form.is_valid():
            tid = debt_item.test.id
            debt_item.delete()
            messages.add_message(
                request,
                messages.SUCCESS,
                "Potential debt_item deleted successfully.",
                extra_tags="alert-success",
            )
            return HttpResponseRedirect(reverse("view_test", args=(tid,)))
        else:
            messages.add_message(
                request,
                messages.ERROR,
                "Unable to delete potential debt_item, please try again.",
                extra_tags="alert-danger",
            )
    else:
        raise PermissionDenied()


@user_is_authorized(Stub_Debt_Item, Permissions.Debt_Item_Edit, "fid")
def promote_to_debt_item(request, fid):
    debt_item = get_object_or_404(Stub_Debt_Item, id=fid)
    test = debt_item.test
    form_error = False
    push_all_jira_issues = jira_helper.is_push_all_issues(debt_item)
    jform = None
    use_jira = jira_helper.get_jira_project(debt_item) is not None
    debt_context_tab = Product_Tab(
        debt_item.test.engagement.debt_context, title="Promote debt_item", tab="debt_items"
    )

    if request.method == "POST":
        form = PromoteDebtItemForm(request.POST, debt_context=test.engagement.debt_context)
        if use_jira:
            jform = JIRADebtItemForm(
                request.POST,
                instance=debt_item,
                prefix="jiraform",
                push_all=push_all_jira_issues,
                jira_project=jira_helper.get_jira_project(debt_item),
            )

        if form.is_valid() and (jform is None or jform.is_valid()):
            if jform:
                logger.debug(
                    "jform.jira_issue: %s", jform.cleaned_data.get("jira_issue")
                )
                logger.debug(
                    JFORM_PUSH_TO_JIRA_MESSAGE, jform.cleaned_data.get("push_to_jira")
                )

            new_debt_item = form.save(commit=False)
            new_debt_item.test = test
            new_debt_item.reporter = request.user
            new_debt_item.numerical_severity = debt_item.get_numerical_severity(
                new_debt_item.severity
            )

            new_debt_item.active = True
            new_debt_item.false_p = False
            new_debt_item.duplicate = False
            new_debt_item.mitigated = None
            new_debt_item.verified = True
            new_debt_item.out_of_scope = False

            new_debt_item.save()

            debt_item_helper.add_endpoints(new_debt_item, form)

            push_to_jira = False
            if jform and jform.is_valid():
                # Push to Jira?
                logger.debug("jira form valid")
                push_to_jira = push_all_jira_issues or jform.cleaned_data.get(
                    "push_to_jira"
                )

                # if the jira issue key was changed, update database
                new_jira_issue_key = jform.cleaned_data.get("jira_issue")
                if new_debt_item.has_jira_issue:
                    # vaiable "jira_issue" no used
                    # jira_issue = new_debt_item.jira_issue
                    """
                    everything in DD around JIRA integration is based on the internal id of
                    the issue in JIRA instead of on the public jira issue key.
                    I have no idea why, but it means we have to retrieve
                    the issue from JIRA to get the internal JIRA id. we can assume the issue exist,
                    which is already checked in the validation of the jform
                    """

                    if not new_jira_issue_key:
                        jira_helper.debt_item_unlink_jira(request, new_debt_item)

                    elif new_jira_issue_key != new_debt_item.jira_issue.jira_key:
                        jira_helper.debt_item_unlink_jira(request, new_debt_item)
                        jira_helper.debt_item_link_jira(
                            request, new_debt_item, new_jira_issue_key
                        )
                else:
                    logger.debug("debt_item has no jira issue yet")
                    if new_jira_issue_key:
                        logger.debug(
                            "debt_item has no jira issue yet, but jira issue specified in request. trying to link.")
                        jira_helper.debt_item_link_jira(
                            request, new_debt_item, new_jira_issue_key
                        )

            debt_item_helper.save_vulnerability_ids(
                new_debt_item, form.cleaned_data["vulnerability_ids"].split()
            )

            new_debt_item.save(push_to_jira=push_to_jira)

            debt_item.delete()
            if "githubform" in request.POST:
                gform = GITHUBDebtItemForm(
                    request.POST,
                    prefix="githubform",
                    enabled=GITHUB_PKey.objects.get(
                        debt_context=test.engagement.debt_context
                    ).push_all_issues,
                )
                if gform.is_valid():
                    add_external_issue(new_debt_item, "github")

            messages.add_message(
                request,
                messages.SUCCESS,
                "debt_item promoted successfully.",
                extra_tags="alert-success",
            )

            return HttpResponseRedirect(reverse("view_test", args=(test.id,)))
        else:
            form_error = True
            add_error_message_to_response(
                "The form has errors, please correct them below."
            )
            add_field_errors_to_response(jform)
            add_field_errors_to_response(form)
    else:
        form = PromoteDebtItemForm(
            initial={
                "title": debt_item.title,
                "debt_context_tab": debt_context_tab,
                "date": debt_item.date,
                "severity": debt_item.severity,
                "description": debt_item.description,
                "test": debt_item.test,
                "reporter": debt_item.reporter,
            },
            debt_context=test.engagement.debt_context,
        )

        if use_jira:
            jform = JIRADebtItemForm(
                prefix="jiraform",
                push_all=jira_helper.is_push_all_issues(test),
                jira_project=jira_helper.get_jira_project(test),
            )

    return render(
        request,
        "dojo/promote_to_debt_item.html",
        {
            "form": form,
            "debt_context_tab": debt_context_tab,
            "test": test,
            "stub_debt_item": debt_item,
            "form_error": form_error,
            "jform": jform,
        },
    )


@user_has_global_permission(Permissions.Debt_Item_Edit)
def templates(request):
    templates = Debt_Item_Template.objects.all().order_by("cwe")
    templates = TemplateDebtItemFilter(request.GET, queryset=templates)
    paged_templates = get_page_items(request, templates.qs, 25)

    title_words = get_words_for_field(templates.qs, "title")

    add_breadcrumb(title="Template Listing", top_level=True, request=request)
    return render(
        request,
        "dojo/templates.html",
        {
            "templates": paged_templates,
            "filtered": templates,
            "title_words": title_words,
        },
    )


@user_has_global_permission(Permissions.Debt_Item_Edit)
def export_templates_to_json(request):
    leads_as_json = serializers.serialize("json", Debt_Item_Template.objects.all())
    return HttpResponse(leads_as_json, content_type="json")


def apply_cwe_mitigation(apply_to_debt_items, template, update=True):
    count = 0
    if apply_to_debt_items and template.template_match and template.cwe is not None:
        # Update active, verified debt_items with the CWE template
        # If CWE only match only update issues where there isn't a CWE + Title match
        if template.template_match_title:
            count = Debt_Item.objects.filter(
                active=True,
                verified=True,
                cwe=template.cwe,
                title__icontains=template.title,
            ).update(
                mitigation=template.mitigation,
                impact=template.impact,
                references=template.references,
            )
        else:
            debt_item_templates = Debt_Item_Template.objects.filter(
                cwe=template.cwe, template_match=True, template_match_title=True
            )

            debt_item_ids = None
            result_list = None
            # Exclusion list
            for title_template in debt_item_templates:
                debt_item_ids = Debt_Item.objects.filter(
                    active=True,
                    verified=True,
                    cwe=title_template.cwe,
                    title__icontains=title_template.title,
                ).values_list("id", flat=True)
                if result_list is None:
                    result_list = debt_item_ids
                else:
                    result_list = list(chain(result_list, debt_item_ids))

            # If result_list is None the filter exclude won't work
            if result_list:
                count = Debt_Item.objects.filter(
                    active=True, verified=True, cwe=template.cwe
                ).exclude(id__in=result_list)
            else:
                count = Debt_Item.objects.filter(
                    active=True, verified=True, cwe=template.cwe
                )

            if update:
                # MySQL won't allow an 'update in statement' so loop will have to do
                for debt_item in count:
                    debt_item.mitigation = template.mitigation
                    debt_item.impact = template.impact
                    debt_item.references = template.references
                    template.last_used = timezone.now()
                    template.save()
                    new_note = Notes()
                    new_note.entry = (
                        "CWE remediation text applied to debt_item for CWE: %s using template: %s."
                        % (template.cwe, template.title)
                    )
                    new_note.author, created = User.objects.get_or_create(
                        username="System"
                    )
                    new_note.save()
                    debt_item.notes.add(new_note)
                    debt_item.save()

            count = count.count()
    return count


@user_has_global_permission(Permissions.Debt_Item_Add)
def add_template(request):
    form = DebtItemTemplateForm()
    if request.method == "POST":
        form = DebtItemTemplateForm(request.POST)
        if form.is_valid():
            apply_message = ""
            template = form.save(commit=False)
            template.numerical_severity = Debt_Item.get_numerical_severity(
                template.severity
            )
            debt_item_helper.save_vulnerability_ids_template(
                template, form.cleaned_data["vulnerability_ids"].split()
            )
            template.save()
            form.save_m2m()
            count = apply_cwe_mitigation(
                form.cleaned_data["apply_to_debt_items"], template
            )
            if count > 0:
                apply_message = (
                    " and " + str(count) + pluralize(count, "debt_item,debt_items") + " "
                )

            messages.add_message(
                request,
                messages.SUCCESS,
                "Template created successfully. " + apply_message,
                extra_tags="alert-success",
            )
            return HttpResponseRedirect(reverse("templates"))
        else:
            messages.add_message(
                request,
                messages.ERROR,
                "Template form has error, please revise and try again.",
                extra_tags="alert-danger",
            )
    add_breadcrumb(title="Add Template", top_level=False, request=request)
    return render(
        request, "dojo/add_template.html", {"form": form, "name": "Add Template"}
    )


@user_has_global_permission(Permissions.Debt_Item_Edit)
def edit_template(request, tid):
    template = get_object_or_404(Debt_Item_Template, id=tid)
    form = DebtItemTemplateForm(
        instance=template,
        initial={"vulnerability_ids": "\n".join(template.vulnerability_ids)},
    )

    if request.method == "POST":
        form = DebtItemTemplateForm(request.POST, instance=template)
        if form.is_valid():
            template = form.save(commit=False)
            template.numerical_severity = Debt_Item.get_numerical_severity(
                template.severity
            )
            debt_item_helper.save_vulnerability_ids_template(
                template, form.cleaned_data["vulnerability_ids"].split()
            )
            template.save()
            form.save_m2m()

            count = apply_cwe_mitigation(
                form.cleaned_data["apply_to_debt_items"], template
            )
            if count > 0:
                apply_message = (
                    " and "
                    + str(count)
                    + " "
                    + pluralize(count, "debt_item,debt_items")
                    + " "
                )
            else:
                apply_message = ""

            messages.add_message(
                request,
                messages.SUCCESS,
                "Template " + apply_message + "updated successfully.",
                extra_tags="alert-success",
            )
            return HttpResponseRedirect(reverse("templates"))
        else:
            messages.add_message(
                request,
                messages.ERROR,
                "Template form has error, please revise and try again.",
                extra_tags="alert-danger",
            )

    count = apply_cwe_mitigation(True, template, False)
    add_breadcrumb(title="Edit Template", top_level=False, request=request)
    return render(
        request,
        "dojo/add_template.html",
        {
            "form": form,
            "count": count,
            "name": "Edit Template",
            "template": template,
        },
    )


@user_has_global_permission(Permissions.Debt_Item_Delete)
def delete_template(request, tid):
    template = get_object_or_404(Debt_Item_Template, id=tid)
    if request.method == "POST":
        form = DeleteDebtItemTemplateForm(request.POST, instance=template)
        if form.is_valid():
            template.delete()
            messages.add_message(
                request,
                messages.SUCCESS,
                "debt_item Template deleted successfully.",
                extra_tags="alert-success",
            )
            return HttpResponseRedirect(reverse("templates"))
        else:
            messages.add_message(
                request,
                messages.ERROR,
                "Unable to delete Template, please revise and try again.",
                extra_tags="alert-danger",
            )
    else:
        raise PermissionDenied()


def download_debt_item_pic(request, token):
    class Thumbnail(ImageSpec):
        processors = [ResizeToFill(100, 100)]
        format = "JPEG"
        options = {"quality": 70}

    class Small(ImageSpec):
        processors = [ResizeToFill(640, 480)]
        format = "JPEG"
        options = {"quality": 100}

    class Medium(ImageSpec):
        processors = [ResizeToFill(800, 600)]
        format = "JPEG"
        options = {"quality": 100}

    class Large(ImageSpec):
        processors = [ResizeToFill(1024, 768)]
        format = "JPEG"
        options = {"quality": 100}

    class Original(ImageSpec):
        format = "JPEG"
        options = {"quality": 100}

    mimetypes.init()

    size_map = {
        "thumbnail": Thumbnail,
        "small": Small,
        "medium": Medium,
        "large": Large,
        "original": Original,
    }

    try:
        access_token = FileAccessToken.objects.get(token=token)
        size = access_token.size

        if access_token.size not in list(size_map.keys()):
            raise Http404
        size = access_token.size
        # we know there is a token - is it for this image
        if access_token.size == size:
            """all is good, one time token used, delete it"""
            access_token.delete()
        else:
            raise PermissionDenied
    except Exception:
        raise PermissionDenied

    with open(access_token.file.file.file.name, "rb") as file:
        file_name = file.name
        image = size_map[size](source=file).generate()
        response = StreamingHttpResponse(FileIterWrapper(image))
        response["Content-Disposition"] = "inline"
        mimetype, encoding = mimetypes.guess_type(file_name)
        response["Content-Type"] = mimetype
        return response


@user_is_authorized(Product, Permissions.Debt_Item_Edit, "pid")
def merge_debt_item_debt_context(request, pid):
    debt_context = get_object_or_404(Product, pk=pid)
    debt_item_to_update = request.GET.getlist("debt_item_to_update")
    debt_items = None

    if (
        request.GET.get("merge_debt_items") or request.method == "POST"
    ) and debt_item_to_update:
        debt_item = Debt_Item.objects.get(
            id=debt_item_to_update[0], test__engagement__debt_context=debt_context
        )
        debt_items = debt_item.objects.filter(
            id__in=debt_item_to_update, test__engagement__debt_context=debt_context
        )
        form = MergeDebtItems(
            debt_item=debt_item,
            debt_items=debt_items,
            initial={"debt_item_to_merge_into": debt_item_to_update[0]},
        )

        if request.method == "POST":
            form = MergeDebtItems(request.POST, debt_item=debt_item, debt_items=debt_items)
            if form.is_valid():
                debt_item_to_merge_into = form.cleaned_data["debt_item_to_merge_into"]
                debt_items_to_merge = form.cleaned_data["debt_items_to_merge"]
                debt_item_descriptions = ""
                debt_item_references = ""
                notes_entry = ""
                static = False
                dynamic = False

                if debt_item_to_merge_into not in debt_items_to_merge:
                    for debt_item in debt_items_to_merge.exclude(
                        pk=debt_item_to_merge_into.pk
                    ):
                        notes_entry = "{}\n- {} ({}),".format(
                            notes_entry, debt_item.title, debt_item.id
                        )
                        if debt_item.static_debt_item:
                            static = debt_item.static_debt_item

                        if debt_item.dynamic_debt_item:
                            dynamic = debt_item.dynamic_debt_item

                        if form.cleaned_data["append_description"]:
                            debt_item_descriptions = "{}\n{}".format(
                                debt_item_descriptions, debt_item.description
                            )
                            # Workaround until file path is one to many
                            if debt_item.file_path:
                                debt_item_descriptions = "{}\n**File Path:** {}\n".format(
                                    debt_item_descriptions, debt_item.file_path
                                )

                        # If checked merge the Reference
                        if (
                            form.cleaned_data["append_reference"]
                            and debt_item.references is not None
                        ):
                            debt_item_references = "{}\n{}".format(
                                debt_item_references, debt_item.references
                            )

                        # if checked merge the endpoints
                        if form.cleaned_data["add_endpoints"]:
                            debt_item_to_merge_into.endpoints.add(
                                *debt_item.endpoints.all()
                            )

                        # if checked merge the tags
                        if form.cleaned_data["tag_debt_item"]:
                            for tag in debt_item.tags.all():
                                debt_item_to_merge_into.tags.add(tag)

                        # if checked re-assign the burp requests to the merged debt_item
                        if form.cleaned_data["dynamic_raw"]:
                            BurpRawRequestResponse.objects.filter(
                                debt_item=debt_item
                            ).update(debt_item=debt_item_to_merge_into)

                        # Add merge debt_item information to the note if set to inactive
                        if form.cleaned_data["debt_item_action"] == "inactive":
                            single_debt_item_notes_entry = ("debt_item has been set to inactive "
                                                          "and merged with the debt_item: {}.").format(
                                debt_item_to_merge_into.title
                            )
                            note = Notes(
                                entry=single_debt_item_notes_entry, author=request.user
                            )
                            note.save()
                            debt_item.notes.add(note)

                            # If the merged debt_item should be tagged as merged-into
                            if form.cleaned_data["mark_tag_debt_item"]:
                                debt_item.tags.add("merged-inactive")

                    # Update the debt_item to merge into
                    if debt_item_descriptions != "":
                        debt_item_to_merge_into.description = "{}\n\n{}".format(
                            debt_item_to_merge_into.description, debt_item_descriptions
                        )

                    if debt_item_to_merge_into.static_debt_item:
                        static = debt_item.static_debt_item

                    if debt_item_to_merge_into.dynamic_debt_item:
                        dynamic = debt_item.dynamic_debt_item

                    if debt_item_references != "":
                        debt_item_to_merge_into.references = "{}\n{}".format(
                            debt_item_to_merge_into.references, debt_item_references
                        )

                    debt_item_to_merge_into.static_debt_item = static
                    debt_item_to_merge_into.dynamic_debt_item = dynamic

                    # Update the timestamp
                    debt_item_to_merge_into.last_reviewed = timezone.now()
                    debt_item_to_merge_into.last_reviewed_by = request.user

                    # Save the data to the merged debt_item
                    debt_item_to_merge_into.save()

                    # If the debt_item merged into should be tagged as merged
                    if form.cleaned_data["mark_tag_debt_item"]:
                        debt_item_to_merge_into.tags.add("merged")

                    debt_item_action = ""
                    # Take action on the debt_items
                    if form.cleaned_data["debt_item_action"] == "inactive":
                        debt_item_action = "inactivated"
                        debt_items_to_merge.exclude(pk=debt_item_to_merge_into.pk).update(
                            active=False,
                            last_reviewed=timezone.now(),
                            last_reviewed_by=request.user,
                        )
                    elif form.cleaned_data["debt_item_action"] == "delete":
                        debt_item_action = "deleted"
                        debt_items_to_merge.delete()

                    notes_entry = ("debt_item consists of merged debt_items from the following "
                                   "debt_items which have been {}: {}").format(
                        debt_item_action, notes_entry[:-1]
                    )
                    note = Notes(entry=notes_entry, author=request.user)
                    note.save()
                    debt_item_to_merge_into.notes.add(note)

                    messages.add_message(
                        request,
                        messages.SUCCESS,
                        "debt_items merged",
                        extra_tags="alert-success",
                    )
                    return HttpResponseRedirect(
                        reverse("edit_debt_item", args=(debt_item_to_merge_into.id,))
                    )
                else:
                    messages.add_message(
                        request,
                        messages.ERROR,
                        "Unable to merge debt_items. debt_items to merge contained in debt_item to merge into.",
                        extra_tags="alert-danger",
                    )
            else:
                messages.add_message(
                    request,
                    messages.ERROR,
                    "Unable to merge debt_items. Required fields were not selected.",
                    extra_tags="alert-danger",
                )

    debt_context_tab = Product_Tab(
        debt_item.test.engagement.debt_context, title="Merge debt_items", tab="debt_items"
    )
    custom_breadcrumb = {
        "Open debt_items": reverse(
            "debt_context_open_debt_items", args=(debt_item.test.engagement.debt_context.id,)
        )
        + "?test__engagement__debt_context="
        + str(debt_item.test.engagement.debt_context.id)
    }

    return render(
        request,
        "dojo/merge_debt_items.html",
        {
            "form": form,
            "name": "Merge debt_items",
            "debt_item": debt_item,
            "debt_context_tab": debt_context_tab,
            "title": debt_context_tab.title,
            "custom_breadcrumb": custom_breadcrumb,
        },
    )


# bulk update and delete are combined, so we can't have the nice user_is_authorized decorator
def debt_item_bulk_update_all(request, pid=None):
    system_settings = System_Settings.objects.get()

    logger.debug("bulk 10")
    form = DebtItemBulkUpdateForm(request.POST)
    now = timezone.now()
    return_url = None

    if request.method == "POST":
        logger.debug("bulk 20")

        debt_item_to_update = request.POST.getlist("debt_item_to_update")
        finds = Debt_Item.objects.filter(id__in=debt_item_to_update).order_by("id")
        total_find_count = finds.count()
        debt_contexts = set([find.test.engagement.debt_context for find in finds])
        if request.POST.get("delete_bulk_debt_items"):
            if form.is_valid() and debt_item_to_update:
                if pid is not None:
                    debt_context = get_object_or_404(Product, id=pid)
                    user_has_permission_or_403(
                        request.user, debt_context, Permissions.Debt_Item_Delete
                    )

                finds = get_authorized_debt_items(
                    Permissions.Debt_Item_Delete, finds
                ).distinct()

                skipped_find_count = total_find_count - finds.count()
                deleted_find_count = finds.count()

                for find in finds:
                    find.delete()

                if skipped_find_count > 0:
                    add_error_message_to_response(
                        "Skipped deletion of {} debt_items because you are not authorized.".format(
                            skipped_find_count
                        )
                    )

                if deleted_find_count > 0:
                    messages.add_message(
                        request,
                        messages.SUCCESS,
                        "Bulk delete of {} debt_items was successful.".format(
                            deleted_find_count
                        ),
                        extra_tags="alert-success",
                    )
        else:
            if form.is_valid() and debt_item_to_update:
                if pid is not None:
                    debt_context = get_object_or_404(Product, id=pid)
                    user_has_permission_or_403(
                        request.user, debt_context, Permissions.Debt_Item_Edit
                    )

                # make sure users are not editing stuff they are not authorized for
                finds = get_authorized_debt_items(
                    Permissions.Debt_Item_Edit, finds
                ).distinct()

                skipped_find_count = total_find_count - finds.count()
                updated_find_count = finds.count()

                if skipped_find_count > 0:
                    add_error_message_to_response(
                        "Skipped update of {} debt_items because you are not authorized.".format(
                            skipped_find_count
                        )
                    )

                finds = prefetch_for_debt_items(finds)
                if form.cleaned_data["severity"] or form.cleaned_data["status"]:
                    for find in finds:
                        old_find = copy.deepcopy(find)

                        if form.cleaned_data["severity"]:
                            find.severity = form.cleaned_data["severity"]
                            find.numerical_severity = Debt_Item.get_numerical_severity(
                                form.cleaned_data["severity"]
                            )
                            find.last_reviewed = now
                            find.last_reviewed_by = request.user

                        if form.cleaned_data["status"]:
                            # logger.debug('setting status from bulk edit form: %s', form)
                            find.active = form.cleaned_data["active"]
                            find.verified = form.cleaned_data["verified"]
                            find.false_p = form.cleaned_data["false_p"]
                            find.out_of_scope = form.cleaned_data["out_of_scope"]
                            find.is_mitigated = form.cleaned_data["is_mitigated"]
                            find.last_reviewed = timezone.now()
                            find.last_reviewed_by = request.user

                        # use super to avoid all custom logic in our overriden save method
                        # it will trigger the pre_save signal
                        find.save_no_options()

                        if system_settings.false_positive_history:
                            # If debt_item is being marked as false positive
                            if find.false_p:
                                do_false_positive_history(find)

                            # If debt_item was a false positive and is being reactivated: retroactively reactivates all equal debt_items
                            elif old_find.false_p and not find.false_p:
                                if system_settings.retroactive_false_positive_history:
                                    logger.debug('FALSE_POSITIVE_HISTORY: Reactivating existing debt_items based on: %s', find)

                                    existing_fp_debt_items = match_debt_item_to_existing_debt_items(
                                        find, debt_context=find.test.engagement.debt_context
                                    ).filter(false_p=True)

                                    for fp in existing_fp_debt_items:
                                        logger.debug('FALSE_POSITIVE_HISTORY: Reactivating false positive %i: %s', fp.id, fp)
                                        fp.active = find.active
                                        fp.verified = find.verified
                                        fp.false_p = False
                                        fp.out_of_scope = find.out_of_scope
                                        fp.is_mitigated = find.is_mitigated
                                        fp.save_no_options()

                    for debt_context in debt_contexts:
                        debt_calculate_grade(debt_context)

                if form.cleaned_data["date"]:
                    for debt_item in finds:
                        debt_item.date = form.cleaned_data["date"]
                        debt_item.save_no_options()

                if form.cleaned_data["planned_remediation_date"]:
                    for debt_item in finds:
                        debt_item.planned_remediation_date = form.cleaned_data[
                            "planned_remediation_date"
                        ]
                        debt_item.save_no_options()

                if form.cleaned_data["planned_remediation_version"]:
                    for debt_item in finds:
                        debt_item.planned_remediation_version = form.cleaned_data[
                            "planned_remediation_version"
                        ]
                        debt_item.save_no_options()

                skipped_risk_accept_count = 0
                if form.cleaned_data["risk_acceptance"]:
                    for debt_item in finds:
                        if not debt_item.duplicate:
                            if form.cleaned_data["risk_accept"]:
                                if (
                                    not debt_item.test.engagement.debt_context.enable_simple_risk_acceptance
                                ):
                                    skipped_risk_accept_count += 1
                                else:
                                    ra_helper.simple_risk_accept(debt_item)
                            elif form.cleaned_data["risk_unaccept"]:
                                ra_helper.risk_unaccept(debt_item)

                    for debt_context in debt_contexts:
                        debt_calculate_grade(debt_context)

                if skipped_risk_accept_count > 0:
                    messages.add_message(
                        request,
                        messages.WARNING,
                        ("Skipped simple risk acceptance of %i debt_items, "
                         "simple risk acceptance is disabled on the related debt_contexts")
                        % skipped_risk_accept_count,
                        extra_tags="alert-warning",
                    )

                if form.cleaned_data["debt_item_group_create"]:
                    logger.debug("debt_item_group_create checked!")
                    debt_item_group_name = form.cleaned_data["debt_item_group_create_name"]
                    logger.debug("debt_item_group_create_name: %s", debt_item_group_name)
                    debt_item_group, added, skipped = debt_item_helper.create_debt_item_group(
                        finds, debt_item_group_name
                    )

                    if added:
                        add_success_message_to_response(
                            "Created debt_item group with %s debt_items" % added
                        )
                        return_url = reverse(
                            "view_debt_item_group", args=(debt_item_group.id,)
                        )

                    if skipped:
                        add_success_message_to_response(
                            "Skipped %s debt_items in group creation, debt_items already part of another group"
                            % skipped
                        )

                    # refresh debt_items from db
                    finds = finds.all()

                if form.cleaned_data["debt_item_group_add"]:
                    logger.debug("debt_item_group_add checked!")
                    fgid = form.cleaned_data["add_to_debt_item_group_id"]
                    debt_item_group = Debt_Item_Group.objects.get(id=fgid)
                    debt_item_group, added, skipped = debt_item_helper.add_to_debt_item_group(
                        debt_item_group, finds
                    )

                    if added:
                        add_success_message_to_response(
                            "Added %s debt_items to debt_item group %s"
                            % (added, debt_item_group.name)
                        )
                        return_url = reverse(
                            "view_debt_item_group", args=(debt_item_group.id,)
                        )

                    if skipped:
                        add_success_message_to_response(
                            ("Skipped %s debt_items when adding to debt_item group %s, "
                             "debt_items already part of another group")
                            % (skipped, debt_item_group.name)
                        )

                    # refresh debt_items from db
                    finds = finds.all()

                if form.cleaned_data["debt_item_group_remove"]:
                    logger.debug("debt_item_group_remove checked!")
                    (
                        debt_item_groups,
                        removed,
                        skipped,
                    ) = debt_item_helper.remove_from_debt_item_group(finds)

                    if removed:
                        add_success_message_to_response(
                            "Removed %s debt_items from debt_item groups %s"
                            % (
                                removed,
                                ",".join(
                                    [
                                        debt_item_group.name
                                        for debt_item_group in debt_item_groups
                                    ]
                                ),
                            )
                        )

                    if skipped:
                        add_success_message_to_response(
                            "Skipped %s debt_items when removing from any debt_item group, debt_items not part of any group"
                            % (skipped)
                        )

                    # refresh debt_items from db
                    finds = finds.all()

                if form.cleaned_data["debt_item_group_by"]:
                    logger.debug("debt_item_group_by checked!")
                    logger.debug(form.cleaned_data)
                    debt_item_group_by_option = form.cleaned_data[
                        "debt_item_group_by_option"
                    ]
                    logger.debug("debt_item_group_by_option: %s", debt_item_group_by_option)

                    (
                        debt_item_groups,
                        grouped,
                        skipped,
                        groups_created,
                    ) = debt_item_helper.group_debt_items_by(finds, debt_item_group_by_option)

                    if grouped:
                        add_success_message_to_response(
                            "Grouped %d debt_items into %d (%d newly created) debt_item groups"
                            % (grouped, len(debt_item_groups), groups_created)
                        )

                    if skipped:
                        add_success_message_to_response(
                            ("Skipped %s debt_items when grouping by %s as these debt_items "
                             "were already in an existing group")
                            % (skipped, debt_item_group_by_option)
                        )

                    # refresh debt_items from db
                    finds = finds.all()

                if form.cleaned_data["push_to_github"]:
                    logger.debug("push selected debt_items to github")
                    for debt_item in finds:
                        logger.debug("will push to GitHub debt_item: " + str(debt_item))
                        old_status = debt_item.status()
                        if form.cleaned_data["push_to_github"]:
                            if GITHUB_Issue.objects.filter(debt_item=debt_item).exists():
                                update_external_issue(debt_item, old_status, "github")
                            else:
                                add_external_issue(debt_item, "github")

                if form.cleaned_data["notes"]:
                    logger.debug("Setting bulk notes")
                    note = Notes(
                        entry=form.cleaned_data["notes"],
                        author=request.user,
                        date=timezone.now(),
                    )
                    note.save()
                    history = NoteHistory(
                        data=note.entry, time=note.date, current_editor=note.author
                    )
                    history.save()
                    note.history.add(history)
                    for debt_item in finds:
                        debt_item.notes.add(note)
                        debt_item.save()

                if form.cleaned_data["tags"]:
                    for debt_item in finds:
                        tags = form.cleaned_data["tags"]
                        logger.debug(
                            "bulk_edit: setting tags for: %i %s %s",
                            debt_item.id,
                            debt_item,
                            tags,
                        )
                        # currently bulk edit overwrites existing tags
                        debt_item.tags = tags
                        debt_item.save()

                error_counts = defaultdict(lambda: 0)
                success_count = 0
                debt_item_groups = set(
                    [find.debt_item_group for find in finds if find.has_debt_item_group]
                )
                logger.debug("debt_item_groups: %s", debt_item_groups)
                groups_pushed_to_jira = False
                for group in debt_item_groups:
                    if form.cleaned_data.get("push_to_jira"):
                        (
                            can_be_pushed_to_jira,
                            error_message,
                            error_code,
                        ) = jira_helper.can_be_pushed_to_jira(group)
                        if not can_be_pushed_to_jira:
                            error_counts[error_message] += 1
                            jira_helper.log_jira_alert(error_message, group)
                        else:
                            logger.debug(
                                "pushing to jira from debt_item.debt_item_bulk_update_all()"
                            )
                            jira_helper.push_to_jira(group)
                            success_count += 1

                for error_message, error_count in error_counts.items():
                    add_error_message_to_response(
                        "%i debt_item groups could not be pushed to JIRA: %s"
                        % (error_count, error_message)
                    )

                if success_count > 0:
                    add_success_message_to_response(
                        "%i debt_item groups pushed to JIRA successfully" % success_count
                    )
                    groups_pushed_to_jira = True

                # refresh from db
                finds = finds.all()

                error_counts = defaultdict(lambda: 0)
                success_count = 0
                for debt_item in finds:
                    from dojo.tools import tool_issue_updater

                    tool_issue_updater.async_tool_issue_update(debt_item)

                    # not sure yet if we want to support bulk unlink, so leave as commented out for now
                    # if form.cleaned_data['unlink_from_jira']:
                    #     if debt_item.has_jira_issue:
                    #         jira_helper.debt_item_unlink_jira(request, debt_item)

                    # Because we never call debt_item.save() in a bulk update, we need to actually
                    # push the JIRA stuff here, rather than in debt_item.save()
                    # can't use helper as when push_all_jira_issues is True,
                    # the checkbox gets disabled and is always false
                    # push_to_jira = jira_helper.is_push_to_jira(new_debt_item,
                    # form.cleaned_data.get('push_to_jira'))
                    if not groups_pushed_to_jira and (
                        jira_helper.is_push_all_issues(debt_item)
                        or form.cleaned_data.get("push_to_jira")
                    ):
                        (
                            can_be_pushed_to_jira,
                            error_message,
                            error_code,
                        ) = jira_helper.can_be_pushed_to_jira(debt_item)
                        if debt_item.has_jira_group_issue and not debt_item.has_jira_issue:
                            error_message = (
                                "debt_item already pushed as part of debt_item Group"
                            )
                            error_counts[error_message] += 1
                            jira_helper.log_jira_alert(error_message, debt_item)
                        elif not can_be_pushed_to_jira:
                            error_counts[error_message] += 1
                            jira_helper.log_jira_alert(error_message, debt_item)
                        else:
                            logger.debug(
                                "pushing to jira from debt_item.debt_item_bulk_update_all()"
                            )
                            jira_helper.push_to_jira(debt_item)
                            success_count += 1

                for error_message, error_count in error_counts.items():
                    add_error_message_to_response(
                        "%i debt_items could not be pushed to JIRA: %s"
                        % (error_count, error_message)
                    )

                if success_count > 0:
                    add_success_message_to_response(
                        "%i debt_items pushed to JIRA successfully" % success_count
                    )

                if updated_find_count > 0:
                    messages.add_message(
                        request,
                        messages.SUCCESS,
                        "Bulk update of {} debt_items was successful.".format(
                            updated_find_count
                        ),
                        extra_tags="alert-success",
                    )
            else:
                messages.add_message(
                    request,
                    messages.ERROR,
                    "Unable to process bulk update. Required fields were not selected.",
                    extra_tags="alert-danger",
                )

    if return_url:
        redirect(request, return_url)

    return redirect_to_return_url_or_else(request, None)


def find_available_notetypes(notes):
    single_note_types = Note_Type.objects.filter(
        is_single=True, is_active=True
    ).values_list("id", flat=True)
    multiple_note_types = Note_Type.objects.filter(
        is_single=False, is_active=True
    ).values_list("id", flat=True)
    available_note_types = []
    for note_type_id in multiple_note_types:
        available_note_types.append(note_type_id)
    for note_type_id in single_note_types:
        for note in notes:
            if note_type_id == note.note_type_id:
                break
        else:
            available_note_types.append(note_type_id)
    queryset = Note_Type.objects.filter(id__in=available_note_types).order_by("-id")
    return queryset


def get_missing_mandatory_notetypes(debt_item):
    notes = debt_item.notes.all()
    mandatory_note_types = Note_Type.objects.filter(
        is_mandatory=True, is_active=True
    ).values_list("id", flat=True)
    notes_to_be_added = []
    for note_type_id in mandatory_note_types:
        for note in notes:
            if note_type_id == note.note_type_id:
                break
        else:
            notes_to_be_added.append(note_type_id)
    queryset = Note_Type.objects.filter(id__in=notes_to_be_added)
    return queryset


@user_is_authorized(Debt_Item, Permissions.Debt_Item_Edit, "original_id")
@require_POST
def mark_debt_item_duplicate(request, original_id, duplicate_id):

    original = get_object_or_404(Debt_Item, id=original_id)
    duplicate = get_object_or_404(Debt_Item, id=duplicate_id)

    if original.test.engagement != duplicate.test.engagement:
        if (original.test.engagement.deduplication_on_engagement
                or duplicate.test.engagement.deduplication_on_engagement):
            messages.add_message(
                request,
                messages.ERROR,
                ("Marking debt_item as duplicate/original failed as they are not in the same engagement "
                 "and deduplication_on_engagement is enabled for at least one of them"),
                extra_tags="alert-danger",
            )
            return redirect_to_return_url_or_else(
                request, reverse("view_debt_item", args=(duplicate.id,))
            )

    duplicate.duplicate = True
    duplicate.active = False
    duplicate.verified = False
    # make sure we don't create circular or transitive duplicates
    if original.duplicate:
        duplicate.duplicate_debt_item = original.duplicate_debt_item
    else:
        duplicate.duplicate_debt_item = original

    logger.debug(
        "marking debt_item %i as duplicate of %i",
        duplicate.id,
        duplicate.duplicate_debt_item.id,
    )

    duplicate.last_reviewed = timezone.now()
    duplicate.last_reviewed_by = request.user
    duplicate.save(dedupe_option=False)
    original.found_by.add(duplicate.test.test_type)
    original.save(dedupe_option=False)

    return redirect_to_return_url_or_else(
        request, reverse("view_debt_item", args=(duplicate.id,))
    )


def reset_debt_item_duplicate_status_internal(user, duplicate_id):
    duplicate = get_object_or_404(Debt_Item, id=duplicate_id)

    if not duplicate.duplicate:
        return None

    logger.debug("resetting duplicate status of %i", duplicate.id)
    duplicate.duplicate = False
    duplicate.active = True
    if duplicate.duplicate_debt_item:
        # duplicate.duplicate_debt_item.original_debt_item.remove(duplicate)  # shouldn't be needed
        duplicate.duplicate_debt_item = None
    duplicate.last_reviewed = timezone.now()
    duplicate.last_reviewed_by = user
    duplicate.save(dedupe_option=False)

    return duplicate.id


@user_is_authorized(Debt_Item, Permissions.Debt_Item_Edit, "duplicate_id")
@require_POST
def reset_debt_item_duplicate_status(request, duplicate_id):
    checked_duplicate_id = reset_debt_item_duplicate_status_internal(
        request.user, duplicate_id
    )
    if checked_duplicate_id is None:
        messages.add_message(
            request,
            messages.ERROR,
            "Can't reset duplicate status of a debt_item that is not a duplicate",
            extra_tags="alert-danger",
        )
        return redirect_to_return_url_or_else(
            request, reverse("view_debt_item", args=(duplicate_id,))
        )

    return redirect_to_return_url_or_else(
        request, reverse("view_debt_item", args=(checked_duplicate_id,))
    )


def set_debt_item_as_original_internal(user, debt_item_id, new_original_id):
    debt_item = get_object_or_404(Debt_Item, id=debt_item_id)
    new_original = get_object_or_404(debt_item, id=new_original_id)

    if debt_item.test.engagement != new_original.test.engagement:
        if (debt_item.test.engagement.deduplication_on_engagement
                or new_original.test.engagement.deduplication_on_engagement):
            return False

    if debt_item.duplicate or debt_item.original_debt_item.all():
        # existing cluster, so update all cluster members

        if debt_item.duplicate and debt_item.duplicate_debt_item:
            logger.debug(
                "setting old original %i as duplicate of %i",
                debt_item.duplicate_debt_item.id,
                new_original.id,
            )
            debt_item.duplicate_debt_item.duplicate_debt_item = new_original
            debt_item.duplicate_debt_item.duplicate = True
            debt_item.duplicate_debt_item.save(dedupe_option=False)

        for cluster_member in debt_item.duplicate_debt_item_set():
            if cluster_member != new_original:
                logger.debug(
                    "setting new original for %i to %i",
                    cluster_member.id,
                    new_original.id,
                )
                cluster_member.duplicate_debt_item = new_original
                cluster_member.save(dedupe_option=False)

        logger.debug(
            "setting new original for old root %i to %i", debt_item.id, new_original.id
        )
        debt_item.duplicate = True
        debt_item.duplicate_debt_item = new_original
        debt_item.save(dedupe_option=False)

    else:
        # creating a new cluster, so mark debt_item as duplicate
        logger.debug("marking %i as duplicate of %i", debt_item.id, new_original.id)
        debt_item.duplicate = True
        debt_item.active = False
        debt_item.duplicate_debt_item = new_original
        debt_item.last_reviewed = timezone.now()
        debt_item.last_reviewed_by = user
        debt_item.save(dedupe_option=False)

    logger.debug("marking new original %i as not duplicate", new_original.id)
    new_original.duplicate = False
    new_original.duplicate_debt_item = None
    new_original.save(dedupe_option=False)

    return True


@user_is_authorized(Debt_Item, Permissions.Debt_Item_Edit, "debt_item_id")
@require_POST
def set_debt_item_as_original(request, debt_item_id, new_original_id):
    success = set_debt_item_as_original_internal(
        request.user, debt_item_id, new_original_id
    )
    if not success:
        messages.add_message(
            request,
            messages.ERROR,
            ("Marking debt_item as duplicate/original failed as they are not in the same engagement "
             "and deduplication_on_engagement is enabled for at least one of them"),
            extra_tags="alert-danger",
        )

    return redirect_to_return_url_or_else(
        request, reverse("view_debt_item", args=(debt_item_id,))
    )


@user_is_authorized(Debt_Item, Permissions.Debt_Item_Edit, "fid")
@require_POST
def unlink_jira(request, fid):
    debt_item = get_object_or_404(Debt_Item, id=fid)
    logger.info(
        "trying to unlink a linked jira issue from %d:%s", debt_item.id, debt_item.title
    )
    if debt_item.has_jira_issue:
        try:
            jira_helper.debt_item_unlink_jira(request, debt_item)

            messages.add_message(
                request,
                messages.SUCCESS,
                "Link to JIRA issue succesfully deleted",
                extra_tags="alert-success",
            )

            return JsonResponse({"result": "OK"})
        except Exception as e:
            logger.exception(e)
            messages.add_message(
                request,
                messages.ERROR,
                "Link to JIRA could not be deleted, see alerts for details",
                extra_tags="alert-danger",
            )

            return HttpResponse(status=500)
    else:
        messages.add_message(
            request, messages.ERROR, "Link to JIRA not found", extra_tags="alert-danger"
        )
        return HttpResponse(status=400)


@user_is_authorized(Debt_Item, Permissions.Debt_Item_Edit, "fid")
@require_POST
def push_to_jira(request, fid):
    debt_item = get_object_or_404(Debt_Item, id=fid)
    try:
        logger.info(
            "trying to push %d:%s to JIRA to create or update JIRA issue",
            debt_item.id,
            debt_item.title,
        )
        logger.debug("pushing to jira from debt_item.push_to-jira()")

        # it may look like succes here, but the push_to_jira are swallowing exceptions
        # but cant't change too much now without having a test suite,
        # so leave as is for now with the addition warning message
        # to check alerts for background errors.
        if jira_helper.push_to_jira(debt_item):
            messages.add_message(
                request,
                messages.SUCCESS,
                message="Action queued to create or update linked JIRA issue, check alerts for background errors.",
                extra_tags="alert-success",
            )
        else:
            messages.add_message(
                request,
                messages.SUCCESS,
                "Push to JIRA failed, check alerts on the top right for errors",
                extra_tags="alert-danger",
            )

        return JsonResponse({"result": "OK"})
    except Exception as e:
        logger.exception(e)
        logger.error("Error pushing to JIRA: ", exc_info=True)
        messages.add_message(
            request, messages.ERROR, "Error pushing to JIRA", extra_tags="alert-danger"
        )
        return HttpResponse(status=500)


# precalculate because we need related_actions to be set
def duplicate_cluster(request, debt_item):
    duplicate_cluster = debt_item.duplicate_debt_item_set()

    duplicate_cluster = prefetch_for_debt_items(duplicate_cluster)

    # populate actions for debt_items in duplicate cluster
    for duplicate_member in duplicate_cluster:
        duplicate_member.related_actions = (
            calculate_possible_related_actions_for_similar_debt_item(
                request, debt_item, duplicate_member
            )
        )

    return duplicate_cluster


# django doesn't allow much logic or even method calls with parameters in templates.
# so we have to use a function in this view to calculate the possible actions on a similar (or duplicate) debt_item.
# and we assign this dictionary to the debt_item so it can be accessed in the template.
# these actions are always calculated in the context of the debt_item the user is viewing
# because this determines which actions are possible
def calculate_possible_related_actions_for_similar_debt_item(
    request, debt_item, similar_debt_item
):
    actions = []
    if similar_debt_item.test.engagement != debt_item.test.engagement and (
        similar_debt_item.test.engagement.deduplication_on_engagement
        or debt_item.test.engagement.deduplication_on_engagement
    ):
        actions.append(
            {
                "action": "None",
                "reason": ("This debt_item is in a different engagement and deduplication_inside_engagment "
                           "is enabled here or in that debt_item"),
            }
        )
    elif debt_item.duplicate_debt_item == similar_debt_item:
        actions.append(
            {
                "action": "None",
                "reason": ("This debt_item is the root of the cluster, use an action on another row, "
                           "or the debt_item on top of the page to change the root of the cluser"),
            }
        )
    elif similar_debt_item.original_debt_item.all():
        actions.append(
            {
                "action": "None",
                "reason": ("This debt_item is similar, but is already an original in a different cluster. "
                           "Remove it from that cluster before you connect it to this cluster."),
            }
        )
    else:
        if similar_debt_item.duplicate_debt_item:
            # reset duplicate status is always possible
            actions.append(
                {
                    "action": "reset_debt_item_duplicate_status",
                    "reason": ("This will remove the debt_item from the cluster, "
                               "effectively marking it no longer as duplicate. "
                               "Will not trigger deduplication logic after saving."),
                }
            )

            if (
                similar_debt_item.duplicate_debt_item == debt_item
                or similar_debt_item.duplicate_debt_item == debt_item.duplicate_debt_item
            ):
                # duplicate inside the same cluster
                actions.append(
                    {
                        "action": "set_debt_item_as_original",
                        "reason": ("Sets this debt_item as the Original for the whole cluster. "
                                   "The existing Original will be downgraded to become a member of the cluster and, "
                                   "together with the other members, will be marked as duplicate of the new Original."),
                    }
                )
            else:
                # duplicate inside different cluster
                actions.append(
                    {
                        "action": "mark_debt_item_duplicate",
                        "reason": ("Will mark this debt_item as duplicate of the root debt_item in this cluster, "
                                   "effectively adding it to the cluster and removing it from the other cluster."),
                    }
                )
        else:
            # similar is not a duplicate yet
            if debt_item.duplicate or debt_item.original_debt_item.all():
                actions.append(
                    {
                        "action": "mark_debt_item_duplicate",
                        "reason": "Will mark this debt_item as duplicate of the root debt_item in this cluster",
                    }
                )
                actions.append(
                    {
                        "action": "set_debt_item_as_original",
                        "reason": ("Sets this debt_item as the Original for the whole cluster. "
                                   "The existing Original will be downgraded to become a member of the cluster and, "
                                   "together with the other members, will be marked as duplicate of the new Original."),
                    }
                )
            else:
                # similar_debt_item is not an original/root of a cluster as per earlier if clause
                actions.append(
                    {
                        "action": "mark_debt_item_duplicate",
                        "reason": "Will mark this debt_item as duplicate of the debt_item on this page.",
                    }
                )
                actions.append(
                    {
                        "action": "set_debt_item_as_original",
                        "reason": ("Sets this debt_item as the Original marking the debt_item "
                                   "on this page as duplicate of this original."),
                    }
                )

    return actions
