import logging

from django.utils.translation import gettext as _
from django.shortcuts import render
from watson import search as watson
from django.db.models import Q
from dojo.forms import SimpleSearchForm
from dojo.models import Debt_Item, Debt_Item_Template, Debt_Context, Debt_Test, Debt_Engagement, Languages
from dojo.utils import add_breadcrumb, get_page_items, get_words_for_field
import re
from dojo.debt_item.views import prefetch_for_debt_items
from dojo.endpoint.views import prefetch_for_endpoints
from dojo.filters import DebtItemFilter
from django.conf import settings
import shlex
import itertools
from dojo.debt_context.queries import get_authorized_debt_contexts, get_authorized_app_analysis
from dojo.debt_engagement.queries import get_authorized_debt_engagements
from dojo.debt_test.queries import get_authorized_debt_tests
from dojo.debt_item.queries import get_authorized_debt_items, get_authorized_vulnerability_ids
from dojo.endpoint.queries import get_authorized_endpoints
from dojo.authorization.roles_permissions import Permissions

logger = logging.getLogger(__name__)

# explicitly use our own regex pattern here as django-watson is sensitive so we want to control it here independently of models.py etc.
vulnerability_id_pattern = re.compile(r'(^[A-Z]+-[A-Z\d-]+)$')

max_results = settings.SEARCH_MAX_RESULTS


def simple_search(request):
    debt_tests = None
    debt_items = None
    debt_item_templates = None
    debt_contexts = None
    tagged_debt_tests = None
    tagged_debt_items = None
    tagged_debt_contexts = None
    tagged_endpoints = None
    tagged_debt_engagements = None
    tagged_debt_item_templates = None
    debt_engagements = None
    endpoints = None
    languages = None
    app_analysis = None
    vulnerability_ids = None
    clean_query = ''
    cookie = False
    form = SimpleSearchForm()

    original_clean_query = ""
    debt_items_filter = None
    title_words = None
    component_words = None

    # if request.method == 'GET' and "query" in request.GET:
    if request.method == 'GET':
        form = SimpleSearchForm(request.GET)
        if form.is_valid():
            cookie = True

            clean_query = form.cleaned_data['query'] or ''
            original_clean_query = clean_query

            operators, keywords = parse_search_query(clean_query)

            search_tags = "tag" in operators or "debt_test-tag" in operators or "debt_engagement-tag" in operators or "debt_context-tag" in operators or \
                          "tags" in operators or "debt_test-tags" in operators or "debt_engagement-tags" in operators or "debt_context-tags" in operators or \
                          "not-tag" in operators or "not-debt_test-tag" in operators or "not-debt_engagement-tag" in operators or "not-debt_context-tag" in operators or \
                          "not-tags" in operators or "not-debt_test-tags" in operators or "not-debt_engagement-tags" in operators or "not-debt_context-tags" in operators

            search_vulnerability_ids = "vulnerability_id" in operators or not operators

            search_debt_item_id = "id" in operators
            search_debt_items = "debt_item" in operators or search_debt_item_id or search_tags or not operators

            search_debt_item_templates = "template" in operators or search_tags or not (operators or search_debt_item_id)
            search_debt_tests = "debt_test" in operators or search_tags or not (operators or search_debt_item_id)
            search_debt_engagements = "debt_engagement" in operators or search_tags or not (operators or search_debt_item_id)

            search_debt_contexts = "debt_context" in operators or search_tags or not (operators or search_debt_item_id)
            search_endpoints = "endpoint" in operators or search_tags or not (operators or search_debt_item_id)
            search_languages = "language" in operators or search_tags or not (operators or search_debt_item_id)
            search_technologies = "technology" in operators or search_tags or not (operators or search_debt_item_id)

            authorized_debt_items = get_authorized_debt_items(Permissions.Debt_Item_View)
            authorized_debt_tests = get_authorized_debt_tests(Permissions.Debt_Test_View)
            authorized_debt_engagements = get_authorized_debt_engagements(Permissions.Debt_Engagement_View)
            authorized_debt_contexts = get_authorized_debt_contexts(Permissions.Debt_Context_View)
            authorized_endpoints = get_authorized_endpoints(Permissions.Endpoint_View)
            authorized_debt_item_templates = Debt_Item_Template.objects.all()
            authorized_app_analysis = get_authorized_app_analysis(Permissions.Debt_Context_View)
            authorized_vulnerability_ids = get_authorized_vulnerability_ids(Permissions.Debt_Item_View)

            # TODO better get debt_items in their own query and match on id. that would allow filtering on additional fields such prod_id, etc.

            debt_items = authorized_debt_items
            debt_tests = authorized_debt_tests
            debt_engagements = authorized_debt_engagements
            debt_contexts = authorized_debt_contexts
            endpoints = authorized_endpoints
            app_analysis = authorized_app_analysis
            vulnerability_ids = authorized_vulnerability_ids

            debt_items_filter = None
            title_words = None
            component_words = None

            keywords_query = ' '.join(keywords)

            if search_debt_item_id:
                logger.debug('searching debt_item id')

                debt_items = authorized_debt_items
                debt_items = debt_items.filter(id=operators['id'][0])

            elif search_debt_items:
                logger.debug('searching debt_items')

                debt_items_filter = DebtItemFilter(request.GET, queryset=debt_items, user=request.user, pid=None, prefix='debt_item')
                # setting initial values for filters is not supported and discouraged: https://django-filter.readthedocs.io/en/stable/guide/tips.html#using-initial-values-as-defaults
                # we could try to modify request.GET before generating the filter, but for now we'll leave it as is

                title_words = get_words_for_field(Debt_Item, 'title')
                component_words = get_words_for_field(Debt_Item, 'component_name')

                debt_items = debt_items_filter.qs

                debt_items = apply_tag_filters(debt_items, operators)
                debt_items = apply_endpoint_filter(debt_items, operators)

                debt_items = perform_keyword_search_for_operator(debt_items, operators, 'debt_item', keywords_query)

            else:
                debt_items = None
                debt_items_filter = None
                component_words = None

            # prefetch after watson to avoid inavlid query errors due to watson not understanding prefetching
            if debt_items is not None:  # check for None to avoid query execution
                logger.debug('prefetching debt_items')

                debt_items = get_page_items(request, debt_items, 25)

                debt_items.object_list = prefetch_for_debt_items(debt_items.object_list)

                # some over the top tag displaying happening...
                debt_items.object_list = debt_items.object_list.prefetch_related('debt_test__debt_engagement__debt_context__tags')

            tag = operators['tag'] if 'tag' in operators else keywords
            tags = operators['tags'] if 'tags' in operators else keywords
            not_tag = operators['not-tag'] if 'not-tag' in operators else keywords
            not_tags = operators['not-tags'] if 'not-tags' in operators else keywords
            if search_tags and tag or tags or not_tag or not_tags:
                logger.debug('searching tags')

                Q1, Q2, Q3, Q4 = Q(), Q(), Q(), Q()

                if tag:
                    tag = ','.join(tag)  # contains needs a single value
                    Q1 = Q(tags__name__contains=tag)

                if tags:
                    Q2 = Q(tags__name__in=tags)

                if not_tag:
                    not_tag = ','.join(not_tag)  # contains needs a single value
                    Q3 = Q(tags__name__contains=not_tag)

                if not_tags:
                    Q4 = Q(tags__name__in=not_tags)

                tagged_debt_items = authorized_debt_items.filter(Q1 | Q2).exclude(Q3 | Q4).distinct()[:max_results].prefetch_related('tags')
                tagged_debt_item_templates = authorized_debt_item_templates.filter(Q1 | Q2).exclude(Q3 | Q4).distinct()[:max_results]
                tagged_debt_tests = authorized_debt_tests.filter(Q1 | Q2).exclude(Q3 | Q4).distinct()[:max_results].prefetch_related('tags')
                tagged_debt_engagements = authorized_debt_engagements.filter(Q1 | Q2).exclude(Q3 | Q4).distinct()[:max_results].prefetch_related('tags')
                tagged_debt_contexts = authorized_debt_contexts.filter(Q1 | Q2).exclude(Q3 | Q4).distinct()[:max_results].prefetch_related('tags')
                tagged_endpoints = authorized_endpoints.filter(Q1 | Q2).exclude(Q3 | Q4).distinct()[:max_results].prefetch_related('tags')
            else:
                tagged_debt_items = None
                tagged_debt_item_templates = None
                tagged_debt_tests = None
                tagged_debt_engagements = None
                tagged_debt_contexts = None
                tagged_endpoints = None

            tagged_results = tagged_debt_items or tagged_debt_item_templates or tagged_debt_tests or tagged_debt_engagements or tagged_debt_contexts or tagged_endpoints

            if search_debt_item_templates:
                logger.debug('searching Debt Item templates')

                debt_item_templates = authorized_debt_item_templates
                debt_item_templates = apply_tag_filters(debt_item_templates, operators)

                if keywords_query:
                    watson_results = watson.filter(debt_item_templates, keywords_query)
                    debt_item_templates = debt_item_templates.filter(id__in=[watson.id for watson in watson_results])

                debt_item_templates = debt_item_templates[:max_results]
            else:
                debt_item_templates = None

            if search_debt_tests:
                logger.debug('searching Debt Tests')

                debt_tests = authorized_debt_tests
                debt_tests = apply_tag_filters(debt_tests, operators)

                if keywords_query:
                    watson_results = watson.filter(debt_tests, keywords_query)
                    debt_tests = debt_tests.filter(id__in=[watson.id for watson in watson_results])

                debt_tests = debt_tests.prefetch_related('debt_engagement', 'debt_engagement__debt_context', 'debt_test_type', 'tags', 'debt_engagement__tags', 'debt_engagement__debt_context__tags')
                debt_tests = debt_tests[:max_results]
            else:
                debt_tests = None

            if search_debt_engagements:
                logger.debug('searching Debt Engagements')

                debt_engagements = authorized_debt_engagements
                debt_engagements = apply_tag_filters(debt_engagements, operators)

                if keywords_query:
                    watson_results = watson.filter(debt_engagements, keywords_query)
                    debt_engagements = debt_engagements.filter(id__in=[watson.id for watson in watson_results])

                debt_engagements = debt_engagements.prefetch_related('debt_context', 'debt_context__tags', 'tags')
                debt_engagements = debt_engagements[:max_results]
            else:
                debt_engagements = None

            if search_debt_contexts:
                logger.debug('searching debt_contexts')

                debt_contexts = authorized_debt_contexts
                debt_contexts = apply_tag_filters(debt_contexts, operators)

                if keywords_query:
                    watson_results = watson.filter(debt_contexts, keywords_query)
                    debt_contexts = debt_contexts.filter(id__in=[watson.id for watson in watson_results])

                debt_contexts = debt_contexts.prefetch_related('tags')
                debt_contexts = debt_contexts[:max_results]
            else:
                debt_contexts = None

            if search_endpoints:
                logger.debug('searching endpoint')

                endpoints = authorized_endpoints
                endpoints = apply_tag_filters(endpoints, operators)

                endpoints = endpoints.filter(Q(host__icontains=keywords_query) | Q(path__icontains=keywords_query) | Q(protocol__icontains=keywords_query) | Q(query__icontains=keywords_query) | Q(fragment__icontains=keywords_query))
                endpoints = prefetch_for_endpoints(endpoints)
                endpoints = endpoints[:max_results]
            else:
                endpoints = None

            if search_languages:
                logger.debug('searching languages')

                languages = Languages.objects.filter(language__language__icontains=keywords_query)
                languages = languages.prefetch_related('debt_context', 'debt_context__tags')
                languages = languages[:max_results]
            else:
                languages = None

            if search_technologies:
                logger.debug('searching technologies')

                app_analysis = authorized_app_analysis
                app_analysis = app_analysis.filter(name__icontains=keywords_query)
                app_analysis = app_analysis[:max_results]
            else:
                app_analysis = None

            if search_vulnerability_ids:
                logger.debug('searching vulnerability_ids')

                vulnerability_ids = authorized_vulnerability_ids
                vulnerability_ids = apply_vulnerability_id_filter(vulnerability_ids, operators)
                if keywords_query:
                    watson_results = watson.filter(vulnerability_ids, keywords_query)
                    vulnerability_ids = vulnerability_ids.filter(id__in=[watson.id for watson in watson_results])
                vulnerability_ids = vulnerability_ids.prefetch_related('debt_item__debt_test__debt_engagement__debt_context', 'debt_item__debt_test__debt_engagement__debt_context__tags')
                vulnerability_ids = vulnerability_ids[:max_results]
            else:
                vulnerability_ids = None

            if keywords_query:
                logger.debug('searching generic')
                logger.debug('going generic with: %s', keywords_query)
                generic = watson.search(keywords_query, models=(
                    authorized_debt_items, authorized_debt_tests, authorized_debt_engagements,
                    authorized_debt_contexts, authorized_endpoints,
                    authorized_debt_item_templates, authorized_vulnerability_ids, authorized_app_analysis)) \
                    .prefetch_related('object')[:max_results]
            else:
                generic = None

            # paging doesn't work well with django_watson
            # paged_generic = get_page_items(request, generic, 25)

            # generic = get_page_items(request, generic, 25)
            # generic = watson.search(original_clean_query)[:50].prefetch_related('object')
            # generic = watson.search("qander document 'CVE-2019-8331'")[:10].prefetch_related('object')
            # generic = watson.search("'CVE-2020-6754'")[:10].prefetch_related('object')
            # generic = watson.search(" 'ISEC-433'")[:10].prefetch_related('object')

            logger.debug('all searched')

        else:
            logger.debug(form.errors)
            form = SimpleSearchForm()

        add_breadcrumb(title=_("Simple Search"), top_level=True, request=request)

        activetab = 'debt_items' if debt_items \
            else 'debt_contexts' if debt_contexts \
                else 'debt_engagements' if debt_engagements else \
                    'debt_tests' if debt_tests else \
                         'endpoint' if endpoints else \
                            'tagged' if tagged_results else \
                                'vulnerability_ids' if vulnerability_ids else \
                                    'generic'

    response = render(request, 'dojo/debt_simple_search.html', {
        'clean_query': original_clean_query,
        'languages': languages,
        'app_analysis': app_analysis,
        'debt_tests': debt_tests,
        'debt_items': debt_items,
        'debt_item_templates': debt_item_templates,
        'filtered': debt_items_filter,
        'title_words': title_words,
        'component_words': component_words,
        'debt_contexts': debt_contexts,
        'tagged_debt_tests': tagged_debt_tests,
        'tagged_debt_items': tagged_debt_items,
        'tagged_debt_item_templates': tagged_debt_item_templates,
        'tagged_debt_contexts': tagged_debt_contexts,
        'tagged_endpoints': tagged_endpoints,
        'tagged_debt_engagements': tagged_debt_engagements,
        'debt_engagements': debt_engagements,
        'endpoints': endpoints,
        'vulnerability_ids': vulnerability_ids,
        'name': _('Simple Search'),
        'metric': False,
        'user': request.user,
        'form': form,
        'activetab': activetab,
        'show_debt_context_column': True,
        'generic': generic})

    if cookie:
        response.set_cookie("highlight", value=keywords_query,
                            max_age=None, expires=None,
                            path='/', secure=True, httponly=False)
    else:
        response.delete_cookie("highlight", path='/')
    return response

    '''
    query:     some keywords
    operators: {}
    keywords:  ['some', 'keywords']

    query:     some key-word
    operators: {}
    keywords:  ['some', 'key-word']

    query:     keyword with "space inside"
    operators: {}
    keywords:  ['keyword', 'with', 'space inside']

    query:     tag:anchore word tags:php
    operators: {'tag': ['anchore'], 'tags': ['php']}
    keywords:  ['word']

    query:     tags:php,magento
    operators: {'tags': ['php,magento']}
    keywords:  []

    query:     tags:php tags:magento
    operators: {'tags': ['php', 'magento']}
    keywords:  []

    query:     tags:"php, magento"
    operators: {'tags': ['php, magento']}
    keywords:  []

    query:     tags:anchorse some "space inside"
    operators: {'tags': ['anchorse']}
    keywords:  ['some', 'space inside']

    query:     tags:anchore vulnerability_id:CVE-2020-1234 jquery
    operators: {'tags': ['anchore'], 'vulnerability_id': ['CVE-2020-1234']}
    keywords:  ['jquery']
    '''


# it's not google grade parsing, but let's do some basic stuff right
def parse_search_query(clean_query):
    operators = {}  # operator:parameter formatted in searchquery, i.e. tag:php
    keywords = []  # just keywords to search on

    query_parts = shlex.split(clean_query)

    for query_part in query_parts:
        if ':' in query_part:
            query_part_split = query_part.split(':')

            operator = query_part_split[0]
            parameter = query_part_split[1].strip()

            if operator not in operators:
                operators[operator] = []

            operators[operator].append(parameter)
        else:
            keywords.append(vulnerability_id_fix(query_part))

    logger.debug('query:     %s' % clean_query)
    logger.debug('operators: %s' % operators)
    logger.debug('keywords:  %s' % keywords)

    return operators, keywords


def vulnerability_id_fix(keyword):
    # if the query contains hyphens, django-watson will escape these leading to problems.
    # for vulnerability_ids we make this workaround because we really want to be able to search for them
    # problem still remains for other case, i.e. searching for "valentijn-scholten" will return no results because of the hyphen.
    # see:
    # - https://github.com/etianen/django-watson/issues/223
    # - https://github.com/DefectDojo/django-DefectDojo/issues/1092
    # - https://github.com/DefectDojo/django-DefectDojo/issues/2081

    vulnerability_ids = []
    keyword_parts = keyword.split(',')
    for keyword_part in keyword_parts:
        if bool(vulnerability_id_pattern.match(keyword_part)):
            vulnerability_ids.append('\'' + keyword_part + '\'')

    if vulnerability_ids:
        return ' '.join(vulnerability_ids)
    else:
        return keyword


def apply_tag_filters(qs, operators, skip_relations=False):
    tag_filters = {'tag': ''}

    if qs.model == Debt_Item:
        tag_filters = {
            'tag': '',
            'debt_test-tag': 'debt_test__',
            'debt_engagement-tag': 'debt_test__debt_engagement__',
            'debt_context-tag': 'debt_test__debt_engagement__debt_context__',
        }

    if qs.model == Debt_Test:
        tag_filters = {
            'tag': '',
            'debt_test-tag': '',
            'debt_engagement-tag': 'debt_engagement__',
            'debt_context-tag': 'debt_engagement__debt_context__',
        }

    if qs.model == Debt_Engagement:
        tag_filters = {
            'tag': '',
            'debt_test-tag': 'debt_test__',
            'debt_engagement-tag': '',
            'debt_context-tag': 'debt_context__',
        }

    if qs.model == Debt_Context:
        tag_filters = {
            'tag': '',
            'debt_test-tag': 'debt_engagement__debt_test__',
            'debt_engagement-tag': 'debt_engagement__',
            'debt_context-tag': '',
        }

    for tag_filter in tag_filters:
        if tag_filter in operators:
            value = operators[tag_filter]
            value = ','.join(value)  # contains needs a single value
            qs = qs.filter(**{'%stags__name__contains' % tag_filters[tag_filter]: value})

    for tag_filter in tag_filters:
        if tag_filter + 's' in operators:
            value = operators[tag_filter + 's']
            qs = qs.filter(**{'%stags__name__in' % tag_filters[tag_filter]: value})

    # negative search based on not- prefix (not-tags, not-debt_test-tags, not-debt_engagement-tags, not-debt_context-tags, etc)

    for tag_filter in tag_filters:
        tag_filter = 'not-' + tag_filter
        if tag_filter in operators:
            value = operators[tag_filter]
            value = ','.join(value)  # contains needs a single value
            qs = qs.exclude(**{'%stags__name__contains' % tag_filters[tag_filter.replace('not-', '')]: value})

    for tag_filter in tag_filters:
        tag_filter = 'not-' + tag_filter
        if tag_filter + 's' in operators:
            value = operators[tag_filter + 's']
            qs = qs.exclude(**{'%stags__name__in' % tag_filters[tag_filter.replace('not-', '')]: value})

    return qs


def apply_endpoint_filter(qs, operators):
    if 'endpoint' in operators:
        qs = qs.filter(endpoints__host__contains=','.join(operators['endpoint']))

    return qs


def apply_vulnerability_id_filter(qs, operators):
    if 'vulnerability_id' in operators:
        value = operators['vulnerability_id']

        # possible value:
        # ['CVE-2020-6754]
        # ['CVE-2020-6754,CVE-2018-7489']
        # or when entered multiple times:
        # ['CVE-2020-6754,CVE-2018-7489', 'CVE-2020-1234']

        # so flatten like mad:
        vulnerability_ids = list(itertools.chain.from_iterable([vulnerability_id.split(',') for vulnerability_id in value]))
        logger.debug('vulnerability_id filter: %s', vulnerability_ids)
        qs = qs.filter(Q(vulnerability_id__in=vulnerability_ids))

    return qs


def perform_keyword_search_for_operator(qs, operators, operator, keywords_query):
    watson_results = None
    operator_query = ''
    keywords_query = '' if not keywords_query else keywords_query

    if operator in operators:
        operator_query = ' '.join(operators[operator])

    keywords_query = operator_query + keywords_query
    keywords_query = keywords_query.strip()

    if keywords_query:
        logger.debug('going watson with: %s', keywords_query)
        # watson is too slow to get all results or even to count them
        # counting also results in invalid queries with group by errors
        watson_results = watson.filter(qs, keywords_query)[:max_results]
        # watson_results = watson.filter(qs, keywords_query)
        qs = qs.filter(id__in=[watson.id for watson in watson_results])

    return qs
