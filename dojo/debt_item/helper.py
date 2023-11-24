from django.db.models.query_utils import Q
from django.db.models.signals import post_delete, pre_delete
from django.dispatch.dispatcher import receiver
from dojo.celery import app
from dojo.decorators import dojo_async_task, dojo_model_from_id, dojo_model_to_id
import dojo.jira_link.helper as jira_helper
import logging
from time import strftime
from django.utils import timezone
from django.conf import settings
from fieldsignals import pre_save_changed
from dojo.utils import get_current_user, mass_model_updater, to_str_typed
from dojo.models import Debt_Engagement, Debt_Item, Debt_Item_Group, System_Settings, Debt_Test, Debt_Endpoint, Debt_Endpoint_Status, \
    Debt_Vulnerability_Id, Vulnerability_Id_Template
from dojo.endpoint.utils import save_debt_endpoints_to_add


logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")

OPEN_DEBT_ITEMS_QUERY = Q(active=True)
VERIFIED_DEBT_ITEMS_QUERY = Q(active=True, verified=True)
OUT_OF_SCOPE_DEBT_ITEMS_QUERY = Q(active=False, out_of_scope=True)
FALSE_POSITIVE_DEBT_ITEMS_QUERY = Q(active=False, duplicate=False, false_p=True)
INACTIVE_DEBT_ITEMS_QUERY = Q(active=False, duplicate=False, is_mitigated=False, false_p=False, out_of_scope=False)
ACCEPTED_DEBT_ITEMS_QUERY = Q(risk_accepted=True)
NOT_ACCEPTED_DEBT_ITEMS_QUERY = Q(risk_accepted=False)
WAS_ACCEPTED_DEBT_ITEMS_QUERY = Q(risk_acceptance__isnull=False) & Q(risk_acceptance__expiration_date_handled__isnull=False)
CLOSED_DEBT_ITEMS_QUERY = Q(is_mitigated=True)
UNDER_REVIEW_QUERY = Q(under_review=True)


# this signal is triggered just before a debt_item is getting saved
# and one of the status related fields has changed
# this allows us to:
# - set any depending fields such as mitigated_by, mitigated, etc.
# - update any audit log / status history
def pre_save_debt_item_status_change(sender, instance, changed_fields=None, **kwargs):
    # some code is cloning debt_items by setting id/pk to None, ignore those, will be handled on next save
    # if not instance.id:
    #     logger.debug('ignoring save of debt_item without id')
    #     return

    logger.debug('%i: changed status fields pre_save: %s', instance.id or 0, changed_fields)

    for field, (old, new) in changed_fields.items():
        logger.debug("%i: %s changed from %s to %s" % (instance.id or 0, field, old, new))
        user = None
        if get_current_user() and get_current_user().is_authenticated:
            user = get_current_user()
        update_debt_item_status(instance, user, changed_fields)


# also get signal when id is set/changed so we can process new debt_items
pre_save_changed.connect(
    pre_save_debt_item_status_change,
    sender=Debt_Item,
    fields=[
        "id",
        "active",
        "verified",
        "false_p",
        "is_mitigated",
        "mitigated",
        "mitigated_by",
        "out_of_scope",
        "risk_accepted",
    ],
)


def update_debt_item_status(new_state_debt_item, user, changed_fields=None):
    now = timezone.now()

    logger.debug('changed fields: %s', changed_fields)

    is_new_debt_item = not changed_fields or (changed_fields and len(changed_fields) == 1 and 'id' in changed_fields)

    # activated
    # reactivated
    # closed / mitigated
    # false positivized
    # out_of_scopified
    # marked as duplicate
    # marked as original

    if is_new_debt_item or 'is_mitigated' in changed_fields:
        # debt_item is being mitigated
        if new_state_debt_item.is_mitigated:
            # when mitigating a debt_item, the meta fields can only be editted if allowed
            logger.debug('debt_item being mitigated, set mitigated and mitigated_by fields')

            if can_edit_mitigated_data(user):
                # only set if it was not already set by user
                # not sure if this check really covers all cases, but if we make it more strict
                # it will cause all kinds of issues I believe with new debt_items etc
                new_state_debt_item.mitigated = new_state_debt_item.mitigated or now
                new_state_debt_item.mitigated_by = new_state_debt_item.mitigated_by or user

        # debt_item is being "un"mitigated
        else:
            new_state_debt_item.mitigated = None
            new_state_debt_item.mitigated_by = None

    # people may try to remove mitigated/mitigated_by by accident
    if new_state_debt_item.is_mitigated:
        new_state_debt_item.mitigated = new_state_debt_item.mitigated or now
        new_state_debt_item.mitigated_by = new_state_debt_item.mitigated_by or user

    if is_new_debt_item or 'active' in changed_fields:
        # debt_item is being (re)activated
        if new_state_debt_item.active:
            new_state_debt_item.false_p = False
            new_state_debt_item.out_of_scope = False
            new_state_debt_item.is_mitigated = False
            new_state_debt_item.mitigated = None
            new_state_debt_item.mitigated_by = None
        else:
            # debt_item is being deactivated
            pass

    if is_new_debt_item or 'verified' in changed_fields:
        pass

    if is_new_debt_item or 'false_p' in changed_fields or 'out_of_scope' in changed_fields:
        # existing behaviour is that false_p or out_of_scope implies mitigated
        if new_state_debt_item.false_p or new_state_debt_item.out_of_scope:
            new_state_debt_item.mitigated = new_state_debt_item.mitigated or now
            new_state_debt_item.mitigated_by = new_state_debt_item.mitigated_by or user
            new_state_debt_item.is_mitigated = True
            new_state_debt_item.active = False
            new_state_debt_item.verified = False

    # always reset some fields if the debt_item is not a duplicate
    if not new_state_debt_item.duplicate:
        new_state_debt_item.duplicate = False
        new_state_debt_item.duplicate_debt_item = None

    new_state_debt_item.last_status_update = now


def can_edit_mitigated_data(user):
    return settings.EDITABLE_MITIGATED_DATA and user.is_superuser


def create_debt_item_group(finds, debt_item_group_name):
    logger.debug('creating debt_item_group_create')
    if not finds or len(finds) == 0:
        raise ValueError('cannot create empty Debt_Item Group')

    debt_item_group_name_dummy = 'bulk group ' + strftime("%a, %d %b  %Y %X", timezone.now().timetuple())

    debt_item_group = Debt_Item_Group(debt_test=finds[0].debt_test)
    debt_item_group.creator = get_current_user()
    debt_item_group.name = debt_item_group_name + debt_item_group_name_dummy
    debt_item_group.save()
    available_debt_items = [find for find in finds if not find.debt_item_group_set.all()]
    debt_item_group.debt_items.set(available_debt_items)

    # if user provided a name, we use that, else:
    # if we have components, we may set a nice name but catch 'name already exist' exceptions
    try:
        if debt_item_group_name:
            debt_item_group.name = debt_item_group_name
        elif debt_item_group.components:
            debt_item_group.name = debt_item_group.components
        debt_item_group.save()
    except:
        pass

    added = len(available_debt_items)
    skipped = len(finds) - added
    return debt_item_group, added, skipped


def add_to_debt_item_group(debt_item_group, finds):
    added = 0
    skipped = 0
    available_debt_items = [find for find in finds if not find.debt_item_group_set.all()]
    debt_item_group.debt_items.add(*available_debt_items)

    # Now update the JIRA to add the debt_item to the debt_item group
    if debt_item_group.has_jira_issue and jira_helper.get_jira_instance(debt_item_group).debt_item_jira_sync:
        logger.debug('pushing to jira from debt_item.debt_item_bulk_update_all()')
        jira_helper.push_to_jira(debt_item_group)

    added = len(available_debt_items)
    skipped = len(finds) - added
    return debt_item_group, added, skipped


def add_to_debt_item_group(debt_item_group, finds):
    added = 0
    skipped = 0
    available_debt_items = [find for find in finds if not find.debt_item_group_set.all()]
    debt_item_group.debt_items.add(*available_debt_items)

    # Now update the JIRA to add the debt_item to the debt_item group
    if debt_item_group.has_jira_issue and jira_helper.get_jira_instance(debt_item_group).debt_item_jira_sync:
        logger.debug('pushing to jira from debt_item.debt_item_bulk_update_all()')
        jira_helper.push_to_jira(debt_item_group)

    added = len(available_debt_items)
    skipped = len(finds) - added
    return debt_item_group, added, skipped

def remove_from_debt_item_group(finds):
    removed = 0
    skipped = 0
    affected_groups = set()
    for find in finds:
        groups = find.debt_item_group_set.all()
        if not groups:
            skipped += 1
            continue

        for group in find.debt_item_group_set.all():
            group.debt_items.remove(find)
            affected_groups.add(group)

        removed += 1

    # Now update the JIRA to remove the debt_item from the debt_item group
    for group in affected_groups:
        if group.has_jira_issue and jira_helper.get_jira_instance(group).debt_item_jira_sync:
            logger.debug('pushing to jira from debt_item.debt_item_bulk_update_all()')
            jira_helper.push_to_jira(group)

    return affected_groups, removed, skipped


def remove_from_debt_item_group(finds):
    removed = 0
    skipped = 0
    affected_groups = set()
    for find in finds:
        groups = find.debt_item_group_set.all()
        if not groups:
            skipped += 1
            continue

        for group in find.debt_item_group_set.all():
            group.debt_items.remove(find)
            affected_groups.add(group)

        removed += 1

    # Now update the JIRA to remove the debt_item from the debt_item group
    for group in affected_groups:
        if group.has_jira_issue and jira_helper.get_jira_instance(group).debt_item_jira_sync:
            logger.debug('pushing to jira from debt_item.debt_item_bulk_update_all()')
            jira_helper.push_to_jira(group)

    return affected_groups, removed, skipped

def update_debt_item_group(debt_item, debt_item_group):
    # debt_item_group = Debt_Item_Group.objects.get(id=group)
    if debt_item_group is not None:
        if debt_item_group != debt_item.debt_item_group:
            if debt_item.debt_item_group:
                logger.debug('removing debt_item %d from debt_item_group %s', debt_item.id, debt_item.debt_item_group)
                debt_item.debt_item_group.debt_items.remove(debt_item)
            logger.debug('adding debt_item %d to debt_item_group %s', debt_item.id, debt_item_group)
            debt_item_group.debt_items.add(debt_item)
    else:
        if debt_item.debt_item_group:
            logger.debug('removing debt_item %d from debt_item_group %s', debt_item.id, debt_item.debt_item_group)
            debt_item.debt_item_group.debt_items.remove(debt_item)


def update_debt_item_group(debt_item, debt_item_group):
    # debt_item_group = Debt_Item_Group.objects.get(id=group)
    if debt_item_group is not None:
        if debt_item_group != debt_item.debt_item_group:
            if debt_item.debt_item_group:
                logger.debug('removing debt_item %d from debt_item_group %s', debt_item.id, debt_item.debt_item_group)
                debt_item.debt_item_group.debt_items.remove(debt_item)
            logger.debug('adding debt_item %d to debt_item_group %s', debt_item.id, debt_item_group)
            debt_item_group.debt_items.add(debt_item)
    else:
        if debt_item.debt_item_group:
            logger.debug('removing debt_item %d from debt_item_group %s', debt_item.id, debt_item.debt_item_group)
            debt_item.debt_item_group.debt_items.remove(debt_item)


def get_group_by_group_name(debt_item, debt_item_group_by_option):
    group_name = None

    if debt_item_group_by_option == 'component_name':
        group_name = debt_item.component_name
    elif debt_item_group_by_option == 'component_name+component_version':
        if debt_item.component_name or debt_item.component_version:
            group_name = '%s:%s' % ((debt_item.component_name if debt_item.component_name else 'None'),
                (debt_item.component_version if debt_item.component_version else 'None'))
    elif debt_item_group_by_option == 'file_path':
        if debt_item.file_path:
            group_name = 'Filepath %s' % (debt_item.file_path)
    elif debt_item_group_by_option == 'debt_item_title':
        group_name = debt_item.title
    else:
        raise ValueError("Invalid group_by option %s" % debt_item_group_by_option)

    if group_name:
        return 'Debt_Items in: %s' % group_name

    return group_name


def group_debt_items_by(finds, debt_item_group_by_option):
    grouped = 0
    groups_created = 0
    groups_existing = 0
    skipped = 0
    affected_groups = set()
    for find in finds:
        if find.debt_item_group is not None:
            skipped += 1
            continue

        group_name = get_group_by_group_name(find, debt_item_group_by_option)
        if group_name is None:
            skipped += 1
            continue

        debt_item_group = Debt_Item_Group.objects.filter(debt_test=find.debt_test, name=group_name).first()
        if not debt_item_group:
            debt_item_group, added, skipped = create_debt_item_group([find], group_name)
            groups_created += 1
            grouped += added
            skipped += skipped
        else:
            add_to_debt_item_group(debt_item_group, [find])
            groups_existing += 1
            grouped += 1

        affected_groups.add(debt_item_group)

    # Now update the JIRA to add the debt_item to the debt_item group
    for group in affected_groups:
        if group.has_jira_issue and jira_helper.get_jira_instance(group).debt_item_jira_sync:
            logger.debug('pushing to jira from debt_item.debt_item_bulk_update_all()')
            jira_helper.push_to_jira(group)

    return affected_groups, grouped, skipped, groups_created


def add_debt_items_to_auto_group(name, debt_items, group_by, create_debt_item_groups_for_all_debt_items=True, **kwargs):
    if name is not None and debt_items is not None and len(debt_items) > 0:
        creator = get_current_user()
        if not creator:
            creator = kwargs.get('async_user', None)
        debt_test = debt_items[0].debt_test

        if create_debt_item_groups_for_all_debt_items or len(debt_items) > 1:
            # Only create a debt_item group if we have more than one debt_item for a given debt_item group, unless configured otherwise
            debt_item_group, created = Debt_Item_Group.objects.get_or_create(debt_test=debt_test, creator=creator, name=name)
            if created:
                logger.debug('Created Debt_Item Group %d:%s for debt_test %d:%s', debt_item_group.id, debt_item_group, debt_test.id, debt_test)
                # See if we have old debt_items in the same debt_test that were created without a debt_item group
                # that should be added to this new group
                old_debt_items = Debt_Item.objects.filter(debt_test=debt_test)
                for f in old_debt_items:
                    f_group_name = get_group_by_group_name(f, group_by)
                    if f_group_name == name and f not in debt_items:
                        debt_item_group.debt_items.add(f)

            debt_item_group.debt_items.add(*debt_items)
        else:
            # Otherwise add to an existing debt_item group if it exists only
            try:
                debt_item_group = Debt_Item_Group.objects.get(debt_test=debt_test, name=name)
                if debt_item_group:
                    debt_item_group.debt_items.add(*debt_items)
            except:
                # See if we have old debt_items in the same debt_test that were created without a debt_item group
                # that match this new debt_item - then we can create a debt_item group
                old_debt_items = Debt_Item.objects.filter(debt_test=debt_test)
                created = False
                for f in old_debt_items:
                    f_group_name = get_group_by_group_name(f, group_by)
                    if f_group_name == name and f not in debt_items:
                        debt_item_group, created = Debt_Item_Group.objects.get_or_create(debt_test=debt_test, creator=creator, name=name)
                        debt_item_group.debt_items.add(f)
                if created:
                    debt_item_group.debt_items.add(*debt_items)


@dojo_model_to_id
@dojo_async_task
@app.task
@dojo_model_from_id
def post_process_debt_item_save(debt_item, dedupe_option=True, rules_option=True, debt_context_grading_option=True,
                                issue_updater_option=True, push_to_jira=False, user=None, *args, **kwargs):

    system_settings = System_Settings.objects.get()

    # STEP 1 run all status changing tasks sequentially to avoid race conditions
    if dedupe_option:
        if debt_item.hash_code is not None:
            if system_settings.enable_deduplication:
                from dojo.utils import do_dedupe_debt_item
                do_dedupe_debt_item(debt_item, *args, **kwargs)
            else:
                deduplicationLogger.debug("skipping dedupe because it's disabled in system settings")
        else:
            deduplicationLogger.warning("skipping dedupe because hash_code is None")

    if system_settings.false_positive_history:
        # Only perform false positive history if deduplication is disabled
        if system_settings.enable_deduplication:
            deduplicationLogger.warning("skipping false positive history because deduplication is also enabled")
        else:
            from dojo.utils import do_false_positive_history
            do_false_positive_history(debt_item, *args, **kwargs)

    # STEP 2 run all non-status changing tasks as celery tasks in the background
    if issue_updater_option:
        from dojo.tools import tool_issue_updater
        tool_issue_updater.async_tool_issue_update(debt_item)

    if debt_context_grading_option:
        if system_settings.enable_debt_context_grade:
            from dojo.utils import calculate_grade
            calculate_grade(debt_item.debt_test.debt_engagement.debt_context)
        else:
            deduplicationLogger.debug("skipping debt_context grading because it's disabled in system settings")

    # Adding a snippet here for push to JIRA so that it's in one place
    if push_to_jira:
        logger.debug('pushing debt_item %s to jira from debt_item.save()', debt_item.pk)
        import dojo.jira_link.helper as jira_helper

        # current approach is that whenever a debt_item is in a group, the group will be pushed to JIRA
        # based on feedback we could introduct another push_group_to_jira boolean everywhere
        # but what about the push_all boolean? Let's see how this works for now and get some feedback.
        if debt_item.has_jira_issue or not debt_item.debt_item_group:
            jira_helper.push_to_jira(debt_item)
        elif debt_item.debt_item_group:
            jira_helper.push_to_jira(debt_item.debt_item_group)


@receiver(pre_delete, sender=Debt_Item)
def debt_item_pre_delete(sender, instance, **kwargs):
    logger.debug('debt_item pre_delete: %d', instance.id)
    # this shouldn't be necessary as Django should remove any Many-To-Many entries automatically, might be a bug in Django?
    # https://code.djangoproject.com/ticket/154

    instance.found_by.clear()


def debt_item_delete(instance, **kwargs):
    logger.debug('debt_item delete, instance: %s', instance.id)

    # the idea is that the debt_engagement/debt_test pre delete already prepared all the duplicates inside
    # the debt_test/debt_engagement to no longer point to any original so they can be safely deleted.
    # so if we still find that the debt_item that is going to be delete is an original, it is either
    # a manual / single debt_item delete, or a bulke delete of debt_items
    # in which case we have to process all the duplicates
    # TODO: should we add the prepocessing also to the bulk edit form?
    logger.debug('debt_item_delete: refresh from db: pk: %d', instance.pk)

    try:
        instance.refresh_from_db()
    except Debt_Item.DoesNotExist:
        # due to cascading deletes, the current debt_item could have been deleted already
        # but django still calls delete() in this case
        return

    duplicate_cluster = instance.original_debt_item.all()
    if duplicate_cluster:
        reconfigure_duplicate_cluster(instance, duplicate_cluster)
    else:
        logger.debug('no duplicate cluster found for debt_item: %d, so no need to reconfigure', instance.id)

    # this shouldn't be necessary as Django should remove any Many-To-Many entries automatically, might be a bug in Django?
    # https://code.djangoproject.com/ticket/154
    logger.debug('debt_item delete: clearing found by')
    instance.found_by.clear()


@receiver(post_delete, sender=Debt_Item)
def debt_item_post_delete(sender, instance, **kwargs):
    logger.debug('debt_item post_delete, sender: %s instance: %s', to_str_typed(sender), to_str_typed(instance))
    # calculate_grade(instance.debt_test.debt_engagement.debt_context)


def reset_duplicate_before_delete(dupe):
    dupe.duplicate_debt_item = None
    dupe.duplicate = False


def reset_duplicates_before_delete(qs):
    mass_model_updater(Debt_Item, qs, lambda f: reset_duplicate_before_delete(f), fields=['duplicate', 'duplicate_debt_item'])


def set_new_original(debt_item, new_original):
    if debt_item.duplicate:
        debt_item.duplicate_debt_item = new_original


# can't use model to id here due to the queryset
# @dojo_async_task
# @app.task
def reconfigure_duplicate_cluster(original, cluster_outside):
    # when a debt_item is deleted, and is an original of a duplicate cluster, we have to chose a new original for the cluster
    # only look for a new original if there is one outside this debt_test
    if original is None or cluster_outside is None or len(cluster_outside) == 0:
        return

    if settings.DUPLICATE_CLUSTER_CASCADE_DELETE:
        cluster_outside.order_by('-id').delete()
    else:
        logger.debug('reconfigure_duplicate_cluster: cluster_outside: %s', cluster_outside)
        # set new original to first debt_item in cluster (ordered by id)
        new_original = cluster_outside.order_by('id').first()
        if new_original:
            logger.debug('changing original of duplicate cluster %d to: %s:%s', original.id, new_original.id, new_original.title)

            new_original.duplicate = False
            new_original.duplicate_debt_item = None
            new_original.active = original.active
            new_original.is_mitigated = original.is_mitigated
            new_original.save_no_options()
            new_original.found_by.set(original.found_by.all())

        # if the cluster is size 1, there's only the new original left
        if new_original and len(cluster_outside) > 1:
            # for find in cluster_outside:
            #     if find != new_original:
            #         find.duplicate_debt_item = new_original
            #         find.save_no_options()

            mass_model_updater(Debt_Item, cluster_outside, lambda f: set_new_original(f, new_original), fields=['duplicate_debt_item'])


def prepare_duplicates_for_delete(debt_test=None, debt_engagement=None):
    logger.debug('prepare duplicates for delete, debt_test: %s, debt_engagement: %s', debt_test.id if debt_test else None, debt_engagement.id if debt_engagement else None)
    if debt_test is None and debt_engagement is None:
        logger.warning('nothing to prepare as debt_test and debt_engagement are None')

    fix_loop_duplicates()

    # get all originals in the debt_test/debt_engagement
    originals = Debt_Item.objects.filter(original_debt_item__isnull=False)
    if debt_engagement:
        originals = originals.filter(debt_test__engagement=debt_engagement)
    if debt_test:
        originals = originals.filter(debt_test=debt_test)

    # use distinct to flatten the join result
    originals = originals.distinct()

    if len(originals) == 0:
        logger.debug('no originals found, so no duplicates to prepare for deletion of original')
        return

    # remove the link to the original from the duplicates inside the cluster so they can be safely deleted by the django framework
    total = len(originals)
    i = 0
    # logger.debug('originals: %s', [original.id for original in originals])
    for original in originals:
        i += 1
        logger.debug('%d/%d: preparing duplicate cluster for deletion of original: %d', i, total, original.id)
        cluster_inside = original.original_debt_item.all()
        if debt_engagement:
            cluster_inside = cluster_inside.filter(debt_test__engagement=debt_engagement)

        if debt_test:
            cluster_inside = cluster_inside.filter(debt_test=debt_test)

        if len(cluster_inside) > 0:
            reset_duplicates_before_delete(cluster_inside)

        # reconfigure duplicates outside debt_test/debt_engagement
        cluster_outside = original.original_debt_item.all()
        if debt_engagement:
            cluster_outside = cluster_outside.exclude(debt_test__engagement=debt_engagement)

        if debt_test:
            cluster_outside = cluster_outside.exclude(debt_test=debt_test)

        if len(cluster_outside) > 0:
            reconfigure_duplicate_cluster(original, cluster_outside)

        logger.debug('done preparing duplicate cluster for deletion of original: %d', original.id)


def debt_prepare_duplicates_for_delete(debt_test=None, debt_engagement=None):
    logger.debug('prepare duplicates for delete, debt_test: %s, debt_engagement: %s', debt_test.id if debt_test else None, debt_engagement.id if debt_engagement else None)
    if debt_test is None and debt_engagement is None:
        logger.warning('nothing to prepare as debt_test and debt_engagement are None')

    fix_loop_duplicates()

    # get all originals in the debt_test/debt_engagement
    originals = Debt_Item.objects.filter(original_debt_item__isnull=False)
    if debt_engagement:
        originals = originals.filter(debt_test__debt_engagement=debt_engagement)
    if debt_test:
        originals = originals.filter(debt_test=debt_test)

    # use distinct to flatten the join result
    originals = originals.distinct()

    if len(originals) == 0:
        logger.debug('no originals found, so no duplicates to prepare for deletion of original')
        return

    # remove the link to the original from the duplicates inside the cluster so they can be safely deleted by the django framework
    total = len(originals)
    i = 0
    # logger.debug('originals: %s', [original.id for original in originals])
    for original in originals:
        i += 1
        logger.debug('%d/%d: preparing duplicate cluster for deletion of original: %d', i, total, original.id)
        cluster_inside = original.original_debt_item.all()
        if debt_engagement:
            cluster_inside = cluster_inside.filter(debt_test__debt_engagement=debt_engagement)

        if debt_test:
            cluster_inside = cluster_inside.filter(debt_test=debt_test)

        if len(cluster_inside) > 0:
            reset_duplicates_before_delete(cluster_inside)

        # reconfigure duplicates outside debt_test/debt_engagement
        cluster_outside = original.original_debt_item.all()
        if debt_engagement:
            cluster_outside = cluster_outside.exclude(debt_test__debt_engagement=debt_engagement)

        if debt_test:
            cluster_outside = cluster_outside.exclude(debt_test=debt_test)

        if len(cluster_outside) > 0:
            reconfigure_duplicate_cluster(original, cluster_outside)

        logger.debug('done preparing duplicate cluster for deletion of original: %d', original.id)


@receiver(pre_delete, sender=Debt_Test)
def debt_test_pre_delete(sender, instance, **kwargs):
    logger.debug('debt_test pre_delete, sender: %s instance: %s', to_str_typed(sender), to_str_typed(instance))
    prepare_duplicates_for_delete(debt_test=instance)


@receiver(post_delete, sender=Debt_Test)
def debt_test_post_delete(sender, instance, **kwargs):
    logger.debug('debt_test post_delete, sender: %s instance: %s', to_str_typed(sender), to_str_typed(instance))


@receiver(pre_delete, sender=Debt_Engagement)
def engagement_pre_delete(sender, instance, **kwargs):
    logger.debug('debt_engagement pre_delete, sender: %s instance: %s', to_str_typed(sender), to_str_typed(instance))
    prepare_duplicates_for_delete(debt_engagement=instance)


@receiver(post_delete, sender=Debt_Engagement)
def engagement_post_delete(sender, instance, **kwargs):
    logger.debug('debt_engagement post_delete, sender: %s instance: %s', to_str_typed(sender), to_str_typed(instance))


def fix_loop_duplicates():
    """ Due to bugs in the past and even currently when under high parallel load, there can be transitive duplicates. """
    """ i.e. A -> B -> C. This can lead to problems when deleting debt_itemns, performing deduplication, etc """
    candidates = Debt_Item.objects.filter(duplicate_debt_item__isnull=False, original_debt_item__isnull=False).order_by("-id")

    loop_count = len(candidates)

    if loop_count > 0:
        deduplicationLogger.info("Identified %d Debt_Items with Loops" % len(candidates))
        for find_id in candidates.values_list('id', flat=True):
            removeLoop(find_id, 50)

        new_originals = Debt_Item.objects.filter(duplicate_debt_item__isnull=True, duplicate=True)
        for f in new_originals:
            deduplicationLogger.info("New Original: %d " % f.id)
            f.duplicate = False
            super(Debt_Item, f).save()

        loop_count = Debt_Item.objects.filter(duplicate_debt_item__isnull=False, original_debt_item__isnull=False).count()
        deduplicationLogger.info("%d Debt_Item found which still has Loops, please run fix loop duplicates again" % loop_count)
    return loop_count


def removeLoop(debt_item_id, counter):
    # get ladebt_test status
    debt_item = Debt_Item.objects.get(id=debt_item_id)
    real_original = debt_item.duplicate_debt_item

    if not real_original or real_original is None:
        # loop fully removed
        return

    # duplicate of itself -> clear duplicate status
    if debt_item_id == real_original.id:
        # loop fully removed
        debt_item.duplicate_debt_item = None
        # duplicate remains True, will be set to False in fix_loop_duplicates (and logged as New Original?).
        super(Debt_Item, debt_item).save()
        return

    # Only modify the debt_items if the original ID is lower to get the oldest debt_item as original
    if (real_original.id > debt_item_id) and (real_original.duplicate_debt_item is not None):
        # If not, swap them around
        tmp = debt_item_id
        debt_item_id = real_original.id
        real_original = Debt_Item.objects.get(id=tmp)
        debt_item = Debt_Item.objects.get(id=debt_item_id)

    if real_original in debt_item.original_debt_item.all():
        # remove the original from the duplicate list if it is there
        debt_item.original_debt_item.remove(real_original)
        super(Debt_Item, debt_item).save()
    if counter <= 0:
        # Maximum recursion depth as safety method to circumvent recursion here
        return
    for f in debt_item.original_debt_item.all():
        # for all duplicates set the original as their original, get rid of self in between
        f.duplicate_debt_item = real_original
        super(Debt_Item, f).save()
        super(Debt_Item, real_original).save()
        removeLoop(f.id, counter - 1)


def add_debt_endpoints(new_debt_item, form):
    added_debt_endpoints = save_debt_endpoints_to_add(form.debt_endpoints_to_add_list, new_debt_item.debt_test.debt_engagement.debt_context)
    debt_endpoint_ids = []
    for debt_endpoint in added_debt_endpoints:
        debt_endpoint_ids.append(debt_endpoint.id)

    new_debt_item.debt_endpoints.set(form.cleaned_data['debt_endpoints'] | Debt_Endpoint.objects.filter(id__in=debt_endpoint_ids))

    for debt_endpoint in new_debt_item.debt_endpoints.all():
        eps, created = Debt_Endpoint_Status.objects.get_or_create(
            debt_item=new_debt_item,
            debt_endpoint=debt_endpoint, defaults={'date': form.cleaned_data['date'] or timezone.now()})


def save_vulnerability_ids(debt_item, vulnerability_ids):
    # Remove duplicates
    vulnerability_ids = list(dict.fromkeys(vulnerability_ids))

    # Remove old vulnerability ids
    Debt_Vulnerability_Id.objects.filter(debt_item=debt_item).delete()

    # Save new vulnerability ids
    for vulnerability_id in vulnerability_ids:
        Debt_Vulnerability_Id(debt_item=debt_item, vulnerability_id=vulnerability_id).save()

    # Set CVE
    if vulnerability_ids:
        debt_item.cve = vulnerability_ids[0]
    else:
        debt_item.cve = None


def save_vulnerability_ids_template(debt_item_template, vulnerability_ids):
    # Remove duplicates
    vulnerability_ids = list(dict.fromkeys(vulnerability_ids))

    # Remove old vulnerability ids
    Vulnerability_Id_Template.objects.filter(debt_item_template=debt_item_template).delete()

    # Save new vulnerability ids
    for vulnerability_id in vulnerability_ids:
        Vulnerability_Id_Template(debt_item_template=debt_item_template, vulnerability_id=vulnerability_id).save()

    # Set CVE
    if vulnerability_ids:
        debt_item_template.cve = vulnerability_ids[0]
    else:
        debt_item_template.cve = None
