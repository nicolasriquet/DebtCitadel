from django.core.exceptions import PermissionDenied
from django.utils import timezone
from dojo.utils import get_system_setting, get_full_url
from dateutil.relativedelta import relativedelta
import dojo.jira_link.helper as jira_helper
from dojo.jira_link.helper import escape_for_jira
from dojo.notifications.helper import create_notification
from django.urls import reverse
from dojo.celery import app
from dojo.models import System_Settings, Risk_Acceptance
import logging

logger = logging.getLogger(__name__)


def expire_now(risk_acceptance):
    logger.info('Expiring risk acceptance %i:%s with %i debt_items', risk_acceptance.id, risk_acceptance, len(risk_acceptance.accepted_debt_items.all()))

    reactivated_debt_items = []
    if risk_acceptance.reactivate_expired:
        for debt_item in risk_acceptance.accepted_debt_items.all():
            if not debt_item.active:
                logger.debug('%i:%s: unaccepting a.k.a reactivating debt_item.', debt_item.id, debt_item)
                debt_item.active = True
                debt_item.risk_accepted = False

                if risk_acceptance.restart_sla_expired:
                    debt_item.sla_start_date = timezone.now().date()

                debt_item.save(dedupe_option=False)
                reactivated_debt_items.append(debt_item)
                # debt_items remain in this risk acceptance for reporting / metrics purposes
            else:
                logger.debug('%i:%s already active, no changes made.', debt_item.id, debt_item)

        # best effort JIRA integration, no status changes
        post_jira_comments(risk_acceptance, risk_acceptance.accepted_debt_items.all(), expiration_message_creator)

    risk_acceptance.expiration_date = timezone.now()
    risk_acceptance.expiration_date_handled = timezone.now()
    risk_acceptance.save()

    accepted_debt_items = risk_acceptance.accepted_debt_items.all()
    title = 'Risk acceptance with ' + str(len(accepted_debt_items)) + " accepted debt_items has expired for " + \
            str(risk_acceptance.debt_engagement.debt_context) + ': ' + str(risk_acceptance.debt_engagement.name)

    create_notification(event='risk_acceptance_expiration', title=title, risk_acceptance=risk_acceptance, accepted_debt_items=accepted_debt_items,
                         reactivated_debt_items=reactivated_debt_items, debt_engagement=risk_acceptance.debt_engagement,
                         debt_context=risk_acceptance.debt_engagement.debt_context,
                         url=reverse('view_risk_acceptance', args=(risk_acceptance.debt_engagement.id, risk_acceptance.id, )))


def reinstate(risk_acceptance, old_expiration_date):
    if risk_acceptance.expiration_date_handled:
        logger.info('Reinstating risk acceptance %i:%s with %i debt_items', risk_acceptance.id, risk_acceptance, len(risk_acceptance.accepted_debt_items.all()))

        expiration_delta_days = get_system_setting('risk_acceptance_form_default_days', 90)
        risk_acceptance.expiration_date = timezone.now() + relativedelta(days=expiration_delta_days)

        reinstated_debt_items = []
        for debt_item in risk_acceptance.accepted_debt_items.all():
            if debt_item.active:
                logger.debug('%i:%s: accepting a.k.a. deactivating debt_item', debt_item.id, debt_item)
                debt_item.active = False
                debt_item.risk_accepted = True
                debt_item.save(dedupe_option=False)
                reinstated_debt_items.append(debt_item)
            else:
                logger.debug('%i:%s: already inactive, not making any changes', debt_item.id, debt_item)

        # best effort JIRA integration, no status changes
        post_jira_comments(risk_acceptance, risk_acceptance.accepted_debt_items.all(), reinstation_message_creator)

    risk_acceptance.expiration_date_handled = None
    risk_acceptance.expiration_date_warned = None
    risk_acceptance.save()


def delete(eng, risk_acceptance):
    debt_items = risk_acceptance.accepted_debt_items.all()
    for debt_item in debt_items:
        debt_item.active = True
        debt_item.risk_accepted = False
        debt_item.save(dedupe_option=False)

    # best effort jira integration, no status changes
    post_jira_comments(risk_acceptance, debt_items, unaccepted_message_creator)

    risk_acceptance.accepted_debt_items.clear()
    eng.risk_acceptance.remove(risk_acceptance)
    eng.save()

    for note in risk_acceptance.notes.all():
        note.delete()

    risk_acceptance.path.delete()
    risk_acceptance.delete()


def remove_debt_item_from_risk_acceptance(risk_acceptance, debt_item):
    logger.debug('removing debt_item %i from risk acceptance %i', debt_item.id, risk_acceptance.id)
    risk_acceptance.accepted_debt_items.remove(debt_item)
    debt_item.active = True
    debt_item.risk_accepted = False
    debt_item.save(dedupe_option=False)
    # best effort jira integration, no status changes
    post_jira_comments(risk_acceptance, [debt_item], unaccepted_message_creator)


def add_debt_items_to_risk_acceptance(risk_acceptance, debt_items):
    for debt_item in debt_items:
        if not debt_item.duplicate or debt_item.risk_accepted:
            debt_item.active = False
            debt_item.risk_accepted = True
            debt_item.save(dedupe_option=False)
            risk_acceptance.accepted_debt_items.add(debt_item)
    risk_acceptance.save()

    # best effort jira integration, no status changes
    post_jira_comments(risk_acceptance, debt_items, accepted_message_creator)


def add_debt_items_to_risk_acceptance(risk_acceptance, debt_items):
    for debt_item in debt_items:
        if not debt_item.duplicate or debt_item.risk_accepted:
            debt_item.active = False
            debt_item.risk_accepted = True
            debt_item.save(dedupe_option=False)
            risk_acceptance.accepted_debt_items.add(debt_item)
    risk_acceptance.save()

    # best effort jira integration, no status changes
    post_jira_comments(risk_acceptance, debt_items, accepted_message_creator)


@app.task
def expiration_handler(*args, **kwargs):
    """
    Creates a notification upon risk expiration and X days beforehand if configured.
    This notification is 1 per risk acceptance.

    If configured also sends a JIRA comment in both case to each jira issue.
    This is per debt_item.
    """

    try:
        system_settings = System_Settings.objects.get()
    except System_Settings.DoesNotExist:
        logger.warning("Unable to get system_settings, skipping risk acceptance expiration job")

    risk_acceptances = get_expired_risk_acceptances_to_handle()

    logger.info('expiring %i risk acceptances that are past expiration date', len(risk_acceptances))
    for risk_acceptance in risk_acceptances:
        expire_now(risk_acceptance)
        # notification created by expire_now code

    heads_up_days = system_settings.risk_acceptance_notify_before_expiration
    if heads_up_days > 0:
        risk_acceptances = get_almost_expired_risk_acceptances_to_handle(heads_up_days)

        logger.info('notifying for %i risk acceptances that are expiring within %i days', len(risk_acceptances), heads_up_days)
        for risk_acceptance in risk_acceptances:
            logger.debug('notifying for risk acceptance %i:%s with %i debt_items', risk_acceptance.id, risk_acceptance, len(risk_acceptance.accepted_debt_items.all()))

            notification_title = 'Risk acceptance with ' + str(len(risk_acceptance.accepted_debt_items.all())) + " accepted debt_items will expire on " + \
                timezone.localtime(risk_acceptance.expiration_date).strftime("%b %d, %Y") + " for " + \
                str(risk_acceptance.debt_engagement.debt_context) + ': ' + str(risk_acceptance.debt_engagement.name)

            create_notification(event='risk_acceptance_expiration', title=notification_title, risk_acceptance=risk_acceptance,
                                accepted_debt_items=risk_acceptance.accepted_debt_items.all(), debt_engagement=risk_acceptance.debt_engagement,
                                debt_context=risk_acceptance.debt_engagement.debt_context,
                                url=reverse('view_risk_acceptance', args=(risk_acceptance.debt_engagement.id, risk_acceptance.id, )))

            post_jira_comments(risk_acceptance, expiration_warning_message_creator, heads_up_days)

            risk_acceptance.expiration_date_warned = timezone.now()
            risk_acceptance.save()


def expiration_message_creator(risk_acceptance, heads_up_days=0):
    return 'Risk acceptance [(%s)|%s] with %i debt_items has expired' % \
        (escape_for_jira(risk_acceptance.name),
        get_full_url(reverse('view_risk_acceptance', args=(risk_acceptance.debt_engagement.id, risk_acceptance.id))),
        len(risk_acceptance.accepted_debt_items.all()))


def expiration_warning_message_creator(risk_acceptance, heads_up_days=0):
    return 'Risk acceptance [(%s)|%s] with %i debt_items will expire in %i days' % \
        (escape_for_jira(risk_acceptance.name),
        get_full_url(reverse('view_risk_acceptance', args=(risk_acceptance.debt_engagement.id, risk_acceptance.id))),
        len(risk_acceptance.accepted_debt_items.all()), heads_up_days)


def reinstation_message_creator(risk_acceptance, heads_up_days=0):
    return 'Risk acceptance [(%s)|%s] with %i debt_items has been reinstated (expires on %s)' % \
        (escape_for_jira(risk_acceptance.name),
        get_full_url(reverse('view_risk_acceptance', args=(risk_acceptance.debt_engagement.id, risk_acceptance.id))),
        len(risk_acceptance.accepted_debt_items.all()), timezone.localtime(risk_acceptance.expiration_date).strftime("%b %d, %Y"))


def accepted_message_creator(risk_acceptance, heads_up_days=0):
    if risk_acceptance:
        return 'Debt_Item has been added to risk acceptance [(%s)|%s] with %i debt_items (expires on %s)' % \
            (escape_for_jira(risk_acceptance.name),
            get_full_url(reverse('view_risk_acceptance', args=(risk_acceptance.debt_engagement.id, risk_acceptance.id))),
            len(risk_acceptance.accepted_debt_items.all()), timezone.localtime(risk_acceptance.expiration_date).strftime("%b %d, %Y"))
    else:
        return 'Debt_Item has been risk accepted'


def unaccepted_message_creator(risk_acceptance, heads_up_days=0):
    if risk_acceptance:
        return 'debt_item was unaccepted/deleted from risk acceptance [(%s)|%s]' % \
            (escape_for_jira(risk_acceptance.name),
            get_full_url(reverse('view_risk_acceptance', args=(risk_acceptance.debt_engagement.id, risk_acceptance.id))))
    else:
        return 'Debt_Item is no longer risk accepted'


def post_jira_comment(debt_item, message_factory, heads_up_days=0):
    if not debt_item or not debt_item.has_jira_issue:
        return

    jira_project = jira_helper.get_jira_project(debt_item)

    if jira_project and jira_project.risk_acceptance_expiration_notification:
        jira_instance = jira_helper.get_jira_instance(debt_item)

        if jira_instance:

            jira_comment = message_factory(None, heads_up_days)

            logger.debug("Creating JIRA comment for something risk acceptance related")
            jira_helper.add_simple_jira_comment(jira_instance, debt_item.jira_issue, jira_comment)


def post_jira_comments(risk_acceptance, debt_items, message_factory, heads_up_days=0):
    if not risk_acceptance:
        return

    jira_project = jira_helper.get_jira_project(risk_acceptance.debt_engagement)

    if jira_project and jira_project.risk_acceptance_expiration_notification:
        jira_instance = jira_helper.get_jira_instance(risk_acceptance.debt_engagement)

        if jira_instance:
            jira_comment = message_factory(risk_acceptance, heads_up_days)

            for debt_item in debt_items:
                if debt_item.has_jira_issue:
                    logger.debug("Creating JIRA comment for something risk acceptance related")
                    jira_helper.add_simple_jira_comment(jira_instance, debt_item.jira_issue, jira_comment)


def get_expired_risk_acceptances_to_handle():
    risk_acceptances = Risk_Acceptance.objects.filter(expiration_date__isnull=False, expiration_date_handled__isnull=True, expiration_date__date__lte=timezone.now().date())
    return prefetch_for_expiration(risk_acceptances)


def get_almost_expired_risk_acceptances_to_handle(heads_up_days):
    risk_acceptances = Risk_Acceptance.objects.filter(expiration_date__isnull=False, expiration_date_handled__isnull=True, expiration_date_warned__isnull=True,
            expiration_date__date__lte=timezone.now().date() + relativedelta(days=heads_up_days), expiration_date__date__gte=timezone.now().date())
    return prefetch_for_expiration(risk_acceptances)


def prefetch_for_expiration(risk_acceptances):
    return risk_acceptances.prefetch_related('accepted_debt_items', 'accepted_debt_items__jira_issue',
                                                'debt_engagement_set',
                                                'debt_engagement__jira_project',
                                                'debt_engagement__jira_project__jira_instance'
                                             )


def simple_risk_accept(debt_item, perform_save=True):
    if not debt_item.debt_test.debt_engagement.debt_context.enable_simple_risk_acceptance:
        raise PermissionDenied()

    logger.debug('accepting debt_item %i:%s', debt_item.id, debt_item)
    debt_item.risk_accepted = True
    # risk accepted, so debt_item no longer considered active
    debt_item.active = False
    if perform_save:
        debt_item.save(dedupe_option=False)
    # post_jira_comment might reload from database so see unaccepted debt_item. but the comment
    # only contains some text so that's ok
    post_jira_comment(debt_item, accepted_message_creator)


def risk_unaccept(debt_item, perform_save=True):
    logger.debug('unaccepting debt_item %i:%s if it is currently risk accepted', debt_item.id, debt_item)
    if debt_item.risk_accepted:
        logger.debug('unaccepting debt_item %i:%s', debt_item.id, debt_item)
        # keep reference to ra to for posting comments later
        risk_acceptance = debt_item.risk_acceptance
        # removing from ManyToMany will not fail for non-existing entries
        remove_from_any_risk_acceptance(debt_item)
        if not debt_item.mitigated and not debt_item.false_p and not debt_item.out_of_scope:
            debt_item.active = True
        debt_item.risk_accepted = False
        if perform_save:
            logger.debug('saving unaccepted debt_item %i:%s', debt_item.id, debt_item)
            debt_item.save(dedupe_option=False)

        # post_jira_comment might reload from database so see unaccepted debt_item. but the comment
        # only contains some text so that's ok
        post_jira_comment(debt_item, unaccepted_message_creator)


def remove_from_any_risk_acceptance(debt_item):
    for r in debt_item.risk_acceptance_set.all():
        r.accepted_debt_items.remove(debt_item)
