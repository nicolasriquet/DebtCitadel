import contextlib
from celery.utils.log import get_task_logger
from dojo.celery import app
from dojo.models import Debt_Context, Debt_Engagement, Debt_Test, Debt_Item, Debt_Endpoint
from dojo.decorators import dojo_async_task


logger = get_task_logger(__name__)


@dojo_async_task
@app.task
def propagate_tags_on_debt_context(debt_context_id, *args, **kwargs):
    with contextlib.suppress(Debt_Context.DoesNotExist):
        debt_context = Debt_Context.objects.get(id=debt_context_id)
        propagate_tags_on_debt_context_sync(debt_context)


def propagate_tags_on_debt_context_sync(debt_context):
    # enagagements
    logger.debug(f"Propagating tags from {debt_context} to all engagements")
    propagate_tags_on_object_list(Debt_Engagement.objects.filter(debt_context=debt_context))
    # tests
    logger.debug(f"Propagating tags from {debt_context} to all tests")
    propagate_tags_on_object_list(Debt_Test.objects.filter(engagement__debt_context=debt_context))
    # findings
    logger.debug(f"Propagating tags from {debt_context} to all findings")
    propagate_tags_on_object_list(Debt_Item.objects.filter(test__engagement__debt_context=debt_context))
    # endpoints
    logger.debug(f"Propagating tags from {debt_context} to all endpoints")
    propagate_tags_on_object_list(Debt_Endpoint.objects.filter(debt_context=debt_context))


def propagate_tags_on_object_list(object_list):
    for obj in object_list:
        if obj and obj.id is not None:
            logger.debug(f"\tPropagating tags to {str(type(obj))} - {str(obj)}")
            obj.save()
