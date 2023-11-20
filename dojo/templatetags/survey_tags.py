'''
Created on Feb 18, 2015

@author: jay7958
'''
from django import template
from dojo.models import Answered_Survey, Debt_Answered_Survey, Engagement_Survey, Debt_Engagement_Survey

register = template.Library()


@register.inclusion_tag('defectDojo-engagement-survey/surveys.html')
def show_surveys(engagement, users):
    surveys = Answered_Survey.objects.filter(engagement=engagement)
    return {'surveys': surveys}


@register.inclusion_tag('defectDojo-engagement-survey/surveys.html')
def debt_show_surveys(debt_engagement, users):
    surveys = Debt_Answered_Survey.objects.filter(debt_engagement=debt_engagement)
    return {'surveys': surveys}


@register.inclusion_tag('defectDojo-engagement-survey/add_surveys.html')
def add_surveys(engagement):
    ids = [survey.survey.id for survey in
            Answered_Survey.objects.filter(engagement=engagement)]
    surveys = Engagement_Survey.objects.exclude(
        id__in=ids)
    return {'surveys': surveys,
            'eng': engagement}


@register.inclusion_tag('defectDojo-engagement-survey/add_surveys.html')
def debt_add_surveys(debt_engagement):
    ids = [survey.survey.id for survey in
           Debt_Answered_Survey.objects.filter(debt_engagement=debt_engagement)]
    surveys = Debt_Engagement_Survey.objects.exclude(
        id__in=ids)
    return {'surveys': surveys,
            'debt_engagement': debt_engagement}
