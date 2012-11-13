from django import template
from django.conf import settings

register = template.Library()

@register.inclusion_tag('uploadify_head.html')
def uploadify_head():
    return {
        'STATIC_URL': settings.STATIC_URL,
    }

@register.inclusion_tag('uploadify_widget.html')
def uploadify_widget(options):
    return {
        'STATIC_URL': settings.STATIC_URL,
        'uploadify_options': options,
    }

@register.inclusion_tag('uploadify_upload.html')
def uploadify_upload(css_classes=""):
    return {
        'css_classes': css_classes,
    }
