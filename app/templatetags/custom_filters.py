# app/templatetags/custom_filters.py

from django import template

register = template.Library()

@register.filter(name='add_class')
def add_class(value, arg):
    return value.as_widget(attrs={'class': arg})

@register.filter
def length_is(value, arg):
    """Returns True if the length of the value equals the argument."""
    return len(value) == int(arg)