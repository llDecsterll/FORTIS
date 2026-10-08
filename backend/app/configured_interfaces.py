"""The interfaces actually configured on this server, including custom roles."""
from .config import settings
from .models import Contour


def contour_enabled(contour):
    return settings.employees_enabled if contour == Contour.EMPLOYEES else settings.sites_enabled


def profiles():
    result = []
    for key, role, title in (('employees', 'employees', 'Сотрудники'), ('sites', 'routers', 'Роутеры')):
        if getattr(settings, key + '_enabled'):
            result.append({'role': role, 'title': title, 'name': getattr(settings, key + '_if'),
                           'subnet': getattr(settings, key + '_net'), 'port': getattr(settings, key + '_port'),
                           'uplink': getattr(settings, key + '_nic'), 'endpoint': getattr(settings, key + '_endpoint')})
    return result + list(settings.additional_interfaces)
