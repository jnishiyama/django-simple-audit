# threadlocals middleware
from .models import AuditRequest
from . import settings
from django.utils import importlib

class TrackingRequestOnThreadLocalMiddleware(object):
    """Middleware that gets various objects from the
    request object and saves them in thread local storage."""

    def _get_ip(self, request):
        # get real ip
        if 'HTTP_X_FORWARDED_FOR' in request.META:
            ip = request.META['HTTP_X_FORWARDED_FOR']
        elif 'Client-IP' in request.META:
            ip = request.META['Client-IP']
        else:
            ip = request.META['REMOTE_ADDR']
        ip = ip.split(",")[0]
        return ip

    def _import_from_string(self, val, setting_name):
        """
        Attempt to import a class from a string representation.
        """
        try:
            # Nod to tastypie's use of importlib.
            parts = val.split('.')
            module_path, class_name = '.'.join(parts[:-1]), parts[-1]
            module = importlib.import_module(module_path)
            return getattr(module, class_name)
        except ImportError as e:
            msg = "Could not import '%s' for API setting '%s'. %s: %s." % (val, setting_name, e.__class__.__name__, e)
            raise ImportError(msg)

    def process_request(self, request):
        if not request.user.is_anonymous():
            ip = self._get_ip(request)
            AuditRequest.new_request(request.get_full_path(), request.user, ip)
        else:
            if settings.DJANGO_SIMPLE_AUDIT_REST_FRAMEWORK_AUTHENTICATOR:
                authenticator = self._import_from_string(settings.DJANGO_SIMPLE_AUDIT_REST_FRAMEWORK_AUTHENTICATOR, 'DJANGO_SIMPLE_AUDIT_AUTHENTICATOR')
                user_auth_tuple = authenticator().authenticate(request)
                if user_auth_tuple is not None:
                    user = user_auth_tuple[0]
                    ip = self._get_ip(request)
                    AuditRequest.new_request(request.get_full_path(), user, ip)

    def process_response(self, request, response):
        AuditRequest.cleanup_request()
        return response
