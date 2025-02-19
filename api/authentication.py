from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from .models import APIKey

class APIKeyAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        
        if not auth_header:
            return None 

        try:
            auth_type, api_key = auth_header.split(' ')
        except ValueError:
            raise AuthenticationFailed('Invalid Authorization header format.')


        if auth_type.lower() != 'api_key':
            raise AuthenticationFailed('Invalid authorization scheme. Expected "API_KEY".')

        try:
            api_key_obj = APIKey.objects.get(key=api_key)
            return (api_key_obj.user, None)  
        except APIKey.DoesNotExist:
            raise AuthenticationFailed('Invalid API key')