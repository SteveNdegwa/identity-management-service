import datetime
from typing import Union, Optional

from django.contrib.auth.models import AnonymousUser
from django.http import HttpRequest

from accounts.models import User, SystemUser
from sso.models import SSOSession, AccessToken
from systems.models import SystemClient


class ExtendedRequest(HttpRequest):
    """
    Extends the base HttpRequest with additional attributes.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user: Union[User, AnonymousUser] = AnonymousUser()
        self.system_user: Optional[SystemUser] = None
        self.system_client: Optional[SystemClient] = None
        self.sso_session: Optional[SSOSession] = None
        self.access_token: Optional[AccessToken] = None
        self.is_authenticated: bool = False
        self.user_permissions: list = []
        self.client_ip: str = ''
        self.user_agent: str = ''
        self.data: dict = {}
        self.received_at: Optional[datetime.datetime] = None
