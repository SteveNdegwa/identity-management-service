import datetime

from django.contrib.auth.models import AnonymousUser
from django.http import HttpRequest

from accounts.models import SystemUser, User
from sso.models import AccessToken, SSOSession
from systems.models import SystemClient


class ExtendedRequest(HttpRequest):
    """
    Extends the base HttpRequest with additional attributes.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user: User | AnonymousUser = AnonymousUser()
        self.is_authenticated: bool = False
        self.user_context_selected = False
        self.system_user: SystemUser | None = None
        self.system_client: SystemClient | None = None
        self.sso_session: SSOSession | None = None
        self.access_token: AccessToken | None = None
        self.user_permissions: list = []
        self.client_ip: str = ''
        self.user_agent: str = ''
        self.data: dict = {}
        self.received_at: datetime.datetime | None = None
