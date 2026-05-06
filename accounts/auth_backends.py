from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model


class RealmModelBackend(ModelBackend):
    """
    Auth backend for realm-scoped user identifiers.

    Application SSO paths should pass a realm when authenticating by email.
    Django admin does not have a realm field, so non-unique emails cannot be
    authenticated there without an additional realm-aware admin login form.
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        UserModel = get_user_model()
        login_value = username or kwargs.get(UserModel.USERNAME_FIELD)
        realm = kwargs.get("realm")

        if not login_value or password is None:
            return None

        try:
            if realm is not None:
                user = UserModel._default_manager.get(
                    realm=realm,
                    **{UserModel.USERNAME_FIELD: login_value},
                )
            else:
                user = UserModel._default_manager.get_by_natural_key(login_value)
        except (UserModel.DoesNotExist, UserModel.MultipleObjectsReturned):
            UserModel().set_password(password)
            return None

        if user.check_password(password) and self.user_can_authenticate(user):
            return user
        return None
