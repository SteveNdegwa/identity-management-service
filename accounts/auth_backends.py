from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model

from base.models import Realm


class RealmModelBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        UserModel = get_user_model()
        login_value = username or kwargs.get(UserModel.USERNAME_FIELD)

        realm, _ = Realm.objects.get_or_create(name="Admin")

        if not login_value or password is None:
            return None

        try:
            user = UserModel._default_manager.get(
                realm=realm,
                **{UserModel.USERNAME_FIELD: login_value},
            )
        except (UserModel.DoesNotExist, UserModel.MultipleObjectsReturned):
            UserModel().set_password(password)
            return None

        if user.check_password(password) and self.user_can_authenticate(user):
            return user
        return None
