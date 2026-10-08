from django.urls import path

from . import panel as p

urlpatterns = [
    path("", p.home, name="panel-home"),
    path("login/", p.login_view, name="panel-login"),
    path("register/", p.register_view, name="panel-register"),
    path("forgot/", p.forgot_view, name="panel-forgot"),
    path("reset/<str:token>/", p.reset_view, name="panel-reset"),
    path("logout/", p.logout_view, name="panel-logout"),
    path("verify/<str:token>/", p.verify_view, name="panel-verify"),
    path("domains/add/", p.domain_add, name="panel-domain-add"),
    path("domains/<int:pk>/", p.domain_detail, name="panel-domain"),
    path("domains/<int:pk>/verify/", p.domain_verify, name="panel-domain-verify"),
    path("domains/<int:pk>/delete/", p.domain_delete, name="panel-domain-delete"),
    path("domains/<int:pk>/mailboxes/", p.mailbox_create, name="panel-mailbox-create"),
    path("mailboxes/<int:pk>/delete/", p.mailbox_delete, name="panel-mailbox-delete"),
    path("keys/", p.keys, name="panel-keys"),
    path("keys/new/", p.key_create, name="panel-key-create"),
    path("keys/<int:pk>/revoke/", p.key_revoke, name="panel-key-revoke"),
    path("upgrade/", p.upgrade, name="panel-upgrade"),
]
