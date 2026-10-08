from django.urls import path

from . import api

urlpatterns = [
    path("domains", api.DomainList.as_view()),
    path("domains/<int:pk>", api.DomainDetail.as_view()),
    path("domains/<int:pk>/verify", api.DomainVerify.as_view()),
    path("mailboxes", api.MailboxList.as_view()),
    path("mailboxes/<int:pk>", api.MailboxDetail.as_view()),
    path("keys", api.KeyList.as_view()),
    path("keys/<int:pk>", api.KeyDetail.as_view()),
    path("usage", api.Usage.as_view()),
]
