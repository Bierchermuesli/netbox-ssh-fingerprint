from django.urls import include, path

from utilities.urls import get_model_urls

from . import views

urlpatterns = [
    path('host-keys/', include(get_model_urls('netbox_ssh_fingerprint', 'hostkey', detail=False))),
    path('host-keys/<int:pk>/', include(get_model_urls('netbox_ssh_fingerprint', 'hostkey'))),
    path('known-hosts/', views.KnownHostsView.as_view(), name='known_hosts'),
    path('sshfp/', views.SSHFPView.as_view(), name='sshfp'),
    path('report/', views.ReportView.as_view(), name='report'),
    path('fetch/<str:model>/<int:pk>/', views.FetchView.as_view(), name='fetch'),
    path('replace/<str:model>/<int:pk>/', views.ReplaceHardwareView.as_view(), name='replace_hardware'),
]
