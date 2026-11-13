from django.urls import path

from netbox.api.routers import NetBoxRouter

from . import views

router = NetBoxRouter()
router.APIRootView = views.SSHFingerprintRootView
router.register('host-keys', views.HostKeyViewSet)

urlpatterns = [
    path('known-hosts/', views.KnownHostsView.as_view(), name='known-hosts'),
    path('sshfp/', views.SSHFPView.as_view(), name='sshfp'),
    path('fetch/', views.FetchView.as_view(), name='fetch'),
    path('scans/', views.ScanView.as_view(), name='scans'),
    path('import-known-hosts/', views.ImportKnownHostsView.as_view(), name='import-known-hosts'),
    *router.urls,
]
