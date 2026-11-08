from django.urls import include, path
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register("hosts", views.HostViewSet, basename="host")
router.register("processes", views.ProcessViewSet, basename="process")
router.register("alerts", views.AlertViewSet, basename="alert")
router.register("connections", views.ConnectionViewSet, basename="connection")
router.register("yara", views.YaraViewSet, basename="yara")
router.register("exceptions", views.SuppressionViewSet, basename="exception")
router.register("actions", views.ActionLogViewSet, basename="action")

urlpatterns = [
    path("health/", views.HealthView.as_view()),
    path("ingest/", views.IngestView.as_view()),
    path("overview/", views.OverviewView.as_view()),
    path("graph/", views.GraphView.as_view()),
    path("rules/", views.RulesView.as_view()),
    path("system/", views.SystemView.as_view()),
    path("system/shutdown/", views.ShutdownView.as_view()),
    path("maintenance/clear/", views.ClearHistoryView.as_view()),
    path("reports/export/", views.ReportView.as_view()),
    path("", include(router.urls)),
]
