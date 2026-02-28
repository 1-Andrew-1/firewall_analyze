from django.contrib import admin
from django.urls import path
from analyzer import views

urlpatterns = [
    path("admin/", admin.site.urls),

    path("", views.dashboard_page, name="dashboard"),
    path("upload/", views.upload_page, name="upload"),

    path("snapshots/", views.snapshots_page, name="snapshots"),
    path("snapshot/<int:id>/", views.snapshot_detail_page, name="snapshot_detail"),
    path("snapshot/<int:id>/filter/", views.snapshot_filter_page, name="snapshot_filter"),
    path("snapshot/<int:id>/nat/", views.snapshot_nat_page, name="snapshot_nat"),
    path("snapshot/<int:id>/analyze/", views.snapshot_analyze, name="snapshot_analyze"),
    path("snapshot/<int:id>/delete/", views.delete_snapshot, name="snapshot_delete"),

    path("reports/", views.reports_page, name="reports"),
    path("report/<int:id>/", views.report_detail_page, name="report_detail"),
    path("report/<int:id>/delete/", views.delete_report, name="delete_report"),
    path("report/<int:id>/json/", views.export_report_json, name="export_report_json"),
]
