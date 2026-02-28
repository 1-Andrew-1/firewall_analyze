from django.db import models
from django.utils import timezone


class Snapshot(models.Model):
    STATUS_PROCESSING = "processing"
    STATUS_READY = "ready"
    STATUS_ERROR = "error"

    STATUS_CHOICES = [
        (STATUS_PROCESSING, "в процессе"),
        (STATUS_READY, "готово"),
        (STATUS_ERROR, "ошибка"),
    ]

    original_filename = models.CharField(max_length=255, blank=True, default="")
    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    is_active = models.BooleanField(default=True)

    # Сырые правила
    fw_rules = models.JSONField(default=list, blank=True)   # FilterRules
    nat_rules = models.JSONField(default=list, blank=True)  # NatRules

    # Счетчики для UI
    policy_rules_count = models.PositiveIntegerField(default=0)
    nat_rules_count = models.PositiveIntegerField(default=0)

    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_READY)
    error_text = models.TextField(blank=True, default="")

    @property
    def filename(self) -> str:
        # В шаблонах иногда дергают s.filename — даем совместимый алиас
        return self.original_filename or f"snapshot_{self.pk}"

    def __str__(self) -> str:
        return f"Snapshot #{self.id} ({self.filename})"


class Report(models.Model):
    snapshot = models.ForeignKey(Snapshot, on_delete=models.CASCADE, related_name="reports")
    created_at = models.DateTimeField(default=timezone.now, db_index=True)

    # Любые агрегаты для карточек/дашборда
    summary = models.JSONField(default=dict, blank=True)

    def __str__(self) -> str:
        return f"Report #{self.id} for Snapshot #{self.snapshot_id}"


class Anomaly(models.Model):
    SEV_LOW = "low"
    SEV_MED = "medium"
    SEV_HIGH = "high"
    SEV_CRIT = "critical"

    SEVERITY_CHOICES = [
        (SEV_LOW, "низкая"),
        (SEV_MED, "средняя"),
        (SEV_HIGH, "высокая"),
        (SEV_CRIT, "критическая"),
    ]

    SCOPE_FW = "fw"
    SCOPE_NAT = "nat"
    SCOPE_CHOICES = [
        (SCOPE_FW, "FilterRules"),
        (SCOPE_NAT, "NatRules"),
    ]

    report = models.ForeignKey(Report, on_delete=models.CASCADE, related_name="anomalies")
    created_at = models.DateTimeField(default=timezone.now, db_index=True)

    scope = models.CharField(max_length=8, choices=SCOPE_CHOICES)
    code = models.CharField(max_length=64, default="", blank=True)

    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, default="")
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default=SEV_MED)

    rule_index = models.IntegerField(null=True, blank=True)
    rule_name = models.CharField(max_length=255, blank=True, default="")

    details = models.JSONField(default=dict, blank=True)

    def __str__(self) -> str:
        return f"[{self.scope}] {self.title} (#{self.id})"
