from __future__ import annotations

from django.db import models


class Host(models.Model):
    host_id = models.CharField(max_length=32, unique=True)
    hostname = models.CharField(max_length=255)
    os_name = models.CharField(max_length=32, blank=True)
    os_version = models.CharField(max_length=255, blank=True)
    arch = models.CharField(max_length=32, blank=True)
    ip_addresses = models.JSONField(default=list, blank=True)
    agent_version = models.CharField(max_length=32, blank=True)
    is_admin = models.BooleanField(default=False)
    capabilities = models.JSONField(default=dict, blank=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField()

    class Meta:
        ordering = ["hostname"]

    def __str__(self) -> str:
        return self.hostname


class Process(models.Model):
    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name="processes")
    pid = models.IntegerField()
    create_ms = models.BigIntegerField()  # create time (ms) - disambiguates PID reuse
    ppid = models.IntegerField(default=0)
    parent = models.ForeignKey("self", null=True, blank=True, on_delete=models.SET_NULL, related_name="children")

    name = models.CharField(max_length=255, blank=True)
    exe = models.CharField(max_length=1024, blank=True, db_index=True)
    cmdline = models.TextField(blank=True)
    cwd = models.CharField(max_length=1024, blank=True)
    username = models.CharField(max_length=255, blank=True)
    sha256 = models.CharField(max_length=64, blank=True)
    exe_deleted = models.BooleanField(default=False)
    is_agent = models.BooleanField(default=False)

    started_at = models.DateTimeField()
    ended_at = models.DateTimeField(null=True, blank=True)

    last_cpu = models.FloatField(default=0)
    last_rss = models.BigIntegerField(default=0)
    last_threads = models.IntegerField(default=0)

    net_out = models.IntegerField(default=0)
    net_listen = models.IntegerField(default=0)
    net_remotes = models.IntegerField(default=0)

    mem_summary = models.JSONField(default=dict, blank=True)
    mem_regions = models.JSONField(default=list, blank=True)  # latest flagged regions (<=16)
    mem_scanned_at = models.DateTimeField(null=True, blank=True)
    # why the memory could not be read: "protected", "denied" or "other". Empty when it was readable
    mem_unreadable = models.CharField(max_length=12, blank=True, default="")
    yara_hits = models.JSONField(default=list, blank=True)    # [{rule, severity, ts}]

    findings = models.JSONField(default=list, blank=True)
    muted = models.JSONField(default=list, blank=True)  # findings silenced by an exception, kept so you can see them
    risk_score = models.IntegerField(default=0, db_index=True)
    anomaly = models.FloatField(null=True, blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["host", "pid", "create_ms"], name="uniq_process_instance")]
        indexes = [
            models.Index(fields=["host", "pid"]),
            models.Index(fields=["host", "-started_at"]),
            models.Index(fields=["ended_at"]),
        ]
        ordering = ["-started_at"]

    @property
    def alive(self) -> bool:
        return self.ended_at is None

    @property
    def basename(self) -> str:
        if self.name:
            return self.name
        return self.exe.replace("\\", "/").rsplit("/", 1)[-1]

    def __str__(self) -> str:
        return f"{self.basename}[{self.pid}]"


class Connection(models.Model):
    process = models.ForeignKey(Process, on_delete=models.CASCADE, related_name="connections")
    direction = models.CharField(max_length=8)  # outbound | listen
    proto = models.CharField(max_length=4)
    laddr = models.CharField(max_length=64, blank=True)
    lport = models.IntegerField(default=0)
    raddr = models.CharField(max_length=64, blank=True)
    rport = models.IntegerField(default=0)
    status = models.CharField(max_length=16, blank=True)
    first_seen = models.DateTimeField()

    scope = models.CharField(max_length=12, blank=True)  # public | private | loopback | ...
    country = models.CharField(max_length=2, blank=True)
    asn = models.IntegerField(null=True, blank=True)
    as_org = models.CharField(max_length=128, blank=True)
    hostname = models.CharField(max_length=255, blank=True)
    entropy = models.FloatField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["process", "first_seen"]),
            models.Index(fields=["raddr"]),
            models.Index(fields=["-first_seen"]),
        ]
        ordering = ["-first_seen"]


class MemoryScan(models.Model):
    process = models.ForeignKey(Process, on_delete=models.CASCADE, related_name="memory_scans")
    ts = models.DateTimeField()
    summary = models.JSONField(default=dict)
    regions = models.JSONField(default=list)  # flagged regions only

    class Meta:
        indexes = [models.Index(fields=["process", "-ts"])]
        ordering = ["-ts"]


class Alert(models.Model):
    SEVERITIES = [("low", "Low"), ("medium", "Medium"), ("high", "High"), ("critical", "Critical")]
    STATUSES = [("open", "Open"), ("ack", "Acknowledged"), ("closed", "Closed"), ("false_positive", "False positive")]

    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name="alerts")
    process = models.ForeignKey(Process, null=True, blank=True, on_delete=models.SET_NULL, related_name="alerts")
    dedupe_key = models.CharField(max_length=255, unique=True)

    rule_id = models.CharField(max_length=64)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    severity = models.CharField(max_length=8, choices=SEVERITIES, db_index=True)
    score = models.IntegerField(default=0)
    weight = models.IntegerField(default=0)  # the finding's own weight (score is the process-wide risk)
    tactic = models.CharField(max_length=64, blank=True)
    technique = models.CharField(max_length=32, blank=True)
    status = models.CharField(max_length=16, choices=STATUSES, default="open", db_index=True)

    process_name = models.CharField(max_length=255, blank=True)
    process_path = models.CharField(max_length=1024, blank=True)
    pid = models.IntegerField(null=True, blank=True)
    remote_ip = models.CharField(max_length=64, blank=True)
    memory_flag = models.BooleanField(default=False)
    evidence = models.JSONField(default=dict, blank=True)
    suppression = models.IntegerField(null=True, blank=True, db_index=True)  # exception that auto-closed this alert

    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()

    class Meta:
        indexes = [models.Index(fields=["-last_seen"]), models.Index(fields=["status", "severity"])]
        ordering = ["-id"]


class YaraJob(models.Model):
    STATUSES = [("queued", "Queued"), ("running", "Running"), ("done", "Done"), ("error", "Error")]

    process = models.ForeignKey(Process, on_delete=models.CASCADE, related_name="yara_jobs")
    status = models.CharField(max_length=8, choices=STATUSES, default="queued")
    scope = models.CharField(max_length=12, default="flagged")  # flagged | executable | all
    include_file = models.BooleanField(default=True)
    use_builtin = models.BooleanField(default=True)
    custom_rules = models.TextField(blank=True)
    auto = models.BooleanField(default=False)

    requested_at = models.DateTimeField()
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    regions_scanned = models.IntegerField(default=0)
    bytes_scanned = models.BigIntegerField(default=0)
    matches = models.JSONField(default=list, blank=True)
    error = models.TextField(blank=True)

    class Meta:
        ordering = ["-id"]


class Suppression(models.Model):
    """An exception: matching findings are not scored or alerted on.

    Matching is conjunctive over the fields that are set: rule_id (exact, or a prefix ending in `*`),
    exe (exact, case-insensitive full path) and name (exact, case-insensitive process name).
    """

    rule_id = models.CharField(max_length=64, blank=True)
    exe = models.CharField(max_length=1024, blank=True)
    name = models.CharField(max_length=255, blank=True)
    note = models.CharField(max_length=255, blank=True)
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-id"]

    def matches(self, rule_id: str, exe: str, name: str) -> bool:
        if self.rule_id:
            if self.rule_id.endswith("*"):
                if not rule_id.startswith(self.rule_id[:-1]):
                    return False
            elif self.rule_id != rule_id:
                return False
        if self.exe and self.exe != (exe or "").lower():
            return False
        if self.name and self.name != (name or "").lower():
            return False
        return True


class ActionLog(models.Model):
    """Log of response actions taken from the UI."""

    ts = models.DateTimeField(auto_now_add=True)
    kind = models.CharField(max_length=16)  # suspend | resume | terminate
    process = models.ForeignKey(Process, null=True, blank=True, on_delete=models.SET_NULL, related_name="actions")
    pid = models.IntegerField()
    name = models.CharField(max_length=255, blank=True)
    ok = models.BooleanField(default=False)
    detail = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ["-id"]
