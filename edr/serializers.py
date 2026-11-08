from __future__ import annotations

from rest_framework import serializers

from .models import ActionLog, Alert, Connection, Host, MemoryScan, Process, Suppression, YaraJob


class HostSerializer(serializers.ModelSerializer):
    process_count = serializers.IntegerField(read_only=True, default=0)
    open_alerts = serializers.IntegerField(read_only=True, default=0)

    class Meta:
        model = Host
        fields = ["id", "host_id", "hostname", "os_name", "os_version", "arch", "ip_addresses", "agent_version",
                  "is_admin", "capabilities", "first_seen", "last_seen", "process_count", "open_alerts"]


class ProcessListSerializer(serializers.ModelSerializer):
    host_name = serializers.CharField(source="host.hostname", read_only=True)
    alive = serializers.BooleanField(read_only=True)
    rwx_regions = serializers.SerializerMethodField()
    unbacked_exec = serializers.SerializerMethodField()
    top_finding = serializers.SerializerMethodField()
    finding_count = serializers.SerializerMethodField()

    class Meta:
        model = Process
        fields = ["id", "host", "host_name", "pid", "ppid", "parent", "name", "exe", "cmdline", "username", "sha256",
                  "started_at", "ended_at", "alive", "risk_score", "anomaly", "net_out", "net_listen", "last_cpu",
                  "last_rss", "rwx_regions", "unbacked_exec", "top_finding", "finding_count", "exe_deleted"]

    def get_rwx_regions(self, o):
        return (o.mem_summary or {}).get("rwx_regions", 0)

    def get_unbacked_exec(self, o):
        return (o.mem_summary or {}).get("unbacked_exec", 0)

    def get_top_finding(self, o):
        return o.findings[0]["title"] if o.findings else None

    def get_finding_count(self, o):
        return len(o.findings)


class ConnectionSerializer(serializers.ModelSerializer):
    process_name = serializers.CharField(source="process.name", read_only=True)
    pid = serializers.IntegerField(source="process.pid", read_only=True)

    class Meta:
        model = Connection
        fields = ["id", "process", "process_name", "pid", "direction", "proto", "laddr", "lport", "raddr", "rport",
                  "status", "first_seen", "scope", "country", "asn", "as_org", "hostname", "entropy"]


class AlertSerializer(serializers.ModelSerializer):
    host_name = serializers.CharField(source="host.hostname", read_only=True)

    class Meta:
        model = Alert
        fields = ["id", "host", "host_name", "process", "rule_id", "title", "description", "severity", "score",
                  "weight", "tactic", "technique", "status", "process_name", "process_path", "pid", "remote_ip", "memory_flag",
                  "evidence", "first_seen", "last_seen", "suppression"]
        read_only_fields = fields


class AlertUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Alert
        fields = ["status"]


class MemoryScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = MemoryScan
        fields = ["id", "ts", "summary", "regions"]


class YaraJobSerializer(serializers.ModelSerializer):
    process_name = serializers.CharField(source="process.name", read_only=True)
    pid = serializers.IntegerField(source="process.pid", read_only=True)

    class Meta:
        model = YaraJob
        fields = ["id", "process", "process_name", "pid", "status", "scope", "include_file", "use_builtin", "auto",
                  "requested_at", "started_at", "finished_at", "regions_scanned", "bytes_scanned", "matches", "error"]


class YaraRequestSerializer(serializers.Serializer):
    scope = serializers.ChoiceField(choices=["flagged", "executable", "all"], default="flagged")
    include_file = serializers.BooleanField(default=True)
    use_builtin = serializers.BooleanField(default=True)
    custom_rules = serializers.CharField(required=False, allow_blank=True, default="", max_length=262144)


class IngestHostSerializer(serializers.Serializer):
    host_id = serializers.CharField(max_length=32)
    hostname = serializers.CharField(max_length=255)
    os_name = serializers.CharField(max_length=32, required=False, allow_blank=True)
    os_version = serializers.CharField(max_length=255, required=False, allow_blank=True)
    arch = serializers.CharField(max_length=32, required=False, allow_blank=True)
    ip_addresses = serializers.ListField(child=serializers.CharField(max_length=64), required=False, max_length=16)
    agent_version = serializers.CharField(max_length=32, required=False, allow_blank=True)
    is_admin = serializers.BooleanField(required=False)
    capabilities = serializers.DictField(required=False)


class IngestSerializer(serializers.Serializer):
    host = IngestHostSerializer()
    events = serializers.ListField(child=serializers.DictField(), max_length=5000)
    sent_at = serializers.FloatField(required=False)
    # [[pid, create_time], ...] of every process alive when the collector (re)started
    live = serializers.ListField(child=serializers.ListField(child=serializers.FloatField(), min_length=2, max_length=2),
                                 required=False, max_length=100000)


class SuppressionSerializer(serializers.ModelSerializer):
    silenced = serializers.SerializerMethodField()

    class Meta:
        model = Suppression
        fields = ["id", "rule_id", "exe", "name", "note", "enabled", "created_at", "silenced"]
        read_only_fields = ["id", "created_at", "silenced"]

    def get_silenced(self, o):
        return (self.context.get("silenced") or {}).get(o.id, 0)

    def validate(self, attrs):
        inst = self.instance
        rule = (attrs.get("rule_id", inst.rule_id if inst else "") or "").strip()
        exe = (attrs.get("exe", inst.exe if inst else "") or "").strip().lower()
        name = (attrs.get("name", inst.name if inst else "") or "").strip().lower()
        if not (rule or exe or name):
            raise serializers.ValidationError("Choose at least a rule, a program path or a process name.")
        if rule == "*" and not (exe or name):
            raise serializers.ValidationError("Muting every rule for every program would switch detection off.")
        attrs.update(rule_id=rule, exe=exe, name=name)
        return attrs


class ActionLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = ActionLog
        fields = ["id", "ts", "kind", "process", "pid", "name", "ok", "detail"]
