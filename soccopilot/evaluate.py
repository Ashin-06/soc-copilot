"""Benchmark: labelled multi-stage incident campaigns (modelled on OTRF Security Datasets
and Splunk BOTS, plus digital banking payment fraud) mixed with a day of normal traffic."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from .correlate import Incident
from .pipeline import SOCCopilot
from .triage import TriageReport

BASE_TS = 1761039000.0  # 2025-10-21 09:30:00 UTC (15:00 IST daytime)


@dataclass
class CampaignSpec:
    campaign_id: str
    title: str
    primary_entity: str
    expected_tactics: list[str]
    expects_security_and_fraud: bool
    events: list[dict[str, Any]] = field(default_factory=list)


def build_labelled_campaigns(base_ts: float = BASE_TS) -> list[CampaignSpec]:
    """Construct 6 multi-stage labelled attack campaigns spanning auth, API, cloud, servers, and payments."""
    campaigns: list[CampaignSpec] = []

    # Campaign 1: Customer ATO + MFA Fatigue + Beneficiary Add + ₹1,85,000 Wire Drain (Security + Fraud)
    c1_ts = base_ts + 600
    c1_events = [
        {
            "event_id": f"EVT-100{i}",
            "source_type": "auth",
            "ts": c1_ts + i * 12,
            "action": "login_failed",
            "outcome": "failure",
            "customer_id": "CUST-1042",
            "account": "50100984512011",
            "customer_name": "Mrs. Kavita Deshmukh",
            "phone": "+91 98201 44510",
            "ip": "185.220.101.42",
            "device_id": "DEV-ANON-99",
            "campaign_id": "CAMP-01",
            "message": f"Failed password attempt #{i} for CUST-1042 from Tor exit node 185.220.101.42",
        }
        for i in range(1, 5)
    ] + [
        {
            "event_id": "EVT-1005",
            "source_type": "auth",
            "ts": c1_ts + 65,
            "action": "mfa_push_denied",
            "outcome": "failure",
            "customer_id": "CUST-1042",
            "account": "50100984512011",
            "ip": "185.220.101.42",
            "device_id": "DEV-ANON-99",
            "campaign_id": "CAMP-01",
            "message": "Customer denied unsolicited MFA push notification #1",
        },
        {
            "event_id": "EVT-1006",
            "source_type": "auth",
            "ts": c1_ts + 80,
            "action": "mfa_push_denied",
            "outcome": "failure",
            "customer_id": "CUST-1042",
            "account": "50100984512011",
            "ip": "185.220.101.42",
            "device_id": "DEV-ANON-99",
            "campaign_id": "CAMP-01",
            "message": "Customer denied unsolicited MFA push notification #2",
        },
        {
            "event_id": "EVT-1007",
            "source_type": "auth",
            "ts": c1_ts + 95,
            "action": "mfa_push_approved",
            "outcome": "success",
            "customer_id": "CUST-1042",
            "account": "50100984512011",
            "ip": "185.220.101.42",
            "device_id": "DEV-ANON-99",
            "campaign_id": "CAMP-01",
            "message": "MFA push notification approved after repeated prompts",
        },
        {
            "event_id": "EVT-1008",
            "source_type": "auth",
            "ts": c1_ts + 100,
            "action": "login_success",
            "outcome": "success",
            "customer_id": "CUST-1042",
            "account": "50100984512011",
            "customer_name": "Mrs. Kavita Deshmukh",
            "ip": "185.220.101.42",
            "device_id": "DEV-ANON-99",
            "campaign_id": "CAMP-01",
            "message": "Session established for CUST-1042 from 185.220.101.42 (NL)",
        },
        {
            "event_id": "EVT-1009",
            "source_type": "payments",
            "ts": c1_ts + 150,
            "action": "beneficiary_added",
            "outcome": "success",
            "customer_id": "CUST-1042",
            "account": "50100984512011",
            "counterparty_account": "99880011223344",
            "beneficiary_name": "QuickCash Traders",
            "ifsc": "KKBK0000811",
            "ip": "185.220.101.42",
            "device_id": "DEV-ANON-99",
            "campaign_id": "CAMP-01",
            "message": "Added new payee QuickCash Traders (99880011223344)",
        },
        {
            "event_id": "EVT-1010",
            "source_type": "payments",
            "ts": c1_ts + 210,
            "action": "wire_transfer",
            "outcome": "success",
            "customer_id": "CUST-1042",
            "account": "50100984512011",
            "counterparty_account": "99880011223344",
            "amount": 185000.0,
            "pan": "ABCPD4412K",
            "phone": "+91 98201 44510",
            "ip": "185.220.101.42",
            "device_id": "DEV-ANON-99",
            "campaign_id": "CAMP-01",
            "message": "Outbound IMPS/wire transfer of ₹1,85,000 to newly added beneficiary 99880011223344",
        },
    ]
    campaigns.append(
        CampaignSpec(
            campaign_id="CAMP-01",
            title="Customer ATO via MFA Fatigue & ₹1.85L Wire Drain",
            primary_entity="customer:CUST-1042",
            expected_tactics=["initial_access", "credential_access", "impact"],
            expects_security_and_fraud=True,
            events=c1_events,
        )
    )

    # Campaign 2: CloudTrail IAM Privilege Escalation & S3 KYC Bucket Exfiltration
    c2_ts = base_ts - 26100  # 02:15 UTC (off-hours for vikram.rao)
    c2_events = [
        {
            "event_id": "EVT-2001",
            "source_type": "auth",
            "ts": c2_ts,
            "action": "login_success",
            "outcome": "success",
            "user": "vikram.rao",
            "ip": "91.214.124.88",
            "host": "auth-service-prod",
            "campaign_id": "CAMP-02",
            "message": "Staff SSO login by vikram.rao at 02:15 UTC from external IP 91.214.124.88",
        },
        {
            "event_id": "EVT-2002",
            "source_type": "cloudtrail",
            "eventTime": c2_ts + 45,
            "eventSource": "sts.amazonaws.com",
            "eventName": "AssumeRole",
            "userIdentity": {"userName": "vikram.rao"},
            "sourceIPAddress": "91.214.124.88",
            "requestParameters": {"roleArn": "arn:aws:iam::112233445566:role/ProdCoreAdmin"},
            "campaign_id": "CAMP-02",
            "message": "CloudTrail AssumeRole to ProdCoreAdmin by vikram.rao",
        },
        {
            "event_id": "EVT-2003",
            "source_type": "cloudtrail",
            "eventTime": c2_ts + 90,
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateAccessKey",
            "userIdentity": {"userName": "vikram.rao"},
            "sourceIPAddress": "91.214.124.88",
            "responseElements": {"accessKey": {"accessKeyId": "AKIAIOSFODNN7COMPROM"}},
            "campaign_id": "CAMP-02",
            "message": "Created persistent IAM access key AKIAIOSFODNN7COMPROM for vikram.rao",
        },
        {
            "event_id": "EVT-2004",
            "source_type": "cloudtrail",
            "eventTime": c2_ts + 140,
            "eventSource": "s3.amazonaws.com",
            "eventName": "PutBucketPolicy",
            "userIdentity": {"userName": "vikram.rao", "accessKeyId": "AKIAIOSFODNN7COMPROM"},
            "sourceIPAddress": "91.214.124.88",
            "requestParameters": {"bucketName": "northwind-customer-kyc-prod", "policy": "public-read"},
            "campaign_id": "CAMP-02",
            "message": "Modified bucket policy on northwind-customer-kyc-prod",
        },
        {
            "event_id": "EVT-2005",
            "source_type": "cloudtrail",
            "eventTime": c2_ts + 200,
            "eventSource": "s3.amazonaws.com",
            "eventName": "GetObjectBatch",
            "userIdentity": {"userName": "vikram.rao", "accessKeyId": "AKIAIOSFODNN7COMPROM"},
            "sourceIPAddress": "91.214.124.88",
            "bytesTransferredOut": 85_000_000,
            "campaign_id": "CAMP-02",
            "message": "Bulk download of 85 MB from northwind-customer-kyc-prod S3 bucket",
        },
    ]
    campaigns.append(
        CampaignSpec(
            campaign_id="CAMP-02",
            title="Cloud IAM Escalation & S3 KYC Vault Exfiltration",
            primary_entity="user:vikram.rao",
            expected_tactics=["initial_access", "persistence", "collection", "exfiltration"],
            expects_security_and_fraud=False,
            events=c2_events,
        )
    )

    # Campaign 3: API IDOR Account Enumeration + Payment Velocity Structuring (Security + Fraud)
    c3_ts = base_ts + 4200
    c3_events = [
        {
            "event_id": f"EVT-300{i}",
            "source_type": "api_gateway",
            "ts": c3_ts + i * 8,
            "method": "GET",
            "path": f"/api/v1/accounts/5010077234190{i}",
            "status_code": 200 if i == 5 else 403,
            "client_ip": "197.210.52.71",
            "customer_id": "CUST-2088",
            "device_id": "DEV-PROXY-33",
            "campaign_id": "CAMP-03",
            "message": f"API account lookup GET /api/v1/accounts/5010077234190{i} from 197.210.52.71",
        }
        for i in range(1, 6)
    ] + [
        {
            "event_id": "EVT-3006",
            "source_type": "payments",
            "ts": c3_ts + 90,
            "action": "imps_transfer",
            "outcome": "success",
            "customer_id": "CUST-2088",
            "account": "50100772341908",
            "counterparty_account": "77001122334455",
            "amount": 48500.0,
            "ip": "197.210.52.71",
            "device_id": "DEV-PROXY-33",
            "campaign_id": "CAMP-03",
            "message": "Structured IMPS transfer #1 of ₹48,500 (just under ₹50k threshold)",
        },
        {
            "event_id": "EVT-3007",
            "source_type": "payments",
            "ts": c3_ts + 150,
            "action": "imps_transfer",
            "outcome": "success",
            "customer_id": "CUST-2088",
            "account": "50100772341908",
            "counterparty_account": "77001122334455",
            "amount": 49000.0,
            "ip": "197.210.52.71",
            "device_id": "DEV-PROXY-33",
            "campaign_id": "CAMP-03",
            "message": "Structured IMPS transfer #2 of ₹49,000 (just under ₹50k threshold)",
        },
        {
            "event_id": "EVT-3008",
            "source_type": "payments",
            "ts": c3_ts + 210,
            "action": "imps_transfer",
            "outcome": "success",
            "customer_id": "CUST-2088",
            "account": "50100772341908",
            "counterparty_account": "77001122334455",
            "amount": 47800.0,
            "ip": "197.210.52.71",
            "device_id": "DEV-PROXY-33",
            "campaign_id": "CAMP-03",
            "message": "Structured IMPS transfer #3 of ₹47,800 (just under ₹50k threshold)",
        },
    ]
    campaigns.append(
        CampaignSpec(
            campaign_id="CAMP-03",
            title="API IDOR Account Enumeration & Structured Smurfing Transfers",
            primary_entity="customer:CUST-2088",
            expected_tactics=["discovery", "impact"],
            expects_security_and_fraud=True,
            events=c3_events,
        )
    )

    # Campaign 4: Bastion SSH Intrusion -> Lateral Movement -> Prod Ledger DB Dump
    c4_ts = base_ts + 8000
    c4_events = [
        {
            "event_id": "EVT-4001",
            "source_type": "wazuh",
            "timestamp": c4_ts,
            "agent": {"name": "prod-bastion-01"},
            "rule": {"id": "5402", "level": 12, "description": "Unauthorized sudo privilege escalation on bastion"},
            "data": {"srcip": "45.155.205.19", "dstuser": "ananya.menon", "action": "sudo_priv_esc", "category": "process"},
            "campaign_id": "CAMP-04",
        },
        {
            "event_id": "EVT-4002",
            "source_type": "wazuh",
            "timestamp": c4_ts + 60,
            "agent": {"name": "prod-core-ledger-db-01"},
            "rule": {"id": "5715", "level": 13, "description": "Lateral SSH execution from bastion to core ledger DB"},
            "data": {"srcip": "45.155.205.19", "dstuser": "ananya.menon", "action": "ssh_lateral_exec", "category": "process"},
            "campaign_id": "CAMP-04",
        },
        {
            "event_id": "EVT-4003",
            "source_type": "wazuh",
            "timestamp": c4_ts + 130,
            "agent": {"name": "prod-core-ledger-db-01"},
            "rule": {"id": "8910", "level": 15, "description": "Bulk pg_dump of core_ledger_accounts table (120 MB)"},
            "data": {
                "srcip": "45.155.205.19",
                "dstuser": "ananya.menon",
                "action": "db_bulk_dump",
                "category": "database",
                "bytes_out": 120_000_000,
            },
            "campaign_id": "CAMP-04",
        },
    ]
    campaigns.append(
        CampaignSpec(
            campaign_id="CAMP-04",
            title="Bastion Privilege Escalation & Core Ledger DB Exfiltration",
            primary_entity="user:ananya.menon",
            expected_tactics=["privilege_escalation", "exfiltration"],
            expects_security_and_fraud=False,
            events=c4_events,
        )
    )

    # Campaign 5: Impossible Travel + Device Swap + Beneficiary Add + ₹2,40,000 RTGS Drain
    c5_ts = base_ts + 12000
    c5_events = [
        {
            "event_id": "EVT-5001",
            "source_type": "auth",
            "ts": c5_ts,
            "action": "login_success",
            "outcome": "success",
            "customer_id": "CUST-3015",
            "account": "50100339011224",
            "ip": "115.96.10.25",
            "device_id": "DEV-MEENA-01",
            "campaign_id": "CAMP-05",
            "message": "Normal mobile login for CUST-3015 from Chennai (IN)",
        },
        {
            "event_id": "EVT-5002",
            "source_type": "auth",
            "ts": c5_ts + 600,
            "action": "login_success",
            "outcome": "success",
            "customer_id": "CUST-3015",
            "account": "50100339011224",
            "ip": "175.45.176.14",
            "device_id": "DEV-NEW-771",
            "campaign_id": "CAMP-05",
            "message": "Login for CUST-3015 from 175.45.176.14 (KP) 10 minutes after Chennai session",
        },
        {
            "event_id": "EVT-5003",
            "source_type": "payments",
            "ts": c5_ts + 640,
            "action": "device_changed",
            "outcome": "success",
            "customer_id": "CUST-3015",
            "account": "50100339011224",
            "ip": "175.45.176.14",
            "device_id": "DEV-NEW-771",
            "campaign_id": "CAMP-05",
            "message": "Primary signing device changed to DEV-NEW-771 for CUST-3015",
        },
        {
            "event_id": "EVT-5004",
            "source_type": "payments",
            "ts": c5_ts + 680,
            "action": "beneficiary_added",
            "outcome": "success",
            "customer_id": "CUST-3015",
            "account": "50100339011224",
            "counterparty_account": "88776655443322",
            "ip": "175.45.176.14",
            "device_id": "DEV-NEW-771",
            "campaign_id": "CAMP-05",
            "message": "Added new RTGS beneficiary 88776655443322",
        },
        {
            "event_id": "EVT-5005",
            "source_type": "payments",
            "ts": c5_ts + 730,
            "action": "rtgs_transfer",
            "outcome": "success",
            "customer_id": "CUST-3015",
            "account": "50100339011224",
            "counterparty_account": "88776655443322",
            "amount": 240000.0,
            "ip": "175.45.176.14",
            "device_id": "DEV-NEW-771",
            "campaign_id": "CAMP-05",
            "message": "High-value RTGS transfer of ₹2,40,000 after impossible travel and device change",
        },
    ]
    campaigns.append(
        CampaignSpec(
            campaign_id="CAMP-05",
            title="Impossible Travel, Device Swap & ₹2.40L RTGS Drain",
            primary_entity="customer:CUST-3015",
            expected_tactics=["initial_access", "persistence", "impact"],
            expects_security_and_fraud=True,
            events=c5_events,
        )
    )

    # Campaign 6: Malicious Insider Off-Hours Bulk Export & Audit Log Stop
    c6_ts = base_ts - 28800  # 01:30 UTC (off-hours for rohit.verma)
    c6_events = [
        {
            "event_id": "EVT-6001",
            "source_type": "auth",
            "ts": c6_ts,
            "action": "login_success",
            "outcome": "success",
            "user": "rohit.verma",
            "ip": "10.12.4.55",
            "host": "auth-service-prod",
            "campaign_id": "CAMP-06",
            "message": "Off-hours staff login by rohit.verma at 01:30 UTC",
        },
        {
            "event_id": "EVT-6002",
            "source_type": "ecs",
            "@timestamp": c6_ts + 80,
            "event": {"category": "database", "action": "bulk_statement_export", "outcome": "success"},
            "user": {"name": "rohit.verma"},
            "source": {"ip": "10.12.4.55"},
            "host": {"name": "prod-core-ledger-db-01"},
            "bytes_out": 68_000_000,
            "campaign_id": "CAMP-06",
            "message": "Bulk export of 68 MB of VIP customer statements by rohit.verma",
        },
        {
            "event_id": "EVT-6003",
            "source_type": "wazuh",
            "timestamp": c6_ts + 120,
            "agent": {"name": "prod-core-ledger-db-01"},
            "rule": {"id": "9104", "level": 14, "description": "Attempt to stop auditd service on core ledger DB"},
            "data": {"srcip": "10.12.4.55", "dstuser": "rohit.verma", "action": "audit_log_stop", "category": "database"},
            "campaign_id": "CAMP-06",
        },
    ]
    campaigns.append(
        CampaignSpec(
            campaign_id="CAMP-06",
            title="Insider Off-Hours Bulk Statement Export & Audit Tamper",
            primary_entity="user:rohit.verma",
            expected_tactics=["initial_access", "collection", "exfiltration"],
            expects_security_and_fraud=False,
            events=c6_events,
        )
    )

    return campaigns


def build_normal_day_traffic(base_ts: float = BASE_TS, count: int = 240) -> list[dict[str, Any]]:
    """Generate a full day of benign digital-bank logs including look-alike negative events
    (scheduled backups, internal vulnerability scans, single password typos, normal UPI payments).
    """
    benign: list[dict[str, Any]] = []
    for i in range(count):
        ts = base_ts + (i * 180)
        mod = i % 6
        if mod == 0:
            benign.append({
                "event_id": f"EVT-BEN-{i:04d}",
                "source_type": "auth",
                "ts": ts,
                "action": "login_success",
                "outcome": "success",
                "customer_id": "CUST-4090",
                "account": "50100612990143",
                "ip": "49.37.20.11",
                "device_id": "DEV-ARJUN-01",
                "message": "Normal customer login from Bengaluru",
            })
        elif mod == 1:
            benign.append({
                "event_id": f"EVT-BEN-{i:04d}",
                "source_type": "api_gateway",
                "ts": ts,
                "method": "GET",
                "path": "/api/v1/profile/summary",
                "status_code": 200,
                "client_ip": "49.37.20.11",
                "customer_id": "CUST-4090",
                "device_id": "DEV-ARJUN-01",
                "message": "GET /api/v1/profile/summary -> 200",
            })
        elif mod == 2:
            benign.append({
                "event_id": f"EVT-BEN-{i:04d}",
                "source_type": "payments",
                "ts": ts,
                "action": "upi_transfer",
                "outcome": "success",
                "customer_id": "CUST-4090",
                "account": "50100612990143",
                "counterparty_account": "50100998877665",
                "amount": 1250.0 + (i % 5) * 300.0,
                "ip": "49.37.20.11",
                "device_id": "DEV-ARJUN-01",
                "message": "Routine UPI merchant payment to saved payee",
            })
        elif mod == 3:
            # Authorized vulnerability scanner on suppressed IP 10.250.0.99
            benign.append({
                "event_id": f"EVT-BEN-{i:04d}",
                "source_type": "api_gateway",
                "ts": ts,
                "method": "GET",
                "path": f"/api/v1/accounts/check-{i}",
                "status_code": 404,
                "client_ip": "10.250.0.99",
                "user": "svc-vuln-scanner",
                "message": "Scheduled internal scanner health check",
            })
        elif mod == 4:
            # Authorized nightly DBA snapshot by svc-backup-nightly
            benign.append({
                "event_id": f"EVT-BEN-{i:04d}",
                "source_type": "cloudtrail",
                "eventTime": ts,
                "eventSource": "s3.amazonaws.com",
                "eventName": "GetObjectBatch",
                "userIdentity": {"userName": "svc-backup-nightly"},
                "sourceIPAddress": "10.10.1.50",
                "bytesTransferredOut": 95_000_000,
                "message": "Scheduled nightly backup verification by svc-backup-nightly",
            })
        else:
            benign.append({
                "event_id": f"EVT-BEN-{i:04d}",
                "source_type": "ecs",
                "@timestamp": ts,
                "event": {"category": "network", "action": "connection_allowed", "outcome": "success"},
                "user": {"name": "dev.kulkarni"},
                "source": {"ip": "10.12.1.15"},
                "host": {"name": "corp-workstation-07"},
                "bytes_out": 4096,
                "message": "Routine corporate workstation HTTPS request",
            })
    return benign


def seed_demo_copilot(copilot: SOCCopilot | None = None) -> SOCCopilot:
    """Populate a SOCCopilot instance with the 6 multi-stage campaigns + normal background logs."""
    cp = copilot or SOCCopilot()
    cp.reset()
    campaigns = build_labelled_campaigns()
    normal = build_normal_day_traffic(count=120)
    all_raw = normal + [ev for c in campaigns for ev in c.events]
    cp.process_raw_events(all_raw, transport="webhook", auto_triage=True)
    return cp


def run_evaluation(benign_count: int = 240) -> dict[str, Any]:
    """Evaluate SOC Copilot on:
    1. Detection recall of labelled multi-stage incidents
    2. Noise (false-positive incidents per day on normal traffic)
    3. Speed (mean and max time-to-first-alert in milliseconds)
    4. Reports (share of AI triage claims backed by a cited valid log entry ID + privacy masking)
    """
    campaigns = build_labelled_campaigns()
    benign_events = build_normal_day_traffic(count=benign_count)

    # 1. Measure false-positive incident noise on a full day of normal traffic alone
    benign_copilot = SOCCopilot()
    benign_copilot.process_raw_events(benign_events, transport="file_drop")
    false_positive_incidents = len(benign_copilot.incidents)

    # 2. Measure per-campaign time-to-first-alert and combined multi-campaign detection & correlation
    full_copilot = SOCCopilot()
    full_copilot.process_raw_events(benign_events, transport="file_drop")

    ttfa_ms_list: list[float] = []
    for camp in campaigns:
        t0 = time.perf_counter()
        full_copilot.process_raw_events(camp.events, transport="webhook")
        ttfa_ms_list.append((time.perf_counter() - t0) * 1000.0)

    detected_campaigns = 0
    security_fraud_linked = 0
    expected_sec_fraud = sum(1 for c in campaigns if c.expects_security_and_fraud)
    campaign_results: list[dict[str, Any]] = []
    citation_coverages: list[float] = []
    tactic_recalls: list[float] = []

    incidents_list = list(full_copilot.incidents.values())
    for camp in campaigns:
        camp_eids = {e["event_id"] for e in camp.events}
        matched_inc: Incident | None = None
        best_overlap = 0
        for inc in incidents_list:
            overlap = len(camp_eids & set(inc.event_ids))
            if overlap > best_overlap:
                best_overlap = overlap
                matched_inc = inc

        detected = matched_inc is not None and best_overlap >= 2
        if detected and matched_inc is not None:
            detected_campaigns += 1
            if camp.expects_security_and_fraud and matched_inc.security_fraud_joined:
                security_fraud_linked += 1
            rep: TriageReport = full_copilot.triage_engine.triage_incident(matched_inc, use_llm=False)
            citation_coverages.append(rep.citation_coverage)
            tac_hit = sum(1 for t in camp.expected_tactics if t in matched_inc.tactics) / max(1, len(camp.expected_tactics))
            tactic_recalls.append(tac_hit)
            campaign_results.append({
                "campaign_id": camp.campaign_id,
                "title": camp.title,
                "detected": True,
                "incident_id": matched_inc.incident_id,
                "risk_score": matched_inc.risk_score,
                "severity": matched_inc.severity,
                "events_correlated": f"{best_overlap}/{len(camp_eids)}",
                "security_fraud_joined": matched_inc.security_fraud_joined,
                "tactic_recall": round(tac_hit, 3),
                "citation_coverage": rep.citation_coverage,
                "proposed_actions": len(rep.recommended_containment),
            })
        else:
            campaign_results.append({
                "campaign_id": camp.campaign_id,
                "title": camp.title,
                "detected": False,
                "incident_id": None,
                "risk_score": 0.0,
                "severity": "none",
                "events_correlated": f"0/{len(camp_eids)}",
                "security_fraud_joined": False,
                "tactic_recall": 0.0,
                "citation_coverage": 0.0,
                "proposed_actions": 0,
            })

    recall = round(detected_campaigns / len(campaigns), 4)
    mean_citation = round(sum(citation_coverages) / max(1, len(citation_coverages)), 4)
    mean_tactic_recall = round(sum(tactic_recalls) / max(1, len(tactic_recalls)), 4)
    mean_ttfa_ms = round(sum(ttfa_ms_list) / max(1, len(ttfa_ms_list)), 2)

    return {
        "campaigns_total": len(campaigns),
        "campaigns_detected": detected_campaigns,
        "detection_recall": recall,
        "security_fraud_join_rate": round(security_fraud_linked / max(1, expected_sec_fraud), 4),
        "false_positive_incidents_per_day": false_positive_incidents,
        "benign_events_tested": len(benign_events),
        "mean_time_to_first_alert_ms": mean_ttfa_ms,
        "max_time_to_first_alert_ms": round(max(ttfa_ms_list), 2),
        "report_citation_coverage": mean_citation,
        "report_tactic_recall": mean_tactic_recall,
        "campaigns": campaign_results,
    }
