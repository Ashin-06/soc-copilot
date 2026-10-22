"""Stage 3 Enrich: Asset inventory, staff directory, customer context, GeoIP + impossible
travel, and threat intelligence (IP & domain reputation).
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from .normalize import NormalizedEvent


@dataclass
class AssetInfo:
    host: str
    criticality: int        # 1 (low) .. 5 (critical)
    criticality_label: str  # low | medium | high | critical
    environment: str        # prod | corp | staging
    owner_team: str
    service: str


@dataclass
class StaffInfo:
    username: str
    full_name: str
    role: str
    department: str
    privilege_tier: str     # standard | privileged_admin | dba | service
    usual_hours: tuple[int, int] = (8, 20)
    usual_countries: tuple[str, ...] = ("IN",)


@dataclass
class CustomerProfile:
    customer_id: str
    full_name: str
    account: str
    pan: str
    phone: str
    email: str
    account_age_days: int
    avg_transfer_amount: float
    usual_countries: tuple[str, ...] = ("IN",)
    beneficiary_changed_at: float | None = None
    device_changed_at: float | None = None
    phone_changed_at: float | None = None
    known_devices: set[str] = field(default_factory=set)
    known_beneficiaries: set[str] = field(default_factory=set)


DEFAULT_ASSETS: dict[str, AssetInfo] = {
    "prod-core-ledger-db-01": AssetInfo("prod-core-ledger-db-01", 5, "critical", "prod", "Core Banking DBA", "core-ledger-postgres"),
    "core-payments-engine": AssetInfo("core-payments-engine", 5, "critical", "prod", "Payments Platform", "imps-rtgs-switch"),
    "aws.cloudtrail": AssetInfo("aws.cloudtrail", 5, "critical", "prod", "Cloud Platform Security", "aws-control-plane"),
    "s3.amazonaws.com": AssetInfo("s3.amazonaws.com", 5, "critical", "prod", "Cloud Data Platform", "customer-kyc-vault-s3"),
    "iam.amazonaws.com": AssetInfo("iam.amazonaws.com", 5, "critical", "prod", "Cloud Platform Security", "aws-iam"),
    "sts.amazonaws.com": AssetInfo("sts.amazonaws.com", 4, "high", "prod", "Cloud Platform Security", "aws-sts"),
    "prod-api-gw-01": AssetInfo("prod-api-gw-01", 4, "high", "prod", "Digital Channels", "edge-api-gateway"),
    "auth-service-prod": AssetInfo("auth-service-prod", 4, "high", "prod", "Identity & Access", "customer-staff-sso"),
    "prod-bastion-01": AssetInfo("prod-bastion-01", 4, "high", "prod", "SRE Infrastructure", "ssh-bastion"),
    "corp-workstation-07": AssetInfo("corp-workstation-07", 2, "medium", "corp", "IT Operations", "staff-laptop"),
    "staging-api-01": AssetInfo("staging-api-01", 1, "low", "staging", "QA Engineering", "staging-gateway"),
}

DEFAULT_STAFF: dict[str, StaffInfo] = {
    "vikram.rao": StaffInfo("vikram.rao", "Mr. Vikram Rao", "Senior Cloud Engineer", "Cloud Infrastructure", "privileged_admin", (9, 19), ("IN",)),
    "ananya.menon": StaffInfo("ananya.menon", "Ms. Ananya Menon", "Database Reliability Engineer", "Core Banking Ops", "dba", (9, 18), ("IN",)),
    "dev.kulkarni": StaffInfo("dev.kulkarni", "Mr. Dev Kulkarni", "Customer Operations Analyst", "Retail Support", "standard", (8, 18), ("IN",)),
    "rohit.verma": StaffInfo("rohit.verma", "Mr. Rohit Verma", "Treasury Operations Manager", "Treasury", "privileged_admin", (9, 18), ("IN",)),
    "svc-vuln-scanner": StaffInfo("svc-vuln-scanner", "Internal Vulnerability Scanner", "Automated Scanner", "Security", "service", (0, 24), ("IN", "CORP")),
    "svc-backup-nightly": StaffInfo("svc-backup-nightly", "Nightly Backup Service", "Automated Backup", "SRE", "service", (0, 24), ("IN", "CORP")),
}

DEFAULT_CUSTOMERS: dict[str, CustomerProfile] = {
    "CUST-1042": CustomerProfile(
        customer_id="CUST-1042",
        full_name="Mrs. Kavita Deshmukh",
        account="50100984512011",
        pan="ABCPD4412K",
        phone="+91 98201 44510",
        email="kavita.deshmukh@gmail.com",
        account_age_days=840,
        avg_transfer_amount=12000.0,
        usual_countries=("IN",),
        known_devices={"DEV-KAVITA-01"},
        known_beneficiaries={"50100112233445"},
    ),
    "CUST-2088": CustomerProfile(
        customer_id="CUST-2088",
        full_name="Mr. Siddharth Malhotra",
        account="50100772341908",
        pan="BMCPM8821F",
        phone="+91 98112 77890",
        email="siddharth.m@outlook.com",
        account_age_days=410,
        avg_transfer_amount=18000.0,
        usual_countries=("IN",),
        known_devices={"DEV-SID-01"},
        known_beneficiaries={"50100665544332"},
    ),
    "CUST-3015": CustomerProfile(
        customer_id="CUST-3015",
        full_name="Dr. Meenakshi Sundaram",
        account="50100339011224",
        pan="AAHPS9910Q",
        phone="+91 94440 31209",
        email="dr.meenakshi@apollo-clinic.in",
        account_age_days=1420,
        avg_transfer_amount=22000.0,
        usual_countries=("IN",),
        known_devices={"DEV-MEENA-01"},
        known_beneficiaries={"50100443322119"},
    ),
    "CUST-4090": CustomerProfile(
        customer_id="CUST-4090",
        full_name="Mr. Arjun Nair",
        account="50100612990143",
        pan="ACDPN5531E",
        phone="+91 98450 11920",
        email="arjun.nair@techcorp.in",
        account_age_days=65,
        avg_transfer_amount=8500.0,
        usual_countries=("IN",),
        known_devices={"DEV-ARJUN-01"},
        known_beneficiaries={"50100998877665"},
    ),
}

# Offline deterministic GeoIP prefixes + coordinates (lat, lon)
GEO_PREFIXES: dict[str, dict[str, Any]] = {
    "49.36.": {"country": "IN", "city": "Mumbai", "lat": 19.0760, "lon": 72.8777},
    "49.37.": {"country": "IN", "city": "Bengaluru", "lat": 12.9716, "lon": 77.5946},
    "103.21.": {"country": "IN", "city": "Delhi", "lat": 28.6139, "lon": 77.2090},
    "115.96.": {"country": "IN", "city": "Chennai", "lat": 13.0827, "lon": 80.2707},
    "122.161.": {"country": "IN", "city": "Hyderabad", "lat": 17.3850, "lon": 78.4867},
    "10.": {"country": "IN", "city": "Corporate-LAN", "lat": 19.0760, "lon": 72.8777},
    "172.16.": {"country": "IN", "city": "VPC-Internal", "lat": 19.0760, "lon": 72.8777},
    "185.220.101.": {"country": "NL", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041},
    "91.214.124.": {"country": "RU", "city": "Moscow", "lat": 55.7558, "lon": 37.6173},
    "45.155.205.": {"country": "RO", "city": "Bucharest", "lat": 44.4268, "lon": 26.1025},
    "197.210.52.": {"country": "NG", "city": "Lagos", "lat": 6.5244, "lon": 3.3792},
    "175.45.176.": {"country": "KP", "city": "Pyongyang", "lat": 39.0194, "lon": 125.7381},
    "198.51.100.": {"country": "US", "city": "Ashburn", "lat": 39.0438, "lon": -77.4874},
}

# Threat intelligence database: IP reputation & domain reputation
THREAT_INTEL_IPS: dict[str, dict[str, Any]] = {
    "185.220.101.42": {
        "score": 0.96,
        "category": "tor_exit_credential_stuffing",
        "feeds": ["TorExitNodes", "AbuseIPDB-Banking-BruteForce"],
        "country": "NL",
        "asn": "AS60729 Tor Exit Router",
    },
    "91.214.124.88": {
        "score": 0.94,
        "category": "bulletproof_hosting_c2",
        "feeds": ["Spamhaus-DROP", "FeodoTracker"],
        "country": "RU",
        "asn": "AS49877 Bulletproof Hosting",
    },
    "45.155.205.19": {
        "score": 0.91,
        "category": "ssh_scanner_botnet",
        "feeds": ["EmergingThreats", "BlocklistDE-SSH"],
        "country": "RO",
        "asn": "AS209605 HostRoyale",
    },
    "197.210.52.71": {
        "score": 0.88,
        "category": "ato_proxy_network",
        "feeds": ["FS-ISAC-FraudProxy"],
        "country": "NG",
        "asn": "AS29465 Residential Proxy",
    },
    "175.45.176.14": {
        "score": 0.99,
        "category": "sanctioned_apt_actor",
        "feeds": ["OFAC-Sanctions", "Lazarus-Indicators"],
        "country": "KP",
        "asn": "AS131279 Star JV",
    },
}

THREAT_INTEL_DOMAINS: dict[str, dict[str, Any]] = {
    "paste-exfil-drop.top": {"score": 0.97, "category": "exfiltration_drop"},
    "northwind-kyc-update.xyz": {"score": 0.95, "category": "phishing_kit"},
    "cdn-telemetry-sync.ru": {"score": 0.92, "category": "c2_beacon"},
}


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


class Enricher:
    """Enriches NormalizedEvent instances with asset criticality, staff directory,
    customer context (recent beneficiary/device/phone changes), GeoIP, and Threat Intel.
    """

    def __init__(self):
        self.assets: dict[str, AssetInfo] = dict(DEFAULT_ASSETS)
        self.staff: dict[str, StaffInfo] = dict(DEFAULT_STAFF)
        self.customers: dict[str, CustomerProfile] = {
            cid: CustomerProfile(
                customer_id=c.customer_id,
                full_name=c.full_name,
                account=c.account,
                pan=c.pan,
                phone=c.phone,
                email=c.email,
                account_age_days=c.account_age_days,
                avg_transfer_amount=c.avg_transfer_amount,
                usual_countries=c.usual_countries,
                beneficiary_changed_at=c.beneficiary_changed_at,
                device_changed_at=c.device_changed_at,
                phone_changed_at=c.phone_changed_at,
                known_devices=set(c.known_devices),
                known_beneficiaries=set(c.known_beneficiaries),
            )
            for cid, c in DEFAULT_CUSTOMERS.items()
        }
        self._account_to_customer: dict[str, str] = {
            c.account: cid for cid, c in self.customers.items()
        }
        self._last_geo_by_actor: dict[str, tuple[float, dict[str, Any]]] = {}

    def lookup_ip_geo(self, ip: str | None) -> dict[str, Any]:
        if not ip:
            return {"country": "UNKNOWN", "city": "Unknown", "lat": 19.0760, "lon": 72.8777}
        for prefix, geo in GEO_PREFIXES.items():
            if ip.startswith(prefix):
                return dict(geo)
        if ip in THREAT_INTEL_IPS:
            c = THREAT_INTEL_IPS[ip]["country"]
            return {"country": c, "city": "External", "lat": 52.3676, "lon": 4.9041}
        return {"country": "IN", "city": "Mumbai", "lat": 19.0760, "lon": 72.8777}

    def lookup_ip_reputation(self, ip: str | None) -> dict[str, Any]:
        if not ip:
            return {"ip": None, "score": 0.0, "malicious": False, "category": "clean", "feeds": []}
        if ip in THREAT_INTEL_IPS:
            info = THREAT_INTEL_IPS[ip]
            return {
                "ip": ip,
                "score": info["score"],
                "malicious": info["score"] >= 0.7,
                "category": info["category"],
                "feeds": list(info["feeds"]),
                "country": info["country"],
                "asn": info["asn"],
            }
        return {"ip": ip, "score": 0.05, "malicious": False, "category": "clean", "feeds": [], "country": self.lookup_ip_geo(ip)["country"]}

    def enrich(self, ev: NormalizedEvent) -> NormalizedEvent:
        enr: dict[str, Any] = {}

        # Resolve customer_id from account if not set
        if not ev.customer_id and ev.account and ev.account in self._account_to_customer:
            ev.customer_id = self._account_to_customer[ev.account]
            ent = f"customer:{ev.customer_id}"
            if ent not in ev.entities:
                ev.entities.append(ent)

        # 1. Asset inventory context
        asset = self.assets.get(ev.host or "")
        if asset:
            enr["asset_criticality"] = asset.criticality
            enr["asset_criticality_label"] = asset.criticality_label
            enr["asset_environment"] = asset.environment
            enr["asset_owner"] = asset.owner_team
            enr["asset_service"] = asset.service
        else:
            enr["asset_criticality"] = 2
            enr["asset_criticality_label"] = "medium"
            enr["asset_environment"] = "prod"

        # 2. Staff directory context
        staff = self.staff.get(ev.user or "")
        if staff:
            enr["staff_name"] = staff.full_name
            enr["staff_role"] = staff.role
            enr["staff_department"] = staff.department
            enr["staff_privilege_tier"] = staff.privilege_tier
            enr["staff_usual_hours"] = list(staff.usual_hours)

        # 3. GeoIP + impossible travel
        geo = self.lookup_ip_geo(ev.source_ip)
        enr["geo_country"] = geo["country"]
        enr["geo_city"] = geo["city"]

        actor_key = ev.customer_id or ev.user
        enr["impossible_travel"] = False
        enr["travel_speed_kmh"] = 0.0
        if actor_key and ev.source_ip:
            prev = self._last_geo_by_actor.get(actor_key)
            if prev is not None:
                prev_ts, prev_geo = prev
                dt_hours = max((ev.timestamp - prev_ts) / 3600.0, 1.0 / 60.0)
                dist_km = _haversine_km(prev_geo["lat"], prev_geo["lon"], geo["lat"], geo["lon"])
                speed = dist_km / dt_hours
                if dist_km > 800.0 and speed > 900.0 and abs(ev.timestamp - prev_ts) <= 7200:
                    enr["impossible_travel"] = True
                    enr["travel_speed_kmh"] = round(speed, 1)
                    enr["previous_country"] = prev_geo["country"]
            if ev.event_outcome == "success":
                self._last_geo_by_actor[actor_key] = (ev.timestamp, geo)

        # 4. Threat intelligence (IP + URL/domain)
        ip_rep = self.lookup_ip_reputation(ev.source_ip)
        enr["ip_reputation_score"] = ip_rep["score"]
        enr["ip_malicious"] = ip_rep["malicious"]
        enr["ip_threat_category"] = ip_rep["category"]
        enr["ip_threat_feeds"] = ip_rep["feeds"]

        domain_rep_score = 0.0
        for dom, dinfo in THREAT_INTEL_DOMAINS.items():
            if (ev.url and dom in ev.url) or (ev.message and dom in ev.message):
                domain_rep_score = max(domain_rep_score, dinfo["score"])
                enr["domain_threat_category"] = dinfo["category"]
        enr["domain_reputation_score"] = domain_rep_score

        # 5. Customer context & state tracking (account age, recent beneficiary / device / phone changes)
        cust = self.customers.get(ev.customer_id or "")
        if cust:
            if not ev.account:
                ev.account = cust.account
                acc_ent = f"account:{cust.account}"
                if acc_ent not in ev.entities:
                    ev.entities.append(acc_ent)

            if ev.event_action == "beneficiary_added" and ev.event_outcome == "success":
                cust.beneficiary_changed_at = ev.timestamp
                if ev.counterparty_account:
                    cust.known_beneficiaries.add(ev.counterparty_account)
            elif ev.event_action == "device_changed" and ev.event_outcome == "success":
                cust.device_changed_at = ev.timestamp
                if ev.device_id:
                    cust.known_devices.add(ev.device_id)
            elif ev.event_action == "phone_changed" and ev.event_outcome == "success":
                cust.phone_changed_at = ev.timestamp

            recent_window = 1800.0  # 30 minutes
            recent_ben = (
                cust.beneficiary_changed_at is not None
                and 0 <= (ev.timestamp - cust.beneficiary_changed_at) <= recent_window
            )
            recent_dev = (
                cust.device_changed_at is not None
                and 0 <= (ev.timestamp - cust.device_changed_at) <= recent_window
            )
            recent_phone = (
                cust.phone_changed_at is not None
                and 0 <= (ev.timestamp - cust.phone_changed_at) <= recent_window
            )
            enr["customer_name"] = cust.full_name
            enr["customer_account"] = cust.account
            enr["customer_pan"] = cust.pan
            enr["customer_phone"] = cust.phone
            enr["customer_email"] = cust.email
            enr["account_age_days"] = cust.account_age_days
            enr["avg_transfer_amount"] = cust.avg_transfer_amount
            enr["amount_to_avg_ratio"] = round(ev.amount / max(cust.avg_transfer_amount, 1.0), 2) if ev.amount > 0 else 0.0
            enr["recent_beneficiary_change"] = recent_ben
            enr["recent_device_change"] = recent_dev
            enr["recent_phone_change"] = recent_phone
            enr["unrecognized_device"] = bool(ev.device_id and ev.device_id not in cust.known_devices)

        ev.enrichment = enr
        return ev
