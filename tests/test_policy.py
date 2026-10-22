from soccopilot.pipeline import DEFAULT_POLICY, SOCCopilot


def test_policy_file_drives_the_components(tmp_path):
    text = DEFAULT_POLICY.read_text(encoding="utf-8")
    text = text.replace('suppressed_ips = ["10.250.0.99"]', "suppressed_ips = []")
    text = text.replace("max_batch_size = 5000", "max_batch_size = 10")
    p = tmp_path / "policy.toml"
    p.write_text(text.split("allowed_actions")[0] + 'allowed_actions = ["notify_customer"]\n', encoding="utf-8")

    cp = SOCCopilot(policy_path=p)
    assert cp.correlator.suppressed_ips == set()          # empty means none, not the demo default
    assert cp.ingest_service.validator.max_batch_size == 10
    assert cp.playbooks.allowed_actions == {"notify_customer"}
    cp.reset()
    assert cp.ingest_service.validator.max_batch_size == 10  # a reset keeps the policy


def test_shipped_policy_matches_the_scoring_defaults():
    cp = SOCCopilot()
    assert cp.correlator.severity_weights == {"low": 12.0, "medium": 24.0, "high": 38.0, "critical": 52.0}
    assert cp.correlator.asset_criticality_weight == 3.0
