"""Streamlit Analyst Console for SOC Copilot (`streamlit run app.py` or `streamlit run soccopilot/app.py`)."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from soccopilot.evaluate import run_evaluation, seed_demo_copilot


def render_app() -> None:
    st.set_page_config(page_title="SOC Copilot · Digital Bank", layout="wide")
    st.title("SOC Copilot for a Digital Bank")
    st.caption(
        "Ingest · Normalise (ECS) · Enrich · Detect (Sigma + Baselines) · Correlate (Security + Fraud Entity Graph) "
        "· AI Triage (Privacy-Scrubbed Read-Only Tool Loop) · Respond (Call-Bound Playbook Approvals) · Hash-Chained Audit"
    )

    if "copilot" not in st.session_state:
        st.session_state.copilot = seed_demo_copilot()

    cp = st.session_state.copilot

    with st.sidebar:
        st.subheader("Controls")
        if st.button("Reset & Re-seed Demo"):
            st.session_state.copilot = seed_demo_copilot()
            cp = st.session_state.copilot
            st.rerun()
        ok_chain, chain_msg = cp.audit.verify()
        st.metric("Events in DuckDB", cp.event_store.count())
        st.metric("Active Alerts", len(cp.alerts))
        st.metric("Correlated Incidents", len(cp.incidents))
        st.write(f"**Audit Chain:** {'✅ ' if ok_chain else '❌ '}{chain_msg}")

    tab_inc, tab_actions, tab_eval, tab_audit = st.tabs([
        "1 · Incident Queue & AI Triage",
        "2 · Playbook Approvals & Connectors",
        "3 · Benchmark Evaluation",
        "4 · Source Health & Audit Trail",
    ])

    with tab_inc:
        incs = sorted(cp.incidents.values(), key=lambda x: (-x.risk_score, x.created_at))
        if not incs:
            st.info("No active incidents.")
        else:
            q_rows = [
                {
                    "ID": i.incident_id,
                    "Severity": i.severity.upper(),
                    "Score": i.risk_score,
                    "Title": i.title,
                    "Sec+Fraud": "YES" if i.security_fraud_joined else "no",
                    "Money at Risk (₹)": f"₹{i.money_at_risk:,.0f}",
                    "Tactics": " → ".join(i.tactics),
                    "Status": i.status,
                }
                for i in incs
            ]
            st.dataframe(pd.DataFrame(q_rows), use_container_width=True, hide_index=True)

            sel_id = st.selectbox("Inspect Incident", [i.incident_id for i in incs])
            inc = cp.incidents[sel_id]
            rep = cp.state_store.get_report(sel_id) or cp.triage_engine.triage_incident(inc, use_llm=False).to_dict()

            c1, c2 = st.columns([1.3, 1.0])
            with c1:
                st.subheader(f"{inc.incident_id}: {inc.title}")
                st.markdown(f"**AI Triage Summary** *(Citation Coverage: {rep['citation_coverage']*100:.0f}% · Mode: `{rep['generated_by']}`)*")
                st.info(rep["summary"])
                st.markdown("**Likely Impact**")
                for imp in rep.get("likely_impact", []):
                    st.markdown(f"- {imp}")
                st.markdown("**ATT&CK Storyline Timeline**")
                for step in rep.get("timeline", []):
                    st.code(step, language="text")

            with c2:
                st.subheader("Entity Graph & Risk Breakdown")
                st.json(inc.score_breakdown)
                st.markdown("**Linked Entities**")
                st.write(", ".join(f"`{e}`" for e in inc.entities))
                st.markdown("**Privacy Gateway Masking (Before LLM)**")
                st.json(rep.get("privacy_masked_counts", {}))

                st.subheader("Analyst Feedback (Tunes Rule Weights)")
                verdict = st.radio("Verdict", ["true_positive", "false_positive"], horizontal=True, key=f"v_{sel_id}")
                reason = st.text_input("Reason", value="Verified multi-stage evidence", key=f"r_{sel_id}")
                if st.button("Submit Feedback", key=f"fb_{sel_id}"):
                    fb = cp.correlator.record_feedback(inc, verdict, reason)
                    cp.state_store.save_incident(inc)
                    st.success(f"Updated score to {inc.risk_score}; tuned weights: {fb['updated_rule_weights']}")

    with tab_actions:
        st.subheader("Proposed Containment Actions (Single-Use SHA-256 Call-Bound Approvals)")
        actions = cp.playbooks.list_actions()
        for act in actions:
            cols = st.columns([3, 2, 1, 1])
            cols[0].markdown(f"**`{act['action_type']}`** → `{act['target']}` ({act['incident_id']})\n\n{act['rationale']}")
            cols[1].code(f"Status: {act['status']}\nSHA256: {act['digest'][:16]}...")
            if act["status"] == "pending":
                if cols[2].button("Approve", key=f"ap_{act['action_id']}"):
                    cp.playbooks.decide_and_run(act["action_id"], approve=True, analyst="soc.streamlit")
                    st.rerun()
                if cols[3].button("Decline", key=f"dc_{act['action_id']}"):
                    cp.playbooks.decide_and_run(act["action_id"], approve=False, analyst="soc.streamlit")
                    st.rerun()

    with tab_eval:
        st.subheader("Benchmark against 6 Labelled Multi-Stage Campaigns + Normal Day Traffic")
        res = run_evaluation()
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Detection Recall", f"{res['detection_recall']*100:.0f}%")
        m2.metric("False-Positive Incidents/Day", str(res["false_positive_incidents_per_day"]))
        m3.metric("Mean Batch Latency", f"{res['mean_batch_latency_ms']:.0f} ms")
        m4.metric("Cited Evidence Coverage", f"{res['report_citation_coverage']*100:.0f}%")
        st.dataframe(pd.DataFrame(res["campaigns"]), use_container_width=True, hide_index=True)

    with tab_audit:
        st.subheader("Per-Source Health Monitor")
        st.dataframe(pd.DataFrame(list(cp.ingest_service.health.check_health().values())), use_container_width=True, hide_index=True)
        st.subheader("Hash-Chained Audit Log")
        st.dataframe(pd.DataFrame(cp.audit.entries[::-1]), use_container_width=True, hide_index=True)


if __name__ == "__main__":
    render_app()
