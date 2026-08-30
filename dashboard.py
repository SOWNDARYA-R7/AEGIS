import json
import os
import streamlit as st
from agents import investigation_agent, threat_detection_agent, triage_agent
from graph_engine import graph_db
from verify import apply_mitigation, closed_loop_verification_agent

st.set_page_config(page_title="Autonomous Agentic SOC", layout="wide", page_icon="🛡️")

st.title("Autonomous SOC: Multi-Agent GraphRAG & Closed-Loop Response")

LOG_FILE = "access_logs.json"

col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("1. Real-time Log Ingestion & Triage")
    if st.button("Poll Latest Log & Run Pipeline"):
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r") as f:
                lines = [line.strip() for line in f.readlines() if line.strip()]

            valid_log = None
            # Extract the last valid JSON log (ignoring Flask text logs)
            for line in reversed(lines):
                try:
                    valid_log = json.loads(line)
                    break
                except Exception:
                    continue

            if valid_log:
                st.write("**Raw Log Captured:**")
                st.json(valid_log)

                # Agent 1: Triage
                triage_out = triage_agent(valid_log)
                st.write(f"**Triage Score:** {triage_out['risk_score']} / 10 | Escalate: `{triage_out['escalate']}`")

                if triage_out["escalate"]:
                    # Agent 2: Investigate
                    inv_out = investigation_agent(triage_out)
                    
                    # Agent 3: Threat Detection
                    detection_out = threat_detection_agent(inv_out)
                    st.session_state["current_detection"] = detection_out
            else:
                st.error("⚠️ No valid JSON attack logs found yet. Please hit the search API again.")
        else:
            st.error("Log file not found. Ensure app.py is running and you have visited the site.")

with col2:
    st.subheader("2. Agent Reasoning & GraphRAG Alignment")

    if "current_detection" in st.session_state:
        det = st.session_state["current_detection"]
        graph_res = det["graph_rag_result"]
        observed_payload = det["investigation"]["what"]["payload_observed"]

        if graph_res.get("found"):
            st.success(f"**Known MITRE Technique Detected:** {graph_res['technique']}")
            
            # Agent 4 & 5: Mitigation and Verification
            attacker_ip = det["investigation"]["who"]["source_ip"]
            st.warning(f"Initiating Autonomous Containment for IP: {attacker_ip}...")
            
            apply_mitigation(attacker_ip)
            verif = closed_loop_verification_agent(attacker_ip)

            st.write("---")
            st.subheader("3. Closed-Loop Verification")
            if verif["system_safe"]:
                st.success(verif["verification_report"])
            else:
                st.error(verif["verification_report"])

        else:
            st.error("⚠️ Novel / Zero-Day Pattern Detected! Not found in GraphRAG.")
            st.code(f"Observed Payload: {observed_payload}")

            # Human in the Loop (RLHF)
            st.write("### Human-in-the-Loop Feedback (RLHF)")
            h_col1, h_col2 = st.columns(2)

            with h_col1:
                if st.button("Approve Attack Pattern (+1 Reward)"):
                    update_res = graph_db.update_knowledge(observed_payload, is_malicious=True)
                    st.success(update_res)
                    st.info("Graph updated. Run the attack again to see autonomous blocking.")

            with h_col2:
                if st.button("Mark False Positive (-1 Penalty)"):
                    update_res = graph_db.update_knowledge(observed_payload, is_malicious=False)
                    st.info(update_res) 