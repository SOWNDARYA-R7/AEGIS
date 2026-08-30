import networkx as nx

class MITREGraphEngine:
    def __init__(self):
        self.graph = nx.DiGraph()
        self._seed_mitre_knowledge()

    def _seed_mitre_knowledge(self):
        """Seed initial MITRE ATT&CK rules (Baseline Knowledge)"""
        # Tactics (High-level goals)
        self.graph.add_node("TA0001", name="Initial Access", type="Tactic")
        self.graph.add_node("TA0040", name="Impact", type="Tactic")

        # Techniques (How they do it)
        self.graph.add_node("T1190", name="Exploit Public-Facing App (SQLi/XSS)", type="Technique")
        self.graph.add_node("T1499", name="Endpoint Denial of Service", type="Technique")
        
        # Link Techniques to Tactics
        self.graph.add_edge("T1190", "TA0001", relation="SUBTECHNIQUE_OF")
        self.graph.add_edge("T1499", "TA0040", relation="SUBTECHNIQUE_OF")

        # Known Signatures (What it looks like)
        self.graph.add_node("SIG_SQLI_1", pattern="' OR '1'='1", type="Signature")
        self.graph.add_node("SIG_XSS_1", pattern="<script>", type="Signature")
        
        # Link Signatures to Techniques
        self.graph.add_edge("SIG_SQLI_1", "T1190", relation="INDICATES")
        self.graph.add_edge("SIG_XSS_1", "T1190", relation="INDICATES")

    def query_pattern(self, payload: str):
        """Searches the graph for known attack patterns."""
        payload_str = str(payload).lower()

        for node, data in self.graph.nodes(data=True):
            if data.get("type") == "Signature":
                pattern = data.get("pattern", "").lower()
                if pattern and pattern in payload_str:
                    # Traverse the graph to find the associated Technique
                    technique_node = list(self.graph.successors(node))[0]
                    technique_data = self.graph.nodes[technique_node]
                    return {
                        "found": True,
                        "technique": f"{technique_node} - {technique_data.get('name')}"
                    }

        return {"found": False, "status": "NOVEL_ATTACK_PATTERN"}

    def update_knowledge(self, pattern_signature: str, is_malicious: bool):
        """RLHF Engine: Dynamically updates the graph based on Human Feedback."""
        node_id = f"DYN_SIG_{abs(hash(pattern_signature)) % 10000}"

        if is_malicious:
            # Reward +1: Add to graph as a new attack pattern under T1190
            self.graph.add_node(node_id, pattern=pattern_signature, type="Signature", learned=True)
            self.graph.add_edge(node_id, "T1190", relation="LEARNED_INDICATOR")
            return f"Success: Learned new attack pattern '{pattern_signature}'."
        else:
            # Penalty -1: Whitelist it so it doesn't trigger alerts again
            self.graph.add_node(node_id, pattern=pattern_signature, type="Whitelist", learned=True)
            return f"Success: Marked '{pattern_signature}' as safe."

# Single global instance to be used by our agents
graph_db = MITREGraphEngine()
