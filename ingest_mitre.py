import requests
from neo4j import GraphDatabase

# Neo4j Connection - Update your password here!
URI = "neo4j://127.0.0.1:7687"
AUTH = ("neo4j", "Sound#777")

# Official MITRE STIX JSON Source
MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

def ingest_mitre_graph():
    print("1. Downloading latest MITRE ATT&CK data from GitHub... (This takes a few seconds)")
    response = requests.get(MITRE_URL)
    data = response.json()
    objects = data.get("objects", [])

    # Filter out exactly what we need for the SOC
    techniques = [obj for obj in objects if obj.get("type") == "attack-pattern"]
    tactics = [obj for obj in objects if obj.get("type") == "x-mitre-tactic"]

    print(f"Downloaded {len(tactics)} Tactics and {len(techniques)} Techniques.")
    print("2. Connecting to Neo4j and building the GraphRAG...")

    driver = GraphDatabase.driver(URI, auth=AUTH)

    with driver.session() as session:
        # Clear any existing junk for a clean slate
        session.run("MATCH (n) DETACH DELETE n")

        # Create Tactic Nodes (The attacker's high-level goals)
        for tac in tactics:
            session.run('''
                MERGE (t:Tactic {id: $id})
                SET t.name = $name, t.description = $desc, t.shortname = $shortname
            ''', id=tac.get("id"), name=tac.get("name"), desc=tac.get("description", ""), shortname=tac.get("x_mitre_shortname"))

        # Create Technique Nodes (How the attacker achieves the goals)
        for tech in techniques:
            ext_refs = tech.get("external_references", [])
            tech_id = ext_refs[0]["external_id"] if ext_refs else "Unknown"

            session.run('''
                MERGE (t:Technique {id: $id})
                SET t.name = $name, t.description = $desc, t.mitre_id = $mitre_id
            ''', id=tech.get("id"), name=tech.get("name"), desc=tech.get("description", ""), mitre_id=tech_id)

            # Map Techniques to Tactics using the Kill Chain Phases
            for phase in tech.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    session.run('''
                        MATCH (tech:Technique {id: $tech_id})
                        MATCH (tac:Tactic {shortname: $tactic_shortname})
                        MERGE (tech)-[:SUBTECHNIQUE_OF]->(tac)
                    ''', tech_id=tech.get("id"), tactic_shortname=phase.get("phase_name"))

        print("3. Success! MITRE Knowledge Graph is now live in Neo4j.")

    driver.close()

if __name__ == "__main__":
    try:
        ingest_mitre_graph()
    except Exception as e:
        print(f"Error connecting to Neo4j or parsing data: {e}")