import requests

def apply_mitigation(attacker_ip: str, base_url: str = "http://127.0.0.1:5000"):
    """Executes IP containment against the target web application."""
    try:
        res = requests.post(
            f"{base_url}/admin/block_ip", 
            json={"ip": attacker_ip},
            timeout=2
        )
        return res.status_code == 200
    except Exception as e:
        print(f"Mitigation failed to execute: {e}")
        return False

def closed_loop_verification_agent(attacker_ip: str, base_url: str = "http://127.0.0.1:5000") -> dict:
    """Probes the live target application to verify the threat isolation worked."""
    try:
        # Send a verification probe acting as the attacker
        headers = {"X-Forwarded-For": attacker_ip}
        response = requests.get(
            f"{base_url}/search?q=verification_ping",
            headers=headers,
            timeout=2,
        )

        # If target returns 403 Forbidden -> Threat is successfully neutralized
        if response.status_code == 403:
            return {
                "system_safe": True,
                "status_code": 403,
                "verification_report": f"Attacker IP ({attacker_ip}) confirmed ISOLATED. Perimeter is secure."
            }
        else:
            return {
                "system_safe": False,
                "status_code": response.status_code,
                "verification_report": "Threat still active! Endpoint is accessible from the flagged origin."
            }
    except Exception as err:
        return {"system_safe": False, "error": str(err)}