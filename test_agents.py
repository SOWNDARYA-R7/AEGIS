from agents import run_investigation_pipeline

if __name__ == "__main__":
    test_payload = "'; DROP TABLE users;--"
    test_endpoint = "/search"
    
    print(f"\n[!] Triggering AEGIS-X Multi-Agent Investigation on: {test_payload}\n")
    report = run_investigation_pipeline(test_payload, test_endpoint)
    
    print("\n" + "="*50)
    print("           FINAL SOC LEAD REPORT")
    print("="*50)
    print(report)
    