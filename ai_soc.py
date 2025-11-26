import time
import json
import requests
import sys

# CONFIGURATION
# Replace this with your actual Windows Host IP where Ollama is running
OLLAMA_IP = "192.168.1.100" 
OLLAMA_PORT = "11434"
MODEL = "llama3" 

LOG_FILE = "/var/ossec/logs/alerts/alerts.json"

def analyze_alert(alert_json):
    print(f"\n[!] ALERT RECEIVED: {alert_json['rule']['description']}")
    
    # Extract key data
    agent_name = alert_json['agent']['name']
    file_path = alert_json['data']['win']['eventdata'].get('targetFilename', 'Unknown')
    process = alert_json['data']['win']['eventdata'].get('image', 'Unknown')
    
    # The Prompt for Llama 3
    prompt = f"""
    You are a Senior Level 3 SOC Analyst. Analyze this high-severity security alert:
    
    ALERT: Ransomware Behavior Detected
    HOST: {agent_name}
    PROCESS: {process}
    TARGET FILE: {file_path}
    MITRE TACTIC: Impact (Data Encrypted for Impact)
    
    Task:
    1. Explain why this behavior is dangerous.
    2. Suggest 3 immediate forensic steps to investigate the source.
    3. Generate a short Executive Summary for the CISO.
    """
    
    print("[-] Sending to AI Analyst (Llama 3)...")
    
    try:
        url = f"http://{OLLAMA_IP}:{OLLAMA_PORT}/api/generate"
        payload = {
            "model": MODEL,
            "prompt": prompt,
            "stream": False
        }
        
        response = requests.post(url, json=payload, timeout=30)
        ai_response = response.json()['response']
        
        print("\n" + "="*40)
        print("🤖 AI INCIDENT REPORT")
        print("="*40)
        print(ai_response)
        print("="*40)
        
        # Save to file
        with open("incident_report.md", "a") as f:
            f.write(f"\n\n# Alert: {alert_json['rule']['id']}\n{ai_response}")
            
    except Exception as e:
        print(f"[X] AI Error: {e}")

def monitor_logs():
    print(f"[*] AI SOC Analyst listening on {LOG_FILE}...")
    try:
        f = open(LOG_FILE, 'r')
        f.seek(0, 2) # Go to end of file
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
                
            try:
                data = json.loads(line)
                # Check if this is our Ransomware Rule (ID 100005)
                if data['rule']['id'] == '100005':
                    analyze_alert(data)
            except json.JSONDecodeError:
                continue
    except FileNotFoundError:
        print(f"[!] Error: Log file {LOG_FILE} not found. Are you running as root?")

if __name__ == "__main__":
    monitor_logs()
