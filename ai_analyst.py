# ai_analyst.py

import os
import google.generativeai as genai
from dotenv import load_dotenv

# Load environment variables (your API key)
load_dotenv()

# Configure the Generative AI client
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel('gemini-2.5-flash')

async def generate_threat_report(alert_data: dict) -> str:
    """
    Takes the structured alert data and returns a
    human-readable threat report from the AI, including MITRE mapping.
    """
    
    # We'll serialize the first few events for the prompt
    event_preview = "\n".join(
        [f"- {item['type']}: {item['details']}" for item in alert_data['sequence'][:3]]
    )

    # Get key IPs
    attacker_ip = alert_data.get('attacker_ip', 'Unknown')
    victim_ip = "Internal Host" # Placeholder
    victim_port = ""
    try:
        details = alert_data['sequence'][0]['details']
        if 'to' in details:
            victim_str = details.split('to ')[1].split(' (')[0]
            if ':' in victim_str:
                victim_ip, victim_port = victim_str.split(':')
            else:
                victim_ip = victim_str
    except Exception:
        pass # Stick with defaults if parsing fails

    prompt = f"""
    You are 'NetSentinel Guardian,' a world-class cybersecurity AI analyst. 
    Your tone is professional, urgent, and insightful.

    **INCIDENT DATA:**
    - Incident ID: {alert_data['incident_id']}
    - Threat Score (0-100): {alert_data['threat_score']}
    - Primary Attacker IP: {attacker_ip}
    - Primary Target: {victim_ip} {f"(Port: {victim_port})" if victim_port else ""}
    - Initial Events Detected:
    {event_preview}

    **YOUR TASK (IN 2 PARTS):**

    **PART 1: THREAT REPORT**
    Generate a concise, 3-sentence threat report for an administrator.
    1.  **VERDICT:** Start with a bold verdict (e.g., "**Critical Threat:**").
    2.  **ANALYSIS:** In one sentence, explain *what is happening* and *why it's suspicious*. Be specific (e.g., "DNS tunneling," "lateral movement," "reconnaissance scan").
    3.  **RECOMMENDATION:** Provide one clear, actionable "Recommended First Step."

    **PART 2: MITRE ATT&CK MAPPING**
    Based *only* on the incident data, map the activity to the most relevant MITRE ATT&CK Tactic and Technique.
    Format this part *exactly* as follows:
    
    ---
    **MITRE ATT&CK Intel:**
    * **Tactic:** TXXXX - [Tactic Name]
    * **Technique:** TXXXX.XXX - [Technique Name]
    * **Reasoning:** [Brief 1-sentence explanation of why it maps]
    
    **EXAMPLE OF A FULL RESPONSE:**

    **Critical Threat:** An internal host is exhibiting C2 behavior. It's sending periodic, small UDP packets to an external IP, strongly suggesting a DNS tunneling-based backdoor. **Recommended First Step:** Immediately isolate host 10.0.9.179 from the network for forensic analysis.
    
    ---
    **MITRE ATT&CK Intel:**
    * **Tactic:** T1071 - Application Layer Protocol
    * **Technique:** T1071.004 - DNS
    * **Reasoning:** The use of DNS protocols for command and control or data exfiltration is a classic C2 technique.
    """

    try:
        response = await model.generate_content_async(prompt)
        return response.text.strip()
    except Exception as e:
        print(f"[AI Analyst Error]: {e}")
        return "AI analysis failed. Please review raw data."


async def generate_incident_playbook(alert_data: dict, ai_summary: str) -> str:
    """
    Generates a step-by-step incident response playbook using the AI.
    Takes the original alert data and the already-generated AI summary as input.
    """
    # Extract key details for the prompt
    attacker_ip = alert_data.get('attacker_ip', 'Unknown')
    victim_ip = "Internal Host"
    victim_port = ""
    mitre_tactic = "Unknown"
    mitre_technique = "Unknown"

    try:
        # Try to parse victim IP/Port from the first event
        details = alert_data['sequence'][0]['details']
        if 'to' in details:
            victim_str = details.split('to ')[1].split(' (')[0]
            if ':' in victim_str: victim_ip, victim_port = victim_str.split(':')
            else: victim_ip = victim_str
        
        # Try to parse MITRE info from the summary (split by '---')
        if "---" in ai_summary:
            mitre_section = ai_summary.split("---")[1]
            if "Tactic:" in mitre_section: mitre_tactic = mitre_section.split("Tactic:")[1].split("\n")[0].strip()
            if "Technique:" in mitre_section: mitre_technique = mitre_section.split("Technique:")[1].split("\n")[0].strip()
            
    except Exception as e:
        print(f"[AI Playbook Parser] Minor error parsing details: {e}")
        pass # Stick with defaults if parsing fails

    playbook_prompt = f"""
    You are 'NetSentinel Responder,' an expert incident response (IR) lead AI.
    An incident has been detected with the following details:

    **Incident Summary:**
    {ai_summary.split("---")[0].strip()} # Only the summary part

    **Key Details:**
    - Incident ID: {alert_data['incident_id']}
    - Threat Score: {alert_data['threat_score']}
    - Primary Attacker IP: {attacker_ip}
    - Primary Target: {victim_ip} {f"(Port: {victim_port})" if victim_port else ""}
    - MITRE Tactic: {mitre_tactic}
    - MITRE Technique: {mitre_technique}

    **YOUR TASK:**
    Generate a concise, step-by-step incident response playbook (3-5 numbered steps max) suitable for a system administrator. Focus on immediate actions for:
    1.  **Containment:** Stop the bleeding. Isolate affected systems. Block malicious IPs/Domains.
    2.  **Eradication:** Remove the threat actor/malware.
    3.  **Verification:** Confirm the threat is gone and systems are clean.

    **Format:** Use markdown numbered list. Be clear and direct.

    **Example Playbook:**
    1.  **Isolate Host:** Immediately remove host {victim_ip} from the network (unplug cable or disable network interface).
    2.  **Block Attacker:** Add a firewall rule to block all inbound and outbound traffic from/to IP address {attacker_ip}.
    3.  **Analyze & Clean:** Perform a full malware scan and forensic analysis on the isolated host {victim_ip}. Reimage if necessary.
    4.  **Monitor:** Closely monitor network traffic for any further signs of communication attempts from {attacker_ip} or similar activity from {victim_ip}.
    """

    try:
        print(f"[AI Playbook] Generating playbook for {alert_data['incident_id']}...")
        response = await model.generate_content_async(playbook_prompt)
        playbook_text = response.text.strip()
        print(f"[AI Playbook] Playbook generated successfully.")
        return playbook_text
    except Exception as e:
        print(f"[AI Playbook] Error generating playbook: {e}")
        return "Failed to generate incident response playbook."