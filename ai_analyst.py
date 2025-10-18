# ai_analyst.py
import random
import os
import google.generativeai as genai
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure the Generative AI client
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel('gemini-2.5-flash') # Fast and effective

async def generate_threat_report(alert_data: dict) -> str:
    """
    Takes the structured alert data and returns a
    human-readable threat report from the AI.
    """
    
    # We'll serialize the sequence for the prompt
    sequence_str = "\n".join(
        [f"- At {item['timestamp']}: {item['type']} ({item['details']})" for item in alert_data['sequence']]
    )

    prompt = f"""
    You are 'NetSentinel Guardian,' a world-class cybersecurity analyst. 
    Based on the following structured incident data, write a concise, human-readable threat report for a busy administrator.

    **Incident Data:**
    - Incident ID: {alert_data['incident_id']}
    - Threat Score (0-100): {alert_data['threat_score']}
    - Main Event Type: {alert_data['main_event']}
    - Event Sequence:
    {sequence_str}

    **Your Task:**
    Generate a 2-3 sentence report. 
    1. Start with a clear verdict (e.g., "Critical Threat," "Suspicious Activity").
    2. Briefly explain what is happening (the story).
    3. State the most logical "Recommended First Step."
    
    Example:
    "Critical Threat: We've detected a high-probability data exfiltration attempt. The attacker performed a port scan, attempted an RDP connection, and is now sending a steady data stream to an unknown IP. Recommended First Step: Immediately block the source IP 1.2.3.4 at the firewall."
    """

    try:
        response = await model.generate_content_async(prompt)
        return response.text.strip()
    except Exception as e:
        print(f"[AI Analyst Error]: {e}")
        return "AI analysis failed. Please review raw data."# ai_analyst.py

import os
import google.generativeai as genai
from dotenv import load_dotenv

# Load environment variables 
load_dotenv()

# Configure the Generative AI client
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel('gemini-2.5-flash') # Fast and effective

async def generate_threat_report(alert_data: dict) -> str:
    """
    Takes the structured alert data and returns a
    human-readable threat report from the AI.
    """
    
    # We'll serialize the sequence for the prompt
    sequence_str = "\n".join(
        [f"- At {item['timestamp']}: {item['type']} ({item['details']})" for item in alert_data['sequence']]
    )

    prompt = f"""
    You are 'NetSentinel Guardian,' a world-class cybersecurity analyst. 
    Based on the following structured incident data, write a concise, human-readable threat report for a busy administrator.

    **Incident Data:**
    - Incident ID: {alert_data['incident_id']}
    - Threat Score (0-100): {alert_data['threat_score']}
    - Main Event Type: {alert_data['main_event']}
    - Event Sequence:
    {sequence_str}

    **Your Task:**
    Generate a 2-3 sentence report. 
    1. Start with a clear verdict (e.g., "Critical Threat," "Suspicious Activity").
    2. Briefly explain what is happening (the story).
    3. State the most logical "Recommended First Step."
    
    Example:
    "Critical Threat: We've detected a high-probability data exfiltration attempt. The attacker performed a port scan, attempted an RDP connection, and is now sending a steady data stream to an unknown IP. Recommended First Step: Immediately block the source IP 1.2.3.4 at the firewall."
    """

    try:
        response = await model.generate_content_async(prompt)
        return response.text.strip()
    except Exception as e:
        print(f"[AI Analyst Error]: {e}")
        return "AI analysis failed. Please review raw data."