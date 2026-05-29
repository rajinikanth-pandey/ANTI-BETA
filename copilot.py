import os
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

client = Groq(
    api_key=os.getenv("GROQ_API_KEY")
)


def generate_copilot_insights(results):
    rollback = results["rollback"]
    covert = results["covert"]
    stealth = results["stealth"]
    hook = results["hook"]
    rootkit = results["rootkit"]
    fragmentation = results["fragmentation"]
    masquerade = results["masquerade"]
    secure_boot = results["secure_boot"]
    integrity = results["integrity"]

    insights = {
        "assistant_name": "ANTI-BETA",

        "threat_triage": [
            f"Highest-confidence compromise indicators are observed in rootkit ({rootkit['confidence']}), secure boot ({secure_boot['confidence']}), and rollback ({rollback['confidence']}) modules.",
            f"Most likely persistence mechanism involves {rootkit['reason']} combined with {hook['reason']} and rollback weakness.",
            "Immediate reverse-engineering escalation is required for vector-table anomalies, callback dispatch surfaces, and secure boot pre-validation logic.",
            "Current evidence strongly favors stealth persistence over accidental corruption due to baseline deviation and persistence surface overlap."
        ],

        "binary_mutation_analysis": [
            f"Most suspicious regions are tied to {results['region_analysis']} and fragmentation score of {fragmentation['cluster_count']} clusters.",
            f"Mutation clustering pattern suggests {results['cluster_analysis']} with staged patch-like spread.",
            "Current byte mutation behavior resembles erase-and-rewrite followed by fragmented hot patching.",
            "Fragmented payload insertion is likely due to multi-cluster mutation distribution across stealth deviation zones."
        ],

        "anti_forensics_behavior": [
            f"Rollback bypass indicators: {rollback['reason']}",
            f"Secure boot weakening evidence: {secure_boot['reason']}",
            f"Integrity neutralization indicators: {integrity['reason']}",
            f"Untouched regions may still hide stealth payloads due to {stealth['reason']}"
        ],

        "persistence_rootkit": [
            f"Hookable syscall / interrupt surfaces detected: {hook['reason']}",
            "Likely to survive partial reflashing due to persistence overlap with stealth baseline drift.",
            f"Rootkit persistence beyond changed offsets is supported by: {rootkit['reason']}",
            "Priority dump targets: vector table, reset handler region, callback dispatch tables, flashfs shadow regions."
        ],

        "covert_masquerade": [
            f"Covert signaling indicators: {covert['reason']}",
            f"Masquerade behavior: {masquerade['reason']}",
            "Telemetry, calibration, and sensor abstraction routines should be reverse-mapped first.",
            "Timing drift + metadata dead space should be inspected for hidden command signaling."
        ],

        "analyst_actionables": [
            "1) Dump vector table and verify reset handler integrity.",
            "2) Diff callback dispatch tables against trusted Betaflight build.",
            "3) Trace flashfs, blackbox, and reserved config pages.",
            "4) Validate rollback counters, build metadata, and version anchors.",
            "5) Perform emulated boot trace to observe hidden telemetry or staged payload activation."
        ]
    }

    return insights


def generate_llm_analysis(results):
    """
    Uses Groq Llama model for deep firmware DFIR reasoning.
    """
    prompt = f"""
You are ANTI-BETA, an elite drone firmware anti-forensics copilot.

Analyze the detector outputs below and answer in highly technical,
point-wise DFIR analyst format.

Detector Results:
{results}

Answer the following:
1. Threat Triage & Prioritization
2. Binary Mutation Analysis
3. Anti-Forensics Behavior
4. Persistence & Rootkit Questions
5. Covert Channel & Masquerade
6. Analyst Next 5 Steps

Make the reasoning deep, forensic, and highly actionable.
"""

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "system",
                    "content": "You are ANTI-BETA, a firmware DFIR copilot."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.3,
            max_tokens=1800
        )

        return response.choices[0].message.content

    except Exception as e:
        return f"ANTI-BETA LLM analysis unavailable: {str(e)}"
    
def generate_chat_response(results, user_message):
    """
    Ultra-fast ANTI-BETA conversational mode.
    Uses compact detector context to avoid token overflow.
    """

    compact_context = {
        "total_changes": results.get("total_changes"),
        "mass_erase_regions": results.get("mass_erase_regions"),
        "rollback": results.get("rollback", {}).get("reason"),
        "rootkit": results.get("rootkit", {}).get("reason"),
        "secure_boot": results.get("secure_boot", {}).get("reason"),
        "integrity": results.get("integrity", {}).get("reason"),
        "stealth": results.get("stealth", {}).get("reason"),
        "covert": results.get("covert", {}).get("reason"),
        "hook": results.get("hook", {}).get("reason"),
    }

    prompt = f"""
You are ANTI-BETA, a fast firmware DFIR chat assistant.

Compact firmware findings:
{compact_context}

User question:
{user_message}

Answer conversationally like ChatGPT.
Keep it direct, technical, and actionable.
"""

    try:
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {
                    "role": "system",
                    "content": "You are ANTI-BETA firmware security chat mode."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.4,
            max_tokens=500
        )

        return response.choices[0].message.content

    except Exception as e:
        return f"ANTI-BETA chat unavailable: {str(e)}"