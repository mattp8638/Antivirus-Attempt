/*
 * TamsilCMS-Sentinel - Master YARA Rules Index
 * 
 * This file includes all YARA rules for comprehensive security scanning
 * across the TamsilCMS-Enterprise platform.
 * 
 * Auto-generated: 2026-02-10
 * Maintained by: TamsilCMS Security Team
 * License: GNU-GPLv2
 * 
 * Rule Categories:
 * - Ransomware (Locky, Petya, WannaCry, Generic patterns)
 * - Banking Trojans (Emotet, TrickBot, Dridex, Qakbot, Zeus, Gozi)
 * - Infostealers (AgentTesla, Azorult, FormBook, Raccoon)
 * - Webshells (PHP, ASP, JSP, China Chopper, b374k, WSO, r57shell)
 * - Credential Theft (Mimikatz, LSASS dumping, Kerberoasting, DCSync)
 * - Execution Techniques (PowerShell, fileless, LOLBins, macro abuse)
 * - Lateral Movement (PsExec, WMI, RDP tunneling)
 * - Persistence (Registry, Scheduled Tasks)
 * 
 * Usage:
 *   Compile: yarac master_rules.yar compiled_rules.yarc
 *   Scan:    yara master_rules.yar /path/to/scan
 *   Recursive: yara -r master_rules.yar /path/to/scan
 */

// ==================== MALWARE RULES ====================
include "./malware/ransomware_comprehensive.yar"
include "./malware/banking_trojans.yar"
include "./malware/webshells.yar"
include "./malware/credential_theft.yar"
include "./malware/execution_techniques.yar"

// ==================== EXPLOIT RULES ====================
// Include exploit rules when available
// include "./exploit/*.yar"
