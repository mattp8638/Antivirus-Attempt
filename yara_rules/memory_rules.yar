/*
    TamsilCMS-Sentinel Memory Scanning Rules
    
    Detect in-memory threats, shellcode, and injected payloads
    Optimized for memory scanning with low false positive rate
    
    Author: TamsilCMS Security Team
    Date: 2026-02-10
    License: GNU-GPLv3
*/

// ==================== COBALT STRIKE DETECTION ====================

rule CobaltStrike_Beacon_Memory
{
    meta:
        description = "Cobalt Strike beacon in memory"
        author = "TamsilCMS Security"
        date = "2026-02-10"
        severity = "critical"
        mitre_attack = "T1055, T1071"
        category = "c2_framework"
    
    strings:
        $beacon1 = "%s.4%08x%08x%08x%08x%08x" wide ascii
        $beacon2 = "%02d/%02d/%02d %02d:%02d:%02d" wide ascii
        $beacon3 = "beacon.dll" wide ascii nocase
        $beacon4 = "ReflectiveLoader" wide ascii
        $config1 = "_NSAKEY" wide ascii
        $config2 = "MSSE-" wide ascii
        $pipe1 = "\\\\.\\pipe\\MSSE-" wide ascii
        $http1 = "User-Agent: " wide ascii
        $http2 = "Accept: */*" wide ascii
    
    condition:
        2 of ($beacon*) or
        ($config1 and $pipe1) or
        (3 of them)
}

rule CobaltStrike_Stager
{
    meta:
        description = "Cobalt Strike stager shellcode"
        author = "TamsilCMS Security"
        severity = "critical"
        mitre_attack = "T1055, T1059"
    
    strings:
        $mz = "MZ"
        $stack1 = { 6A 40 68 00 30 00 00 }  // push 0x40; push 0x3000
        $stack2 = { 68 00 00 40 00 }          // push 0x400000
        $http = "http" wide ascii nocase
        $resolve = { FF D? 89 ?? ?? }         // call reg; mov
    
    condition:
        $mz at 0 and
        2 of ($stack*, $http, $resolve)
}

// ==================== METASPLOIT DETECTION ====================

rule Metasploit_Meterpreter_Memory
{
    meta:
        description = "Metasploit Meterpreter in memory"
        author = "TamsilCMS Security"
        severity = "critical"
        mitre_attack = "T1055, T1071"
        category = "c2_framework"
    
    strings:
        $meterpreter = "meterpreter" wide ascii nocase
        $stdapi = "stdapi_" wide ascii
        $extserver = "ext_server_" wide ascii
        $reflective = "ReflectiveDll" wide ascii
        $core = "core_" wide ascii
        $channel = "_channel_" wide ascii
        $transport = "transport_" wide ascii
    
    condition:
        3 of them
}

rule Metasploit_Reverse_Shell
{
    meta:
        description = "Metasploit reverse shell payload"
        author = "TamsilCMS Security"
        severity = "critical"
    
    strings:
        $shell = "cmd.exe" wide ascii nocase
        $socket = { 68 02 00 ?? ?? }  // push dword (port)
        $wsastartup = "WSAStartup" wide ascii
        $wsasocket = "WSASocketA" wide ascii
        $connect = "connect" wide ascii
    
    condition:
        $shell and 3 of ($socket, $wsastartup, $wsasocket, $connect)
}

// ==================== PROCESS INJECTION ====================

rule ProcessInjection_Shellcode
{
    meta:
        description = "Generic process injection shellcode"
        author = "TamsilCMS Security"
        severity = "high"
        mitre_attack = "T1055"
    
    strings:
        // Common shellcode patterns
        $nop = { 90 90 90 90 90 90 90 90 90 90 }
        $peb1 = { 64 8B ?? 30 }        // mov reg, fs:[30h] (PEB)
        $peb2 = { 64 A1 30 00 00 00 }  // mov eax, fs:[30h]
        $getproc = { 8B ?? 18 8B ?? 0C }  // GetProcAddress walking
        $virtualalloc = "VirtualAlloc" wide ascii
        $virtualallocex = "VirtualAllocEx" wide ascii
        $createremotethread = "CreateRemoteThread" wide ascii
        $writeprocessmemory = "WriteProcessMemory" wide ascii
    
    condition:
        $nop and ($peb1 or $peb2) and $getproc or
        2 of ($virtualalloc, $virtualallocex, $createremotethread, $writeprocessmemory)
}

rule ReflectiveDLLInjection
{
    meta:
        description = "Reflective DLL injection detected"
        author = "TamsilCMS Security"
        severity = "critical"
        mitre_attack = "T1055.001"
    
    strings:
        $mz = "MZ"
        $pe = "PE" 
        $reflective1 = "ReflectiveLoader" wide ascii
        $reflective2 = "_ReflectiveLoader@" wide ascii
        $export = { 45 78 70 6F 72 74 }  // "Export"
        $getproc = "GetProcAddress" wide ascii
        $loadlib = "LoadLibrary" wide ascii
        $virtualalloc = "VirtualAlloc" wide ascii
    
    condition:
        $mz at 0 and $pe and
        ($reflective1 or $reflective2) and
        2 of ($getproc, $loadlib, $virtualalloc)
}

// ==================== CREDENTIAL THEFT ====================

rule Mimikatz_Memory
{
    meta:
        description = "Mimikatz in memory"
        author = "TamsilCMS Security"
        severity = "critical"
        mitre_attack = "T1003.001"
        category = "credential_theft"
    
    strings:
        $str1 = "mimikatz" wide ascii nocase
        $str2 = "sekurlsa" wide ascii nocase
        $str3 = "kerberos" wide ascii nocase
        $str4 = "lsadump" wide ascii nocase
        $str5 = "wdigest" wide ascii nocase
        $str6 = "::logonpasswords" wide ascii nocase
        $str7 = "privilege::debug" wide ascii nocase
        $func1 = "KerbQueryTicketCacheEx2Message" wide ascii
        $func2 = "SspCredentialsSave" wide ascii
    
    condition:
        3 of ($str*) or
        ($str1 and 1 of ($func*))
}

rule LSASS_Dump_Memory
{
    meta:
        description = "LSASS memory dump indicators"
        author = "TamsilCMS Security"
        severity = "critical"
        mitre_attack = "T1003.001"
    
    strings:
        $lsass = "lsass.exe" wide ascii nocase
        $dump = "MiniDumpWriteDump" wide ascii
        $process = "OpenProcess" wide ascii
        $handle = "DuplicateHandle" wide ascii
        $sec1 = "SeDebugPrivilege" wide ascii
        $sec2 = "SeTcbPrivilege" wide ascii
    
    condition:
        $lsass and ($dump or ($process and 1 of ($sec*)))
}

// ==================== FILELESS MALWARE ====================

rule PowerShell_Reflective_Injection
{
    meta:
        description = "PowerShell reflective injection"
        author = "TamsilCMS Security"
        severity = "high"
        mitre_attack = "T1059.001, T1055"
    
    strings:
        $ps1 = "System.Reflection.Assembly" wide ascii
        $ps2 = "System.Runtime.InteropServices" wide ascii
        $ps3 = "VirtualAlloc" wide ascii
        $ps4 = "CreateThread" wide ascii
        $ps5 = "Marshal" wide ascii
        $ps6 = "[DllImport" wide ascii
        $decode1 = "FromBase64String" wide ascii
        $decode2 = "Decompress" wide ascii
    
    condition:
        3 of ($ps*) and 1 of ($decode*)
}

rule Fileless_Malware_Generic
{
    meta:
        description = "Generic fileless malware patterns"
        author = "TamsilCMS Security"
        severity = "high"
    
    strings:
        // High entropy data (likely encrypted payload)
        $entropy = /[\x00-\xFF]{200,}/ // Will check entropy separately
        
        // Download and execute patterns
        $download1 = "DownloadString" wide ascii
        $download2 = "DownloadData" wide ascii
        $download3 = "WebClient" wide ascii
        $exec1 = "IEX" wide ascii
        $exec2 = "Invoke-Expression" wide ascii
        $exec3 = "iex" wide ascii
        
        // Memory allocation
        $alloc1 = "VirtualAlloc" wide ascii
        $alloc2 = "VirtualProtect" wide ascii
        $alloc3 = "HeapAlloc" wide ascii
    
    condition:
        (1 of ($download*) and 1 of ($exec*)) or
        (2 of ($alloc*))
}

// ==================== SHELLCODE DETECTION ====================

rule Shellcode_Common_Patterns
{
    meta:
        description = "Common shellcode patterns"
        author = "TamsilCMS Security"
        severity = "high"
    
    strings:
        // NOP sled
        $nop = { 90 90 90 90 90 90 90 90 90 90 90 90 }
        
        // Register initialization
        $xor_eax = { 31 C0 }  // xor eax, eax
        $xor_ecx = { 31 C9 }  // xor ecx, ecx
        $xor_edx = { 31 D2 }  // xor edx, edx
        
        // PEB access
        $fs_access1 = { 64 8B ?? 30 }  // mov reg, fs:[30h]
        $fs_access2 = { 64 A1 30 00 00 00 }  // mov eax, fs:[30h]
        
        // Stack operations
        $stack_pivot = { 54 59 5A 5B }  // push esp; pop ecx; pop edx; pop ebx
        
        // GetProcAddress walking
        $getproc = { 8B ?? 18 8B ?? 0C }  // PEB->Ldr walking
    
    condition:
        ($nop and 2 of ($xor*, $fs_access*, $stack_pivot, $getproc)) or
        (3 of ($xor*, $fs_access*, $getproc))
}

rule Shellcode_DownloadExecute
{
    meta:
        description = "Shellcode with download and execute capability"
        author = "TamsilCMS Security"
        severity = "critical"
    
    strings:
        $http = "http" wide ascii nocase
        $wininet = "wininet" wide ascii nocase
        $urlmon = "urlmon" wide ascii nocase
        $download = "URLDownloadToFile" wide ascii
        $exec = { FF D? }  // call reg
        $socket = { 68 02 00 }  // push 2 (AF_INET)
    
    condition:
        (($http or $wininet or $urlmon) and ($download or $exec)) or
        $socket
}

// ==================== RANSOMWARE ====================

rule Ransomware_Encryption_Loop
{
    meta:
        description = "Ransomware encryption loop in memory"
        author = "TamsilCMS Security"
        severity = "critical"
        mitre_attack = "T1486"
    
    strings:
        // File enumeration
        $find1 = "FindFirstFile" wide ascii
        $find2 = "FindNextFile" wide ascii
        
        // Encryption APIs
        $crypt1 = "CryptEncrypt" wide ascii
        $crypt2 = "CryptGenKey" wide ascii
        $crypt3 = "BCryptEncrypt" wide ascii
        
        // File operations
        $file1 = "CreateFile" wide ascii
        $file2 = "WriteFile" wide ascii
        $file3 = "DeleteFile" wide ascii
        
        // Common extensions
        $ext1 = ".encrypted" wide ascii
        $ext2 = ".locked" wide ascii
        $ext3 = ".crypto" wide ascii
    
    condition:
        (1 of ($find*) and 1 of ($crypt*) and 2 of ($file*)) or
        (2 of ($crypt*) and 1 of ($ext*))
}

// ==================== PERSISTENCE ====================

rule Persistence_RunKey_Injection
{
    meta:
        description = "Registry Run key modification in memory"
        author = "TamsilCMS Security"
        severity = "medium"
        mitre_attack = "T1547.001"
    
    strings:
        $reg1 = "RegCreateKey" wide ascii
        $reg2 = "RegSetValue" wide ascii
        $reg3 = "RegOpenKey" wide ascii
        $run1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide ascii
        $run2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide ascii
    
    condition:
        (1 of ($reg*)) and (1 of ($run*))
}
