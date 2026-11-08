/*
 * AetherEDR built-in detection rules.
 * Public, well-documented indicators only. Expect false positives from security tooling
 * (rule text sits in the memory of any process that loaded these rules, including AetherEDR
 * itself - the scanner excludes its own PID).
 */

rule AetherEDR_SelfTest
{
    meta:
        description = "Harmless marker used by `python -m edr.selftest` to prove memory scanning works"
        severity = "low"
    strings:
        $m = "AETHEREDR_YARA_SELFTEST_MARKER_7f3a" ascii
    condition:
        $m
}

rule Reflective_PE_In_Memory
{
    meta:
        description = "PE header with an exported ReflectiveLoader: reflectively loaded DLL (Metasploit, Cobalt Strike, others)"
        severity = "high"
        technique = "T1620"
    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }
        $rl = "ReflectiveLoader" ascii
    condition:
        $mz at 0 and $pe and $rl
}

rule Meterpreter_Strings
{
    meta:
        description = "Strings associated with the Metasploit Meterpreter payload"
        severity = "high"
        technique = "T1059"
    strings:
        $a = "metsrv.dll" ascii nocase
        $b = "stdapi_" ascii
        $c = "core_channel_open" ascii
        $d = "PACKET_TLV_TYPE" ascii
    condition:
        2 of them
}

rule CobaltStrike_Beacon_Indicators
{
    meta:
        description = "Default Cobalt Strike beacon artefacts (named pipe patterns and config format strings)"
        severity = "critical"
        technique = "T1071.001"
    strings:
        $p1 = "\\\\.\\pipe\\msagent_" ascii wide
        $p2 = "\\\\.\\pipe\\postex_" ascii wide
        $p3 = "\\\\.\\pipe\\MSSE-" ascii wide
        $f1 = "%s as %s\\%s: %d" ascii
        $f2 = "beacon.dll" ascii
        $f3 = "beacon.x64.dll" ascii
    condition:
        2 of them
}

rule Mimikatz_Strings
{
    meta:
        description = "Mimikatz command and banner strings"
        severity = "critical"
        technique = "T1003.001"
    strings:
        $a = "sekurlsa::logonpasswords" ascii wide nocase
        $b = "gentilkiwi" ascii wide
        $c = "mimikatz" ascii wide nocase
        $d = "kerberos::golden" ascii wide nocase
    condition:
        2 of them
}

rule Shellcode_x64_API_Hash_Stub
{
    meta:
        description = "Common x64 stager prologue (CLD; AND RSP,-16; CALL) used by Metasploit-style shellcode"
        severity = "medium"
        technique = "T1055"
    strings:
        $s1 = { FC 48 83 E4 F0 E8 }
        $s2 = { FC E8 82 00 00 00 60 89 E5 31 C0 64 8B 50 30 }   // x86 block_api stub
    condition:
        any of them
}

rule Linux_Reverse_Shell_Strings
{
    meta:
        description = "Reverse-shell one-liner fragments present in process memory"
        severity = "medium"
        technique = "T1059.004"
    strings:
        $a = "/dev/tcp/" ascii
        $b = "bash -i >&" ascii
        $c = "0<&196;exec 196<>/dev/tcp" ascii
    condition:
        ($a and $b) or $c
}

rule Packed_Or_Injected_ELF_In_Memory
{
    meta:
        description = "ELF header at the start of a scanned memory chunk (memory scans only)"
        severity = "low"
        technique = "T1620"
    strings:
        $elf = { 7F 45 4C 46 02 01 01 }
    condition:
        $elf at 0 and scan_source == "memory"
}
