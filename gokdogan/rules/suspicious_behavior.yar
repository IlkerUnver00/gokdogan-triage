// Behavioral string indicators. These are triage heuristics, not
// family signatures — each match is a reason to look closer, not a
// conviction on its own.

rule PowerShell_EncodedCommand : execution
{
    meta:
        description = "Embedded PowerShell with encoded/hidden execution flags"
        weight = 20
        attack = "T1059"
    strings:
        $ps = "powershell" ascii wide nocase
        $enc = "-enc" ascii wide nocase
        $hidden = "-windowstyle hidden" ascii wide nocase
        $bypass = "-executionpolicy bypass" ascii wide nocase
        $nop = "-noprofile" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and $ps and 2 of ($enc, $hidden, $bypass, $nop)
}

rule Shadow_Copy_Deletion : ransomware
{
    meta:
        description = "Commands that destroy Volume Shadow Copies / backups"
        weight = 30
        attack = "T1490"
    strings:
        $vss = "vssadmin delete shadows" ascii wide nocase
        $wmic = "shadowcopy delete" ascii wide nocase
        $bcd = "bcdedit /set" ascii wide nocase
        $wbadmin = "wbadmin delete catalog" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Ransom_Note_Language : ransomware
{
    meta:
        description = "Ransom-note phrasing embedded in the binary"
        weight = 25
    strings:
        $a = "your files have been encrypted" ascii wide nocase
        $b = "decrypt your files" ascii wide nocase
        $c = "bitcoin" ascii wide nocase
        $d = "decryption key" ascii wide nocase
        $e = "tor browser" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Injection_API_Cluster : injection
{
    meta:
        description = "Classic remote-injection API trio referenced by name"
        weight = 15
        attack = "T1055"
    strings:
        $a = "VirtualAllocEx" ascii
        $b = "WriteProcessMemory" ascii
        $c = "CreateRemoteThread" ascii
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule Discord_Webhook_Exfil : exfil
{
    meta:
        description = "Discord webhook URL (common low-effort exfil channel)"
        weight = 20
        attack = "T1048"
    strings:
        $hook = "discord.com/api/webhooks/" ascii wide nocase
        $hook2 = "discordapp.com/api/webhooks/" ascii wide nocase
    condition:
        any of them
}
