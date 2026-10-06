// Behavioral string indicators. These are triage heuristics, not
// family signatures — each match is a reason to look closer, not a
// conviction on its own. meta.overlaps names a capability built from the
// same evidence (an imported API is also a string in the file); when that
// capability fired, the verdict does not count the rule a second time.

rule PowerShell_EncodedCommand : execution
{
    meta:
        description = "Embedded PowerShell with encoded/hidden execution flags"
        weight = 20
        attack = "T1059"
    strings:
        $ps = "powershell" ascii wide nocase
        // Bare "-enc" also sits inside "grpc-encoding", but Go and Rust pack
        // string literals with nothing between them ("...-NoProfile-enc"), so
        // requiring a separator would miss real encoded commands in exactly
        // those programs. Left as it is until lab rows show which strings fire.
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
        overlaps = "anti-recovery"
    strings:
        $vss = "vssadmin delete shadows" ascii wide nocase
        $wmic = "shadowcopy delete" ascii wide nocase
        // bcdedit only when it turns recovery off: "bcdedit /set" alone is how
        // installers enable Hyper-V or DEP.
        $bcd = /bcdedit(\.exe)?"?\s{1,4}[\/-]set\s[^\r\n]{0,40}(recoveryenabled|bootstatuspolicy)/ ascii wide nocase
        // the reboot into safe mode some ransomware runs before encrypting
        $bcd_safeboot = /bcdedit(\.exe)?"?\s{1,4}[\/-]set\s[^\r\n]{0,40}safeboot/ ascii wide nocase
        $wbadmin = "wbadmin delete catalog" ascii wide nocase
        // the same commands spelled with .exe (optionally quoted, full path)
        $vss_exe = /vssadmin\.exe"?\s{1,4}delete\s{1,4}shadows/ ascii wide nocase
        $wbadmin_exe = /wbadmin\.exe"?\s{1,4}delete\s{1,4}catalog/ ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Ransom_Note_Language : ransomware
{
    meta:
        description = "Ransom-note phrasing embedded in the binary"
        weight = 25
    strings:
        // What a note says about the victim's files. No phrase may contain
        // another, or one sentence would count as two.
        $note1 = "files have been encrypted" ascii wide nocase
        $note2 = "files are encrypted" ascii wide nocase
        $note3 = "decrypt your files" ascii wide nocase
        $note4 = "recover your files" ascii wide nocase
        $note5 = "network has been penetrated" ascii wide nocase
        // ...and how to pay. Alone these are in every browser and in Node.js
        // (crypto libraries, URL-scheme lists), and in forensic tools.
        $c = "bitcoin" ascii wide nocase
        $d = "decryption key" ascii wide nocase
        $e = "tor browser" ascii wide nocase
        // Go's TLS library says "unsupported decryption key type".
        $d_tls = "unsupported decryption key" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and 1 of ($note*) and
        (2 of ($note*) or 1 of ($c, $e) or #d > #d_tls)
}

rule Injection_API_Cluster : injection
{
    meta:
        description = "Classic remote-injection API trio referenced by name"
        weight = 15
        attack = "T1055"
        overlaps = "process-injection"
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
