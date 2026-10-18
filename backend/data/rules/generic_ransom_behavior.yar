/*
 * RansomShield Real-World YARA Detection Rules
 * Covers behavior patterns from known ransomware families:
 * WannaCry, Ryuk, LockBit, REvil/Sodinokibi, Conti, BlackBasta, NotPetya
 *
 * These rules match behavioral artifacts, API strings, and patterns commonly
 * found in ransomware memory/file artifacts — NOT executable code.
 * Safe to use in research/forensic environments.
 */

/* ───────────────────────────────────────────────────────────────
   RULE 1: Shadow Copy Deletion (Used by virtually all ransomware)
   ─────────────────────────────────────────────────────────────── */
rule ShadowCopy_Deletion_Attempt {
    meta:
        description = "Detects shadow copy deletion commands used by ransomware to prevent recovery"
        severity = "CRITICAL"
        families = "WannaCry, Ryuk, LockBit, REvil, Conti, BlackBasta"
    strings:
        $vssadmin1 = "vssadmin delete shadows" ascii wide nocase
        $vssadmin2 = "vssadmin.exe Delete Shadows /all" ascii wide nocase
        $wmic_vss  = "wmic shadowcopy delete" ascii wide nocase
        $ps_vss    = "Get-WmiObject Win32_ShadowCopy" ascii wide nocase
        $bcdedit1  = "bcdedit /set {default} recoveryenabled No" ascii wide nocase
        $bcdedit2  = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii wide nocase
        $wbadmin   = "wbadmin delete catalog -quiet" ascii wide nocase
    condition:
        any of them
}

/* ───────────────────────────────────────────────────────────────
   RULE 2: Ransom Note Content Patterns
   ─────────────────────────────────────────────────────────────── */
rule Ransom_Note_Content {
    meta:
        description = "Detects ransom note text patterns written by ransomware"
        severity = "CRITICAL"
        families = "LockBit, REvil, Conti, BlackBasta, Cl0p"
    strings:
        $note1 = "All your files have been encrypted" ascii wide nocase
        $note2 = "Your files are encrypted" ascii wide nocase
        $note3 = "To decrypt your files" ascii wide nocase
        $note4 = "Pay the ransom" ascii wide nocase
        $note5 = "bitcoin" ascii wide nocase
        $note6 = "YOUR FILES ARE ENCRYPTED" ascii wide nocase
        $note7 = "decryption key" ascii wide nocase
        $note8 = "DO NOT delete this file" ascii wide nocase
        $note9 = "contact us at" ascii wide nocase
        $note10 = "README_TO_DECRYPT" ascii wide nocase
        $note11 = "HOW_TO_DECRYPT" ascii wide nocase
        $note12 = "RECOVERY_FILE" ascii wide nocase
        $note13 = "HELP_DECRYPT" ascii wide nocase
        $note14 = "YOUR_FILES_ARE_LOCKED" ascii wide nocase
        $lockbit = "LockBit" ascii wide
        $revil   = "REvil" ascii wide
        $conti   = "Conti" ascii wide
    condition:
        2 of ($note*) or any of ($lockbit, $revil, $conti)
}

/* ───────────────────────────────────────────────────────────────
   RULE 3: WannaCry Specific Indicators
   ─────────────────────────────────────────────────────────────── */
rule WannaCry_Indicators {
    meta:
        description = "WannaCry ransomware behavioral indicators"
        severity = "CRITICAL"
        family = "WannaCry"
        reference = "EternalBlue exploit, SMB propagation"
    strings:
        $wncry_ext   = ".WNCRY" ascii wide
        $wncryt      = ".WNCRYT" ascii wide
        $tasksche    = "tasksche.exe" ascii wide
        $wannacry1   = "WannaCryptor" ascii wide nocase
        $wannacry2   = "WanaCrypt0r" ascii wide
        $killswitch  = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
        $mssecsvc    = "mssecsvc.exe" ascii wide
        $readme_wcry = "@Please_Read_Me@.txt" ascii wide
    condition:
        any of them
}

/* ───────────────────────────────────────────────────────────────
   RULE 4: Ryuk Ransomware Indicators
   ─────────────────────────────────────────────────────────────── */
rule Ryuk_Indicators {
    meta:
        description = "Ryuk ransomware behavioral indicators"
        severity = "CRITICAL"
        family = "Ryuk"
    strings:
        $ryuk_ext    = ".RYK" ascii wide
        $ryuk_note1  = "RyukReadMe.txt" ascii wide
        $ryuk_note2  = "RyukReadMe.html" ascii wide
        $ryuk_str    = "RYUK_DECRYPTOR" ascii wide
        $net_stop    = "net stop" ascii wide nocase
        $sc_delete   = "sc delete" ascii wide nocase
    condition:
        any of ($ryuk_ext, $ryuk_note1, $ryuk_note2, $ryuk_str) or
        (2 of ($net_stop, $sc_delete))
}

/* ───────────────────────────────────────────────────────────────
   RULE 5: LockBit Ransomware Indicators
   ─────────────────────────────────────────────────────────────── */
rule LockBit_Indicators {
    meta:
        description = "LockBit ransomware behavioral indicators"
        severity = "CRITICAL"
        family = "LockBit"
    strings:
        $lockbit_ext1 = ".lockbit" ascii wide nocase
        $lockbit_ext2 = ".lock" ascii wide
        $lockbit_note = "Restore-My-Files.txt" ascii wide
        $lockbit_note2 = "LockBit_Ransomware.hta" ascii wide
        $lockbit_str  = "LOCKBIT" ascii wide nocase
        $ipc          = "\\\\*\\IPC$" ascii wide
        $admin_share  = "\\\\*\\ADMIN$" ascii wide
    condition:
        any of ($lockbit_ext1, $lockbit_ext2, $lockbit_note, $lockbit_note2, $lockbit_str) or
        ($ipc and $admin_share)
}

/* ───────────────────────────────────────────────────────────────
   RULE 6: Conti Ransomware Indicators
   ─────────────────────────────────────────────────────────────── */
rule Conti_Indicators {
    meta:
        description = "Conti ransomware behavioral indicators"
        severity = "CRITICAL"
        family = "Conti"
    strings:
        $conti_ext   = ".CONTI" ascii wide
        $conti_note  = "readme.txt" ascii wide nocase
        $conti_str1  = "CONTI_DECRYPTOR" ascii wide
        $conti_str2  = "ContiDecryptorSoftware" ascii wide
    condition:
        any of them
}

/* ───────────────────────────────────────────────────────────────
   RULE 7: Generic High-Risk Windows API Combination (Memory Scan)
   ─────────────────────────────────────────────────────────────── */
rule Suspicious_Crypto_API_Usage {
    meta:
        description = "Detects suspicious Windows Crypto API usage combination in process memory"
        severity = "HIGH"
    strings:
        $crypt_acquire   = "CryptAcquireContext" ascii wide
        $crypt_gen_key   = "CryptGenKey" ascii wide
        $crypt_encrypt   = "CryptEncrypt" ascii wide
        $crypt_export    = "CryptExportKey" ascii wide
        $bcrypt_gen      = "BCryptGenerateSymmetricKey" ascii wide
        $bcrypt_encrypt  = "BCryptEncrypt" ascii wide
        $capi_random     = "CryptGenRandom" ascii wide
    condition:
        /* Ransomware uses crypto APIs in combination — benign apps rarely use all these together */
        (($crypt_acquire or $bcrypt_gen) and ($crypt_encrypt or $bcrypt_encrypt) and ($crypt_gen_key or $capi_random))
        or (3 of ($crypt_acquire, $crypt_gen_key, $crypt_encrypt, $crypt_export, $bcrypt_gen, $bcrypt_encrypt, $capi_random))
}

/* ───────────────────────────────────────────────────────────────
   RULE 8: Ransomware File Extension Patterns
   ─────────────────────────────────────────────────────────────── */
rule Ransomware_Extension_Pattern {
    meta:
        description = "Detects known ransomware-appended file extension strings"
        severity = "HIGH"
    strings:
        $ext1  = ".locked" ascii wide nocase
        $ext2  = ".encrypted" ascii wide nocase
        $ext3  = ".enc" ascii wide
        $ext4  = ".crypt" ascii wide nocase
        $ext5  = ".crypted" ascii wide nocase
        $ext6  = ".WNCRY" ascii wide
        $ext7  = ".RYK" ascii wide
        $ext8  = ".lockbit" ascii wide nocase
        $ext9  = ".conti" ascii wide nocase
        $ext10 = ".revil" ascii wide nocase
        $ext11 = ".sodinokibi" ascii wide nocase
        $ext12 = ".blackbasta" ascii wide nocase
        $ext13 = ".darkside" ascii wide nocase
        $ext14 = ".DHARMA" ascii wide
        $ext15 = ".adobe" ascii wide  /* Dharma variant */
    condition:
        any of them
}

/* ───────────────────────────────────────────────────────────────
   RULE 9: Anti-Recovery Commands (Windows Backup Tampering)
   ─────────────────────────────────────────────────────────────── */
rule Anti_Recovery_Tampering {
    meta:
        description = "Detects commands that disable Windows recovery mechanisms"
        severity = "HIGH"
    strings:
        $boot_rec  = "BootStatusPolicy" ascii wide nocase
        $safe_boot = "safeboot" ascii wide nocase
        $wer       = "WerFault.exe" ascii wide
        $drwatson  = "DrWatson" ascii wide
        $taskmgr   = "taskmgr.exe" ascii wide nocase
        $regedit   = "regedit.exe" ascii wide nocase
        $cmd_hide  = "/c start /b" ascii wide nocase
        $self_del  = "del /f /q" ascii wide nocase
    condition:
        2 of them
}

/* ───────────────────────────────────────────────────────────────
   RULE 10: RansomShield Simulation (retained for test environment)
   ─────────────────────────────────────────────────────────────── */
rule Generic_Ransomware_Behavior_Simulation {
    meta:
        description = "Detects controlled test simulation strings — safe lab only"
        author = "RansomShield"
        severity = "MEDIUM"
        type = "SIMULATION_ONLY"
    strings:
        $sim_string1 = "RANSOM_SIMULATION_ACTIVE" ascii wide
        $sim_string2 = ".locked" ascii wide
        $crypto_sim  = "BEGIN_FAKE_ENCRYPTION_ROUTINE" ascii wide
        $controlled  = "CONTROLLED_TEST_RANSOMWARE_LIKE" ascii wide
    condition:
        any of them
}
