
rule Suspicious_StringSet_score10_EXE {
    meta:
        description = "Suspicous string in EXE file"
        author = "Florian Roth"
        date = "2015-08-07"
        score = 10
    strings:
        $s1 = "elevate" ascii fullword
        $s2 = "injected" ascii fullword
        $s3 = "vulnerable" ascii fullword
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule Suspicious_StringSet_score30_EXE {
    meta:
        description = "Suspicous string in EXE file"
        author = "Florian Roth"
        date = "2015-08-07"
        score = 30
    strings:
        $s1 = "net start" ascii fullword
        $s2 = "LSASRV.DLL" ascii fullword
        $s3 = "\\DosDevices\\" ascii fullword
        $s4 = "$Recycle" ascii fullword
        $s5 = "Hello World" ascii fullword
        $s6 = "hello world" ascii fullword
        $s7 = "tor2web" ascii fullword
        $s8 = "sniff" ascii fullword
        $s9 = "c0d3d" ascii fullword
        $s10 = "/c rundll32" ascii fullword
        $s11 = "meterpreter" ascii fullword
        $s12 = "metasploit" ascii fullword
        $s13 = "ntlmhash" ascii fullword
        $s14 = "lmhash" ascii fullword
        $s15 = "infect" ascii fullword
        $s16 = "victim" ascii fullword
        $s17 = "exploited" ascii fullword
        $s18 = "shellcode" ascii fullword
        $s19 = "spoofed" ascii fullword
        $s20 = "Management Support Team1" ascii fullword
        $s21 = "DTOPTOOLZ Co." ascii fullword
        $s22 = "taskkill" ascii fullword
        $s23 = "LSASS" ascii fullword
        $s24 = "lsass.exe" ascii fullword
        $s25 = "sdbinst.exe" ascii fullword
    condition:
        uint16(0) == 0x5a4d and 1 of them and not
        (
            filename matches /lsasrv.dll/ or
            filename matches /taskkill.exe/ or
            filename matches /sdbinst.exe/
        )
}