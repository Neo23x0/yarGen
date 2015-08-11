rule Sdbinst_EXE {
    meta:
        description = "Suspicous string in EXE file"
        author = "Florian Roth"
        date = "2015-08-07"
        score = 10
    strings:
        $s1 = "sdbinst.exe" ascii fullword
    condition:
        uint16(0) == 0x5a4d and 1 of them
}