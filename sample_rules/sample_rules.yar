rule PortScanner {
	meta:
		description = "Auto-generated rule on file PortScanner.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b381b9212282c0c650cb4b0323436c63"
	strings:
		$s0 = "Scan Ports Every"
		$s1 = "C:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB"
		$s2 = "C:\\Documents and Settings\\Alex\\Desktop\\Al\\mess\\client\\MSWINSCK.oca"
		$s3 = "Scan All Possible Ports!"
		$s4 = "Port Scanner, Port Watcher"
		$s5 = "Multiple Range"
		$s6 = "Selected Ports Only"
		$s7 = " 2005 gtvu. All Rights Reserved. gtvu@hotmail.com / al@absent-motive.co.uk"
		$s8 = "Port Scanner By Gtvu"
		$s9 = "Port Control  - Copyright"
	condition:
		all of them
}
rule DomainScanV1_0 {
	meta:
		description = "Auto-generated rule on file DomainScanV1_0.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "aefcd73b802e1c2bdc9b2ef206a4f24e"
	strings:
		$s0 = "dIJMuX$aO-EV"
		$s1 = "XELUxP\"-\\"
		$s2 = "KaR\"U'}-M,."
		$s3 = "V.)\\ZDxpLSav"
		$s4 = "Decompress error"
		$s5 = "Can't load library"
		$s6 = "Can't load function"
		$s7 = "com0tl32:.d"
	condition:
		all of them
}
rule netscantools4or_zip_Folder_setup {
	meta:
		description = "Auto-generated rule on file setup.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "2a8b6c8021850d6232c6bc17d7149aca"
	strings:
		$s0 = "File size expected=%ld, size returned=%ld."
		$s1 = "Could not initialize installation. "
		$s2 = "Initializing Wise Installation Wizard..."
		$s3 = "System DLLs corrupt or missing."
		$s4 = "NetScanTools 4.20 Trial Version Installation"
		$s5 = "Could not extract Wise0132.dll to '%s', CRC does not match."
		$s6 = "Demo installations only run on the computer they were created on."
		$s7 = "_StubFileWrite@12"
	condition:
		all of them
}
rule MooreR_Port_Scanner {
	meta:
		description = "Auto-generated rule on file MooreR Port Scanner.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "376304acdd0b0251c8b19fea20bb6f5b"
	strings:
		$s0 = "Description|"
		$s1 = "VarTstEq~$b"
		$s2 = "Rsge Setup"
		$s3 = "soft Visual Studio\\VB9yp"
		$s4 = "adj_fptan?4"
		$s5 = "ecAnsiToUni"
		$s6 = "sultCheckC/"
		$s7 = "DOWS\\SyMem32\\/o"
		$s8 = "__vbaLMIdCall"
		$s9 = "IP / Hostn$7j"
	condition:
		all of them
}
rule lanspy_zip_Folder_LanSpy {
	meta:
		description = "Auto-generated rule on file LanSpy.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "42114d0f9e88ad76acaa0f145dabf923"
	strings:
		$s0 = "lzma: Compressed data is corrupted (%d)"
		$s1 = "Runtime error     at 00000000"
		$s2 = "<description>Inno Setup</description>"
		$s3 = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
		$s4 = "Inno Setup Setup Data (5.0.4)"
		$s5 = ".DEFAULT\\Control Panel\\International"
		$s6 = "Compressed block is corrupted"
		$s7 = "W(Inno Setup Setup Data (5.0.4)"
		$s8 = "The setup files are corrupted. Please obtain a new copy of the program."
	condition:
		all of them
}
rule superscan {
	meta:
		description = "Auto-generated rule on file superscan.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "0071813eb4668769a15fcd2d1ca1686d"
	strings:
		$s0 = "vkp;_*3RtiSb;sYH"
		$s1 = "\\ws2check.exe"
		$s2 = "$Id: UPX 1.00 Copyright (C) 1996-2000 the UPX Team. All Rights Reserved. $"
		$s3 = "- Kablto iniVal"
		$s4 = "$Info: This file is packed with the UPX executable packer http://upx.tsx.org $"
		$s5 = "sProcessorFeaturePsent1j{ "
	condition:
		all of them
}
rule NetBIOS_Name_Scanner {
	meta:
		description = "Auto-generated rule on file NetBIOS Name Scanner.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "888ba1d391e14c0a9c829f5a1964ca2c"
	strings:
		$s0 = "IconEx\\\\r "
		$s1 = "C:\\WINDOWS\\g;m"
		$s2 = "soft Visual Stu"
		$s3 = "_A^SJADDSIEl"
		$s4 = "NBTScanner!y&"
		$s5 = "MSComctl!b.3"
		$s6 = "_A^SJADDSI>Nl"
	condition:
		all of them
}
rule TrojanHunter_th {
	meta:
		description = "Auto-generated rule on file th.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "6e6c8bf8b294b4c19e8e3fcaa4373037"
	strings:
		$s0 = "TAlignmseNt"
		$s1 = "kern`l32.d"
		$s2 = "Can't load library      "
		$s3 = "5t1tEt:ten6"
		$s4 = "Decompress error        "
		$s5 = "TrykorA- f"
		$s6 = "Can't load function     "
		$s7 = "SI_CHwRrETm"
	condition:
		all of them
}
rule IP_Grabber_v3 {
	meta:
		description = "Auto-generated rule on file IP Grabber v3.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "f444b7085584bf1ddad4dbda494d4459"
	strings:
		$s0 = "cTkoh\\l"
		$s1 = "UljVifK"
		$s2 = "6YHXjaf"
		$s3 = "The procedure entry point %s could not be located in the dynamic link library %s"
		$s4 = "The ordinal %u could not be located in the dynamic link library %s"
	condition:
		all of them
}
rule FeliksPack3___Scanners_ipscan {
	meta:
		description = "Auto-generated rule on file ipscan.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "6c1bcf0b1297689c8c4c12cc70996a75"
	strings:
		$s0 = " VisTC++ R9,"
		$s1 = " _`.B0woZrx"
		$s2 = "WCAP;}ECTED"
		$s3 = "Cont9lBar%&"
		$s4 = "NotSupported"
		$s5 = "dF@@9qotdoBFD"
		$s6 = "SCAN.VERSION{_"
		$s7 = "hid7the\"vWa "
		$s8 = "fxOldhProc423' "
	condition:
		all of them
}
rule CGISscan_CGIScan {
	meta:
		description = "Auto-generated rule on file CGIScan.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "338820e4e8e7c943074d5a5bc832458a"
	strings:
		$s0 = "~~~~~~~~~~~^~~~_TUVWXYZ[\\]~~~|~~~ !\"#$%&'()*+,-./0123456789~~~~~~:;<=>?@ABCDEFGHIJKLMNOPQRS"
		$s1 = "8image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, */*"
		$s2 = "WSocketResolveHost: Cannot convert host address '%s'"
		$s3 = "tcp is the only protocol supported thru socks server"
		$s4 = "0123456789ABCDEF                                                                "
		$s5 = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_ "
		$s6 = "`!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_"
		$s7 = "The file data.txt does not exist. This contains the exploit address details, please re-install."
		$s8 = "System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x"
		$s9 = "image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, */*"
	condition:
		all of them
}
rule netscantools4or_zip_Folder_NSTSTD {
	meta:
		description = "Auto-generated rule on file NSTSTD.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "ea44c48976b2611b0d6574518c9f117d"
	strings:
		$s0 = "ailto:sal=@nwpsw.B"
		$s1 = "~ISEQU4PYA7GEm"
		$s2 = "?fingerThread@@YAIPAX@Z"
		$s3 = "?SaveToDisk@@YGHPBDH@Z"
		$s4 = "$Info: This file is packed with the UPX executable packer http://upx.tsx.org $"
		$s5 = "$Id: UPX 1.04 Copyright (C) 1996-2000 the UPX Team. All Rights Reserved. $"
		$s6 = "i|?ts/@@YAIPAX@Z("
		$s7 = "?ResTH@@YAIPAX@Z"
		$s8 = "ULA:nLIMITATION G "
		$s9 = "ListenThreadProc"
	condition:
		all of them
}
rule NeoTraceProTrial325 {
	meta:
		description = "Auto-generated rule on file NeoTraceProTrial325.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "18bd9b98b8987bdcb32b1a2f05149fe8"
	strings:
		$s0 = "\"Qimq\\d,+*%6<=-"
		$s1 = "Could not initialize installation. "
		$s2 = "Initializing Wise Installation Wizard..."
		$s3 = "System DLLs corrupt or missing."
		$s4 = "NeoTrace Pro 3.25 Trial Installation"
		$s5 = "~qFnfjyniJZiuuZQyeE"
		$s6 = "Demo installations only run on the computer they were created on."
		$s7 = "_StubFileWrite@12"
	condition:
		all of them
}
rule IP_Stealing_Utilities {
	meta:
		description = "Auto-generated rule on file IP Stealing Utilities.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "65646e10fb15a2940a37c5ab9f59c7fc"
	strings:
		$s0 = "IP Stealer Utilities By DarkKnight"
		$s1 = "C:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB"
		$s2 = "doqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoq"
		$s3 = "C:\\unzippesolmod"
		$s4 = "This was made by DarkKnight from www.geeksarecool.com/~antiaol/Index.php"
		$s5 = "IP Stealing Utilities"
		$s6 = "doqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoq"
		$s7 = "C:\\WINDOWS\\System32\\MSWINSCK.oca"
		$s8 = "XIf0(\\-%S*#K' A%"
		$s9 = "IPStealerUtilities"
	condition:
		all of them
}
rule SuperScan4 {
	meta:
		description = "Auto-generated rule on file SuperScan4.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "78f76428ede30e555044b83c47bc86f0"
	strings:
		$s0 = "-./0123456789:;<=>?@ABCDEFGHIJKL"
		$s1 = "`abcdefghijklmnopqrstuvwxyz{|}~"
		$s2 = " td class=\"summO1\">"
		$s3 = "MNOPQRSTWXYZ[\\]^_"
		$s4 = "ageBoxcu B8`"
		$s5 = "WedThuFriSatLJanFebMarAprMayJ"
		$s6 = "REM'EBAqRISE"
		$s7 = "CorExitProcess'msc#e"
		$s8 = "lAugSepOctNovDec"
		$s9 = "rAtime ersrH"
	condition:
		all of them
}
rule PortRacer {
	meta:
		description = "Auto-generated rule on file PortRacer.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "2834a872a0a8da5b1be5db65dfdef388"
	strings:
		$s0 = "Auto Scroll BOTH Text Boxes"
		$s1 = "C:\\Programme\\Microsoft Visual Studio\\VB98\\VB6.OLB"
		$s2 = "C:\\PROGRAMME\\ASP2DLL\\MSWINSCK.oca"
		$s3 = "C:\\PROGRAMME\\ASP2DLL\\MSCOMCTL.oca"
		$s4 = "Start/Stop Portscanning"
		$s5 = "Copyrights (c) 2001 Roughnecks Network System"
		$s6 = "Auto Save LogFile by pressing STOP"
		$s7 = "Manual Log -> click on Save Log File"
		$s8 = "Exclusive written for the Roughnecks NS by AGM65"
	condition:
		all of them
}
rule scanarator {
	meta:
		description = "Auto-generated rule on file scanarator.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "848bd5a518e0b6c05bd29aceb8536c46"
	strings:
		$s0 = "Only use files created from the Computer Scan portion of Scanarator."
		$s1 = "You must enter an IP address or a name of the remote computer!"
		$s2 = "The master port list file list is either missing or in another directory."
		$s3 = "Starting trace to %s, max %s hops, timeout of %s, with %s pings..."
		$s4 = "GET /scripts/..%c0%af../winnt/system32/cmd.exe?/c+dir HTTP/1.0"
		$s5 = "There has been over 100 \"Conflicting Credentials Errors\"."
		$s6 = "Error opening iis.exe, make sure it is in the current directory."
		$s7 = "You must select some ports to export to the new port list file."
		$s8 = "You must check characters or numbers or enter a custom set of characters."
		$s9 = "MasterList.lst doesn't seem to be a proper port list file."
	condition:
		all of them
}
rule aolipsniffer {
	meta:
		description = "Auto-generated rule on file aolipsniffer.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "51565754ea43d2d57b712d9f0a3e62b8"
	strings:
		$s0 = "C:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB"
		$s1 = "dwGetAddressForObject"
		$s2 = "Color Transfer Settings"
		$s3 = "FX Global Lighting Angle"
		$s4 = "Version compatibility info"
		$s5 = "New Windows Thumbnail"
		$s6 = "Layer ID Generator Base"
		$s7 = "Color Halftone Settings"
		$s8 = "C:\\WINDOWS\\SYSTEM\\MSWINSCK.oca"
	condition:
		all of them
}
rule _Bitchin_Threads_ {
	meta:
		description = "Auto-generated rule on file =Bitchin Threads=.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "7491b138c1ee5a0d9d141fbfd1f0071b"
	strings:
		$s0 = ". : EXTRA INFORMATION : .                                                                            (UPDATES)"
		$s1 = "=BITCHIN THREADS=             .: Version 3.1 :.                      DarKPaiN"
		$s2 = "Progenic Warfare and DarKPaiN cannot accept any responsibility for damage or loss of data to yours or anyone else's computer, through the direct or indirect use of this program. If you disagree with this statement please do not use this program again. Progenic Warfare hearby take NO responsibility for the uses and/or misuses of this program."
		$s3 = "This program is simple to use, first setup the ports to scan for, in 'Port settings...', by checking the relevant one. Then place the start IP address and the ending IP address in the boxes, and let it rip... It will alert you when it finds an address, with the port open..."
		$s4 = "Tikigod, YoriK, MaRviN, SpanX, TinZ, DeathBlade.. and anyone else who would like to be thanked..."
		$s5 = "Newer versions of this program are sure to come out... (If I get some feedback..). Any criticism is fine, even if you want me to use different colours, if you have any interesting ports, or trojans you would like added please contact me, DarKPaiN 'Son 'o' Jerel'.. as stated in the About section."
		$s6 = "  =BITCHIN THREADS=                                                   Port Configuration"
		$s7 = "'Come to Progenic Warfare, we have many programs fit for a 'hacker' king, we have the one... the only... PUSH! - ICQ chat kicker, TeSla - the much talked about and highley rated ICQ addon system... So come one come all and click on the link above...'"
		$s8 = " =BITCHIN THREADS=                                           General Configuration"
	condition:
		all of them
}
rule cgis4_cgis4 {
	meta:
		description = "Auto-generated rule on file cgis4.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "d658dad1cd759d7f7d67da010e47ca23"
	strings:
		$s0 = ")PuMB_syJ"
		$s1 = "&,fARW>yR"
		$s2 = "m3hm3t_rullaz"
		$s3 = "7Projectc1"
		$s4 = "Ten-GGl\""
		$s5 = "/Moziqlxa"
	condition:
		all of them
}
rule _Bitchin_Threads__2 {
	meta:
		description = "Auto-generated rule on file =Bitchin Threads=.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "7491b138c1ee5a0d9d141fbfd1f0071b"
	strings:
		$s0 = ". : EXTRA INFORMATION : .                                                                            (UPDATES)"
		$s1 = "=BITCHIN THREADS=             .: Version 3.1 :.                      DarKPaiN"
		$s2 = "Progenic Warfare and DarKPaiN cannot accept any responsibility for damage or loss of data to yours or anyone else's computer, through the direct or indirect use of this program. If you disagree with this statement please do not use this program again. Progenic Warfare hearby take NO responsibility for the uses and/or misuses of this program."
		$s3 = "This program is simple to use, first setup the ports to scan for, in 'Port settings...', by checking the relevant one. Then place the start IP address and the ending IP address in the boxes, and let it rip... It will alert you when it finds an address, with the port open..."
		$s4 = "Tikigod, YoriK, MaRviN, SpanX, TinZ, DeathBlade.. and anyone else who would like to be thanked..."
		$s5 = "Newer versions of this program are sure to come out... (If I get some feedback..). Any criticism is fine, even if you want me to use different colours, if you have any interesting ports, or trojans you would like added please contact me, DarKPaiN 'Son 'o' Jerel'.. as stated in the About section."
		$s6 = "  =BITCHIN THREADS=                                                   Port Configuration"
		$s7 = "'Come to Progenic Warfare, we have many programs fit for a 'hacker' king, we have the one... the only... PUSH! - ICQ chat kicker, TeSla - the much talked about and highley rated ICQ addon system... So come one come all and click on the link above...'"
		$s8 = " =BITCHIN THREADS=                                           General Configuration"
	condition:
		all of them
}
rule SuperScan4_2 {
	meta:
		description = "Auto-generated rule on file SuperScan4.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "78f76428ede30e555044b83c47bc86f0"
	strings:
		$s0 = "-./0123456789:;<=>?@ABCDEFGHIJKL"
		$s1 = "`abcdefghijklmnopqrstuvwxyz{|}~"
		$s2 = " td class=\"summO1\">"
		$s3 = "MNOPQRSTWXYZ[\\]^_"
		$s4 = "ageBoxcu B8`"
		$s5 = "WedThuFriSatLJanFebMarAprMayJ"
		$s6 = "REM'EBAqRISE"
		$s7 = "CorExitProcess'msc#e"
		$s8 = "lAugSepOctNovDec"
		$s9 = "rAtime ersrH"
	condition:
		all of them
}
rule ITrace32 {
	meta:
		description = "Auto-generated rule on file ITrace32.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b5e51291ec9e61cb2a4ff5c96d4caf32"
	strings:
		$s0 = "socket marked as non-blocking and SO_LINGER set not 0"
		$s1 = "round-trip (ms) min/avg/max = %ld/%ld/%ld"
		$s2 = "socket type not supported for address family"
		$s3 = "%d packets transmitted, %d packets received, %d%% packet loss"
		$s4 = "%d bytes from %s: icmp_seq=%d time=%ld ms"
		$s5 = "%d packets transmitted, %d packets received, 100%% packet loss"
		$s6 = "Non-authoritive: host not found or server failure"
		$s7 = "%d bytes %s %s: icmp_type=%d (%s) icmp_code=%d"
		$s8 = "ws_ping - copyright (c) 1995 Ipswitch, Inc. 01234567890123"
		$s9 = "Non-recoverable: refused or not implemented"
	condition:
		all of them
}
rule portscan {
	meta:
		description = "Auto-generated rule on file portscan.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "a8bfdb2a925e89a281956b1e3bb32348"
	strings:
		$s0 = "0    :UNABLE TO RESOLVE HOSTNAME."
		$s1 = "0    :MAX PORTS. Socket not opened."
		$s2 = "C:\\SPHERE\\DOCS\\SCANLOG.TXT"
		$s3 = "0    :SCANNING HOST:"
		$s4 = "0    :RESET - ALL SOCKETS CLOSED"
		$s5 = "0    :SCAN BEGUN ON PORT:"
		$s6 = "0    :PORTSCAN READY."
		$s7 = "0    :SCAN HALTED ON PORT:"
		$s8 = "-----RESULTS OF SCAN FOLLOW-----"
	condition:
		all of them
}
rule SuperScan4_3 {
	meta:
		description = "Auto-generated rule on file SuperScan4.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "78f76428ede30e555044b83c47bc86f0"
	strings:
		$s0 = "-./0123456789:;<=>?@ABCDEFGHIJKL"
		$s1 = "`abcdefghijklmnopqrstuvwxyz{|}~"
		$s2 = " td class=\"summO1\">"
		$s3 = "MNOPQRSTWXYZ[\\]^_"
		$s4 = "ageBoxcu B8`"
		$s5 = "WedThuFriSatLJanFebMarAprMayJ"
		$s6 = "REM'EBAqRISE"
		$s7 = "CorExitProcess'msc#e"
		$s8 = "lAugSepOctNovDec"
		$s9 = "rAtime ersrH"
	condition:
		all of them
}
rule ProPort_zip_Folder_ProPort {
	meta:
		description = "Auto-generated rule on file ProPort.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "c1937a86939d4d12d10fc44b7ab9ab27"
	strings:
		$s0 = "Corrupt Data!"
		$s1 = "K4p~omkIz"
		$s2 = "DllTrojanScan"
		$s3 = "GetDllInfo"
		$s4 = "Compressed by Petite (c)1999 Ian Luck."
		$s5 = "GetFileCRC32"
		$s6 = "GetTrojanNumber"
		$s7 = "TFAKAbout"
	condition:
		all of them
}
rule awsps4_61_setup {
	meta:
		description = "Auto-generated rule on file setup.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "c7efe48f2748e28e96af329b26471fc3"
	strings:
		$s0 = "Inno Setup Messages (2.0.8)"
		$s1 = "zlib: Internal error. Code %d"
		$s2 = "Messages file \"%s\" is missing. Please correct the problem or obtain a new copy of the program."
		$s3 = "zlib: Compressed data is corrupted"
		$s4 = "Runtime error     at 00000000"
		$s5 = "Inno Setup Setup Data (2.0.8)"
		$s6 = " inflate 1.1.3 Copyright 1995-1998 Mark Adler "
		$s7 = "The setup files are corrupted. Please obtain a new copy of the program."
	condition:
		all of them
}
rule StealthWasp_s_Basic_PortScanner_v1_2 {
	meta:
		description = "Auto-generated rule on file StealthWasp's Basic PortScanner v1.2.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "7c0f2cab134534cd35964fe4c6a1ff00"
	strings:
		$s0 = "StealthWasp's Basic PortScanner v1.2"
		$s1 = "Basic PortScanner"
		$s2 = "C:\\Programfiler\\Microsoft Visual Studio\\VB98\\VB6.OLB"
		$s3 = "StealthWasp's Basic PortScanner"
		$s4 = "MS Sans Serif0"
		$s5 = "MS Sans Serif'"
		$s6 = "Now scanning port:"
		$s7 = "C:\\WINDOWS\\System32\\Mswinsck.oca"
	condition:
		all of them
}
rule BluesPortScan {
	meta:
		description = "Auto-generated rule on file BluesPortScan.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "6292f5fc737511f91af5e35643fc9eef"
	strings:
		$s0 = "This program was made by Volker Voss"
		$s1 = "JiBOo~SSB"
		$s2 = "The procedure entry point %s could not be located in the dynamic link library %s"
		$s3 = "FDb[viql|"
		$s4 = "The ordinal %u could not be located in the dynamic link library %s"
	condition:
		all of them
}
rule scanarator_iis {
	meta:
		description = "Auto-generated rule on file iis.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "3a8fc02c62c8dd65e038cc03e5451b6e"
	strings:
		$s0 = "example: iis 10.10.10.10"
		$s1 = "send error"
		$s2 = "Error in connect command"
		$s3 = "Error in socket command"
		$s4 = "wsastartupo error"
		$s5 = "Useage: iis [ip address of server]"
		$s6 = "Enter DOS command (quit to quit): "
		$s7 = "recv error"
		$s8 = "Press any key"
		$s9 = "GET /scripts/..%c0%af../winnt/system32/cmd.exe?/c+"
	condition:
		all of them
}
rule BluesPortScan_2 {
	meta:
		description = "Auto-generated rule on file BluesPortScan.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "6292f5fc737511f91af5e35643fc9eef"
	strings:
		$s0 = "This program was made by Volker Voss"
		$s1 = "JiBOo~SSB"
		$s2 = "The procedure entry point %s could not be located in the dynamic link library %s"
		$s3 = "FDb[viql|"
		$s4 = "The ordinal %u could not be located in the dynamic link library %s"
	condition:
		all of them
}
rule NeoTraceProTrial325_2 {
	meta:
		description = "Auto-generated rule on file NeoTraceProTrial325.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "18bd9b98b8987bdcb32b1a2f05149fe8"
	strings:
		$s0 = "\"Qimq\\d,+*%6<=-"
		$s1 = "Could not initialize installation. "
		$s2 = "Initializing Wise Installation Wizard..."
		$s3 = "System DLLs corrupt or missing."
		$s4 = "NeoTrace Pro 3.25 Trial Installation"
		$s5 = "~qFnfjyniJZiuuZQyeE"
		$s6 = "Demo installations only run on the computer they were created on."
		$s7 = "_StubFileWrite@12"
	condition:
		all of them
}
rule stealth_Stealth {
	meta:
		description = "Auto-generated rule on file Stealth.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "8ce3a386ce0eae10fc2ce0177bbc8ffa"
	strings:
		$s0 = "\" cellspacing=\"0\" cellpadding=\"2\" border=\"1\" bordercolor=\"white\"><tr><td>"
		$s1 = "This tool may be used only by system administrators. I am not responsible for any damages, direct or indirect, caused by usage of this tool."
		$s2 = "~~~~~~~~~~~^~~~_TUVWXYZ[\\]~~~|~~~ !\"#$%&'()*+,-./0123456789~~~~~~:;<=>?@ABCDEFGHIJKLMNOPQRS"
		$s3 = "<table width=\"60%\" bgcolor=\"black\" cellspacing=\"0\" cellpadding=\"2\" border=\"1\" bordercolor=\"white\"><tr><td>"
		$s4 = "Greetings to Andre Freitas, David Alexandre, Fabricio Leite, Marcelo Caffaro and Paulo Lopes."
		$s5 = "<table width=\"60%\" bgcolor=\"white\" cellspacing=\"0\" cellpadding=\"2\" border=\"1\" bordercolor=\"white\"><tr><td>"
		$s6 = "NThis tool may be used only by system administrators. I am not responsible for "
		$s7 = " Freitas, David Alexandre, Fabricio Leite, Marcelo Caffaro e Paulo Lopes."
		$s8 = "o me responsabilizo por danos, diretos ou indiretos, causados pelo uso desta ferramenta."
		$s9 = "MGreetings to Andre Freitas, David Alexandre, Fabricio Leite, Marcelo Caffaro "
	condition:
		all of them
}
rule BluesPortScan_3 {
	meta:
		description = "Auto-generated rule on file BluesPortScan.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "a0026e03b498153d9dbfdd73a5ac748e"
	strings:
		$s0 = "V+nR95*Rat"
		$s1 = "This program was made by Volker Voss"
		$s2 = "q81bxuC&?8"
		$s3 = "mxEh\"O,U"
		$s4 = "The procedure entry point %s could not be located in the dynamic link library %s"
		$s5 = "7iicaN(>(L"
		$s6 = "The ordinal %u could not be located in the dynamic link library %s"
	condition:
		all of them
}
rule DomainScanV1_0_2 {
	meta:
		description = "Auto-generated rule on file DomainScanV1_0.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "aefcd73b802e1c2bdc9b2ef206a4f24e"
	strings:
		$s0 = "dIJMuX$aO-EV"
		$s1 = "XELUxP\"-\\"
		$s2 = "KaR\"U'}-M,."
		$s3 = "V.)\\ZDxpLSav"
		$s4 = "Decompress error"
		$s5 = "Can't load library"
		$s6 = "Can't load function"
		$s7 = "com0tl32:.d"
	condition:
		all of them
}
rule superscan_2 {
	meta:
		description = "Auto-generated rule on file superscan.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "0071813eb4668769a15fcd2d1ca1686d"
	strings:
		$s0 = "vkp;_*3RtiSb;sYH"
		$s1 = "\\ws2check.exe"
		$s2 = "$Id: UPX 1.00 Copyright (C) 1996-2000 the UPX Team. All Rights Reserved. $"
		$s3 = "- Kablto iniVal"
		$s4 = "$Info: This file is packed with the UPX executable packer http://upx.tsx.org $"
		$s5 = "sProcessorFeaturePsent1j{ "
	condition:
		all of them
}
rule Angry_IP_Scanner_v2_08_ipscan {
	meta:
		description = "Auto-generated rule on file ipscan.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "70cf2c09776a29c3e837cb79d291514a"
	strings:
		$s0 = "_H/EnumDisplay/"
		$s1 = "Wad^wkkAjukA\""
		$s2 = "AfxOldhProc423"
		$s3 = "ar%&MDIFrame\""
		$s4 = "EOhl'CDialogK"
		$s5 = "uECTED.MSVCRT0x"
		$s6 = " VisTC++ R9Li"
		$s7 = "akoverwriPh"
		$s8 = "NotSupported7"
	condition:
		all of them
}
rule crack_Loader {
	meta:
		description = "Auto-generated rule on file Loader.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "f4f79358a6c600c1f0ba1f7e4879a16d"
	strings:
		$s0 = "NeoWait.exe"
		$s1 = "RRRRRRRW"
	condition:
		all of them
}
rule TrojanHunter15_zip_Folder_th {
	meta:
		description = "Auto-generated rule on file th.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "6e6c8bf8b294b4c19e8e3fcaa4373037"
	strings:
		$s0 = "TAlignmseNt"
		$s1 = "kern`l32.d"
		$s2 = "Can't load library      "
		$s3 = "5t1tEt:ten6"
		$s4 = "Decompress error        "
		$s5 = "TrykorA- f"
		$s6 = "Can't load function     "
		$s7 = "SI_CHwRrETm"
	condition:
		all of them
}
