rule PortScanner {
	meta:
		description = "Auto-generated rule on file PortScanner.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b381b9212282c0c650cb4b0323436c63"
	strings:
		$s0 = "Scan Ports Every"
		$s1 = "C:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB"
		$s2 = "C:\\Documents and Settings\\Alex\\Desktop\\Al\\mess\\client\\MSWINSCK.oca"
		$s3 = "txtPortWatch"
		$s4 = "scan_multiple"
		$s5 = "Scan All Possible Ports!"
		$s6 = "Port Scanner, Port Watcher"
		$s7 = "Multiple Range"
		$s8 = "scan_selected"
		$s9 = "Selected Ports Only"
		$s10 = " 2005 gtvu. All Rights Reserved. gtvu@hotmail.com / al@absent-motive.co.uk"
		$s11 = "Port Scanner By Gtvu"
		$s12 = "Port Control  - Copyright"
		$s13 = "Port Watcher"
		$s14 = "Waiting . . ."
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
		$s2 = "NbycMiS:Rk"
		$s3 = "KaR\"U'}-M,."
		$s4 = "V89#tiW,p>"
		$s5 = "TPropFixuu"
		$s6 = "V.)\\ZDxpLSav"
		$s7 = "Decompress error"
		$s8 = "Can't load library"
		$s9 = "Can't load function"
		$s10 = "com0tl32:.d"
		$s11 = "SO@TWARE\\"
	condition:
		all of them
}
rule setup {
	meta:
		description = "Auto-generated rule on file setup.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "2a8b6c8021850d6232c6bc17d7149aca"
	strings:
		$s0 = "UpdateScreen"
		$s1 = "_MainWndProc@16"
		$s2 = "File size expected=%ld, size returned=%ld."
		$s3 = "Could not initialize installation. "
		$s4 = "Initializing Wise Installation Wizard..."
		$s5 = "dMS Sans Serif"
		$s6 = "System DLLs corrupt or missing."
		$s7 = "GLBSInstall"
		$s8 = "v>H1Sb~7zim"
		$s9 = "NetScanTools 4.20 Trial Version Installation"
		$s10 = "`<-X0hok\"(OK"
		$s11 = "Could not extract Wise0132.dll to '%s', CRC does not match."
		$s12 = ";3r!igrGfEgfGrg"
		$s13 = "Demo installations only run on the computer they were created on."
		$s14 = "DisplayGraphics"
		$s15 = "&KQOFrcR\\I"
		$s16 = "_StubFileWrite@12"
		$s17 = "R0nid(0L:9b"
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
		$s3 = "Project1"
		$s4 = "soft Visual Studio\\VB9yp"
		$s5 = "IniOnErro"
		$s6 = "MooreR P"
		$s7 = "i\\><<kab"
		$s8 = "adj_fptan?4"
		$s9 = "ecAnsiToUni"
		$s10 = "sultCheckC/"
		$s11 = "DOWS\\SyMem32\\/o"
		$s12 = "__vbaLMIdCall"
		$s13 = "IP / Hostn$7j"
	condition:
		all of them
}
rule LanSpy {
	meta:
		description = "Auto-generated rule on file LanSpy.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "42114d0f9e88ad76acaa0f145dabf923"
	strings:
		$s0 = "lzma: Compressed data is corrupted (%d)"
		$s1 = "TCompressedBlockReader"
		$s2 = "TSetupLanguageEntry@"
		$s3 = "ECompressInternalError"
		$s4 = "LzmaDecoderInit failed (%d)"
		$s5 = "Inno Setup Messages (4.1.4)"
		$s6 = "Runtime error     at 00000000"
		$s7 = "<description>Inno Setup</description>"
		$s8 = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
		$s9 = "Inno Setup Setup Data (5.0.4)"
		$s10 = ".DEFAULT\\Control Panel\\International"
		$s11 = "Compressed block is corrupted"
		$s12 = "W(Inno Setup Setup Data (5.0.4)"
		$s13 = "LzmaDecode failed (%d)"
		$s14 = "TCustomDecompressor"
		$s15 = "    name=\"JR.Inno.Setup\""
		$s16 = "The setup files are corrupted. Please obtain a new copy of the program."
	condition:
		all of them
}
rule superscan {
	meta:
		description = "Auto-generated rule on file superscan.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "0071813eb4668769a15fcd2d1ca1686d"
	strings:
		$s0 = "\\ansi\\deff0"
		$s1 = "vkp;_*3RtiSb;sYH"
		$s2 = "\\hensss.lst"
		$s3 = "\\scanner.hlp"
		$s4 = "\\trojans.lst"
		$s5 = "\\scanner.exe"
		$s6 = "xwelcom$plf"
		$s7 = "\\ws2check.exe"
		$s8 = "\\scanner.cnt"
		$s9 = "$Id: UPX 1.00 Copyright (C) 1996-2000 the UPX Team. All Rights Reserved. $"
		$s10 = "~ageBox8Cr9"
		$s11 = "- Kablto iniVal"
		$s12 = "nK\\orborRl"
		$s13 = "\\scanner.lst"
		$s14 = "$Info: This file is packed with the UPX executable packer http://upx.tsx.org $"
		$s15 = "\\scanner.ini"
		$s16 = "sProcessorFeaturePsent1j{ "
	condition:
		all of them
}
rule NetBIOS_Name_Scanner {
	meta:
		description = "Auto-generated rule on file NetBIOS Name Scanner.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "888ba1d391e14c0a9c829f5a1964ca2c"
	strings:
		$s0 = "OProg: |e"
		$s1 = "IconEx\\\\r "
		$s2 = "C:\\WINDOWS\\g;m"
		$s3 = "YSTEMVBVp7v"
		$s4 = "monDialog1"
		$s5 = "L~7Object^"
		$s6 = "soft Visual Stu"
		$s7 = "xtSplitIP"
		$s8 = "_A^SJADDSIEl"
		$s9 = "lsStatusBar"
		$s10 = ")AddressT"
		$s11 = "]VAPL?8\""
		$s12 = "wSDAJ\\]{pp"
		$s13 = "NT_SINK_JR0"
		$s14 = "NBTScanner!y&"
		$s15 = "<8\"VAPL?"
		$s16 = "pF^diJt#x"
		$s17 = "MSComctl!b.3"
		$s18 = "_A^SJADDSI>Nl"
		$s19 = "MSWinsock."
	condition:
		all of them
}
rule th {
	meta:
		description = "Auto-generated rule on file th.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "6e6c8bf8b294b4c19e8e3fcaa4373037"
	strings:
		$s0 = "TAlignmseNt"
		$s1 = "kern`l32.d"
		$s2 = "Can't load library      "
		$s3 = "WARE\\Bor"
		$s4 = "5t1tEt:ten6"
		$s5 = "ze(d+xiRE"
		$s6 = "Decompress error        "
		$s7 = "Softwar^e"
		$s8 = "TrykorA- f"
		$s9 = "Can't load function     "
		$s10 = "U-OBIm~%U"
		$s11 = "SI_CHwRrETm"
	condition:
		all of them
}
rule IP_Grabber_v3 {
	meta:
		description = "Auto-generated rule on file IP Grabber v3.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "f444b7085584bf1ddad4dbda494d4459"
	strings:
		$s0 = "QibmRn"
		$s1 = "sBUz1 "
		$s2 = "6soGwg"
		$s3 = "cTkoh\\l"
		$s4 = "fTuxje"
		$s5 = "UljVifK"
		$s6 = "6YHXjaf"
		$s7 = "Xuv~Z$"
		$s8 = "bpOL{2"
		$s9 = "The procedure entry point %s could not be located in the dynamic link library %s"
		$s10 = "The ordinal %u could not be located in the dynamic link library %s"
	condition:
		all of them
}
rule ipscan {
	meta:
		description = "Auto-generated rule on file ipscan.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "6c1bcf0b1297689c8c4c12cc70996a75"
	strings:
		$s0 = " VisTC++ R9,"
		$s1 = " _`.B0woZrx"
		$s2 = "MDIFrame\""
		$s3 = "WCAP;}ECTED"
		$s4 = "WCDialog_"
		$s5 = "Cont9lBar%&"
		$s6 = "/TempWndO"
		$s7 = "NotSupported"
		$s8 = "dF@@9qotdoBFD"
		$s9 = "USER32oIS"
		$s10 = "overwriPh"
		$s11 = "8jtoSG.%i"
		$s12 = "SCAN.VERSION{_"
		$s13 = "_software"
		$s14 = "W:D_STATEB"
		$s15 = "oi{n'Rect"
		$s16 = "1\\ Tnag*"
		$s17 = "hid7the\"vWa "
		$s18 = "fxOldhProc423' "
	condition:
		all of them
}
rule CGIScan {
	meta:
		description = "Auto-generated rule on file CGIScan.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "338820e4e8e7c943074d5a5bc832458a"
	strings:
		$s0 = "~~~~~~~~~~~^~~~_TUVWXYZ[\\]~~~|~~~ !\"#$%&'()*+,-./0123456789~~~~~~:;<=>?@ABCDEFGHIJKLMNOPQRS"
		$s1 = "8image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, */*"
		$s2 = "WSocketResolveHost: Cannot convert host address '%s'"
		$s3 = "WSocketResolveProto: Cannot convert protocol '%s'"
		$s4 = "Address family not supported by protocol family"
		$s5 = "tcp is the only protocol supported thru socks server"
		$s6 = "0123456789ABCDEF                                                                "
		$s7 = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_ "
		$s8 = "`!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_"
		$s9 = "Invalid socks level. Must be 4, 4A or 5."
		$s10 = "Can't change socks server if not closed"
		$s11 = "WinSock DLL cannot support this application"
		$s12 = "WSocketResolvePort: Cannot convert port '%s'"
		$s13 = "Mode: Scan for selected CGI holes (Total: "
		$s14 = "listening is not supported thru socks server"
		$s15 = "The file data.txt does not exist. This contains the exploit address details, please re-install."
		$s16 = "System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x"
		$s17 = "image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, */*"
	condition:
		all of them
}
rule NSTSTD {
	meta:
		description = "Auto-generated rule on file NSTSTD.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "ea44c48976b2611b0d6574518c9f117d"
	strings:
		$s0 = "~Hihwes'Perf"
		$s1 = "nstident.dll"
		$s2 = "ailto:sal=@nwpsw.B"
		$s3 = "NotSupported"
		$s4 = "/H:%MS_dx.log"
		$s5 = ")Wa[FeSingle"
		$s6 = "~ISEQU4PYA7GEm"
		$s7 = "?fingerThread@@YAIPAX@Z"
		$s8 = "?SaveToDisk@@YGHPBDH@Z"
		$s9 = "$Info: This file is packed with the UPX executable packer http://upx.tsx.org $"
		$s10 = "$Id: UPX 1.04 Copyright (C) 1996-2000 the UPX Team. All Rights Reserved. $"
		$s11 = "i|?ts/@@YAIPAX@Z("
		$s12 = "?ResTH@@YAIPAX@Z"
		$s13 = "ULA:nLIMITATION G "
		$s14 = "ListenThreadProc"
		$s15 = "O+BmSrucR0\"t"
	condition:
		all of them
}
rule NeoTraceProTrial325 {
	meta:
		description = "Auto-generated rule on file NeoTraceProTrial325.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "18bd9b98b8987bdcb32b1a2f05149fe8"
	strings:
		$s0 = "UpdateScreen"
		$s1 = "_MainWndProc@16"
		$s2 = "\"Qimq\\d,+*%6<=-"
		$s3 = "Could not initialize installation. "
		$s4 = "ghTDTP|cZJZEvq"
		$s5 = "|5|w~7TuV1VvV7"
		$s6 = "Initializing Wise Installation Wizard..."
		$s7 = "System DLLs corrupt or missing."
		$s8 = "NeoTrace Pro 3.25 Trial Installation"
		$s9 = "iFaYmMUN}7<h"
		$s10 = "gEDTT|dKJZ\\vc"
		$s11 = "\\MS Sans Serif"
		$s12 = "~qFnfjyniJZiuuZQyeE"
		$s13 = "Demo installations only run on the computer they were created on."
		$s14 = "DisplayGraphics"
		$s15 = "_StubFileWrite@12"
		$s16 = "KAs'XRvjFB\""
		$s17 = "wL\\cuB\\+uw"
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
		$s2 = "fOvI:o@4"
		$s3 = "Winsock1"
		$s4 = "Support 2"
		$s5 = "doqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoq"
		$s6 = "C:\\unzippesolmod"
		$s7 = "This was made by DarkKnight from www.geeksarecool.com/~antiaol/Index.php"
		$s8 = "Project1"
		$s9 = "IP Stealing Utilities"
		$s10 = "doqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoqdoq"
		$s11 = "Winsock2"
		$s12 = "C:\\WINDOWS\\System32\\MSWINSCK.oca"
		$s13 = "XIf0(\\-%S*#K' A%"
		$s14 = "ght from www.gee"
		$s15 = "IPStealerUtilities"
		$s16 = "Winsock7"
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
		$s1 = "7~pUb\\:7wh"
		$s2 = "`abcdefghijklmnopqrstuvwxyz{|}~"
		$s3 = " td class=\"summO1\">"
		$s4 = "HIDDEN-US!["
		$s5 = "MNOPQRSTWXYZ[\\]^_"
		$s6 = "ageBoxcu B8`"
		$s7 = "WedThuFriSatLJanFebMarAprMayJ"
		$s8 = "uI-CubD+ZkT"
		$s9 = "REM'EBAqRISE"
		$s10 = "CorExitProcess'msc#e"
		$s11 = "DOMA%#R6028"
		$s12 = "lAugSepOctNovDec"
		$s13 = "~nhrpef *Vt"
		$s14 = "rAtime ersrH"
		$s15 = "GArf&Sa_TX,"
	condition:
		all of them
}
rule PortRacer {
	meta:
		description = "Auto-generated rule on file PortRacer.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "2834a872a0a8da5b1be5db65dfdef388"
	strings:
		$s0 = "Port Racer v2.0"
		$s1 = "Auto Scroll BOTH Text Boxes"
		$s2 = "MSComctlLib.StatusBar"
		$s3 = "AGM65's PortRacer v2.0"
		$s4 = "C:\\Programme\\Microsoft Visual Studio\\VB98\\VB6.OLB"
		$s5 = "Auto Scroll Text Boxes"
		$s6 = "AGM65's PortRacer"
		$s7 = "Port Racer Info"
		$s8 = "C:\\PROGRAMME\\ASP2DLL\\MSWINSCK.oca"
		$s9 = "MSComctlLib.Slider"
		$s10 = "C:\\PROGRAMME\\ASP2DLL\\MSCOMCTL.oca"
		$s11 = "Start/Stop Portscanning"
		$s12 = "Set Speed to Max"
		$s13 = "Copyrights (c) 2001 Roughnecks Network System"
		$s14 = "Auto Save LogFile by pressing STOP"
		$s15 = "Manual Log -> click on Save Log File"
		$s16 = "Save LogFile manually"
		$s17 = "ruxnetsys@yahoo.de"
		$s18 = "Exclusive written for the Roughnecks NS by AGM65"
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
		$s3 = "Found password for key .default\\software\\orl\\winvnc3"
		$s4 = "Starting trace to %s, max %s hops, timeout of %s, with %s pings..."
		$s5 = "Failed to open reg key SOFTWARE\\ORL\\winvnc3\\default"
		$s6 = "You must select a group and display the members first."
		$s7 = "GET /scripts/..%c0%af../winnt/system32/cmd.exe?/c+dir HTTP/1.0"
		$s8 = "There has been over 100 \"Conflicting Credentials Errors\"."
		$s9 = "Error opening iis.exe, make sure it is in the current directory."
		$s10 = "There has been over 100 \"Bad Network Path Errors\"."
		$s11 = "You must select a word that is in the password file."
		$s12 = "Major Version = %i  Minor Version = %i  Platform ID = %i"
		$s13 = "Found password for key software\\orl\\winvnc3\\default"
		$s14 = "Failed to open reg key .default\\software\\orl\\winvnc3"
		$s15 = "If you want to get the users of multiple groups use the "
		$s16 = "You must enter how many random passwords to generate."
		$s17 = "You must select some ports to export to the new port list file."
		$s18 = "You must check characters or numbers or enter a custom set of characters."
		$s19 = "MasterList.lst doesn't seem to be a proper port list file."
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
		$s1 = "Japanese Print Flags"
		$s2 = "dwGetAddressForObject"
		$s3 = "fPhotoshop 3.0"
		$s4 = "ICC Untagged Flag"
		$s5 = "dwXCopyDataFrom"
		$s6 = "FX Global Altitude"
		$s7 = "dwGetStringFromLPSTR"
		$s8 = "Copyright Flag"
		$s9 = "Color Transfer Settings"
		$s10 = "FX Global Lighting Angle"
		$s11 = "Version compatibility info"
		$s12 = "New Windows Thumbnail"
		$s13 = "dwGetWndInstance"
		$s14 = "Layer ID Generator Base"
		$s15 = "Color Halftone Settings"
		$s16 = "C:\\WINDOWS\\SYSTEM\\MSWINSCK.oca"
		$s17 = "u*9:HIJXYZghijvwxyz"
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
		$s2 = "yihc]Zmopooqomlng_jzqrxpggkir|~rvjdmlaapw{xxsnkddbdpzszwmdddcr"
		$s3 = " =BITCHIN THREADS=                                                     ABOUT"
		$s4 = "Progenic Warfare and DarKPaiN cannot accept any responsibility for damage or loss of data to yours or anyone else's computer, through the direct or indirect use of this program. If you disagree with this statement please do not use this program again. Progenic Warfare hearby take NO responsibility for the uses and/or misuses of this program."
		$s5 = "~wxsjcmsv{|~wrprowqotqlp|xsq}m^grtt{vkallknonjghmkpiefd`hvrnp}oel~"
		$s6 = "wvzwldj[WXYab_fjcdb_Y^]\\gibdrijswqpuwootcc_Zcbhplehgllv}xvwov"
		$s7 = "This program is simple to use, first setup the ports to scan for, in 'Port settings...', by checking the relevant one. Then place the start IP address and the ending IP address in the boxes, and let it rip... It will alert you when it finds an address, with the port open..."
		$s8 = "~mc`abcdc`]XXY_bda\\YUQOORUXXY[]fnstttojecefgcaaacdkrx{||{yz}}||}"
		$s9 = "Tikigod, YoriK, MaRviN, SpanX, TinZ, DeathBlade.. and anyone else who would like to be thanked..."
		$s10 = "trwtiqve`^]W\\frutkec\\\\epkpqqkinrnbdooiuuf]^c_bhsrpfilfgpuu{z|tu}"
		$s11 = "|ngeluwtjlirlouvkp|jlwxeepkhz|oqqpgb`lsyzsnkodeoocqyigtw]`ibcy~xzxqhhhz"
		$s12 = "Newer versions of this program are sure to come out... (If I get some feedback..). Any criticism is fine, even if you want me to use different colours, if you have any interesting ports, or trojans you would like added please contact me, DarKPaiN 'Son 'o' Jerel'.. as stated in the About section."
		$s13 = "  =BITCHIN THREADS=                                                   Port Configuration"
		$s14 = "BitchiN ThreadS is a Progenic Warfare Product, created by DarKPaiN."
		$s15 = "=BITCHIN THREADS=                              Anti - NetBuster"
		$s16 = "Webfringe - Puting ProGen's wonderful site on the list   (www.Webfringe.com)"
		$s17 = "'Come to Progenic Warfare, we have many programs fit for a 'hacker' king, we have the one... the only... PUSH! - ICQ chat kicker, TeSla - the much talked about and highley rated ICQ addon system... So come one come all and click on the link above...'"
		$s18 = " =BITCHIN THREADS=                                           General Configuration"
		$s19 = "=BITCHIN THREADS=                                  NetBus Control Panel"
	condition:
		all of them
}
rule cgis4 {
	meta:
		description = "Auto-generated rule on file cgis4.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "d658dad1cd759d7f7d67da010e47ca23"
	strings:
		$s0 = "HBiBa4Yc"
		$s1 = "8^SaHI+m"
		$s2 = "|kax `&z"
		$s3 = "myukAsJ]"
		$s4 = "jUj/9lpk"
		$s5 = ")PuMB_syJ"
		$s6 = "qyIz7gAK"
		$s7 = "KEp'<qYH"
		$s8 = "&,fARW>yR"
		$s9 = "m3hm3t_rullaz"
		$s10 = "7Projectc1"
		$s11 = "Ten-GGl\""
		$s12 = "/Moziqlxa"
	condition:
		all of them
}
rule ITrace32 {
	meta:
		description = "Auto-generated rule on file ITrace32.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b5e51291ec9e61cb2a4ff5c96d4caf32"
	strings:
		$s0 = "[received] %d bytes from %s. not for us"
		$s1 = "can't create raw listen socket %s"
		$s2 = "[sendto] wrote %d bytes, return=%d"
		$s3 = "socket marked as non-blocking and SO_LINGER set not 0"
		$s4 = "round-trip (ms) min/avg/max = %ld/%ld/%ld"
		$s5 = "socket type not supported for address family"
		$s6 = "protocol wrong type for this socket"
		$s7 = "%d packets transmitted, %d packets received, %d%% packet loss"
		$s8 = "%d bytes from %s: icmp_seq=%d time=%ld ms"
		$s9 = "Version: %04x %04x     Max Sockets: %d"
		$s10 = "%d packets transmitted, %d packets received, 100%% packet loss"
		$s11 = "Non-authoritive: host not found or server failure"
		$s12 = "%d bytes %s %s: icmp_type=%d (%s) icmp_code=%d"
		$s13 = "[received] too short (%d bytes) from %s"
		$s14 = "WinSock not present or not responding"
		$s15 = "Valid name, no data record for type"
		$s16 = "ws_ping - copyright (c) 1995 Ipswitch, Inc. 01234567890123"
		$s17 = "Non-recoverable: refused or not implemented"
	condition:
		all of them
}
rule portscan {
	meta:
		description = "Auto-generated rule on file portscan.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "a8bfdb2a925e89a281956b1e3bb32348"
	strings:
		$s0 = "0    :SCAN ABORTED."
		$s1 = "0    :UNABLE TO RESOLVE HOSTNAME."
		$s2 = ":CONFAIL:"
		$s3 = "0    :MAX PORTS. Socket not opened."
		$s4 = ":CLOSE:"
		$s5 = "0    :DEBUG MODE"
		$s6 = "C:\\SPHERE\\DOCS\\SCANLOG.TXT"
		$s7 = "CLOSED"
		$s8 = "0    :SCANNING HOST:"
		$s9 = "0    :RESET - ALL SOCKETS CLOSED"
		$s10 = "0    :SCAN BEGUN ON PORT:"
		$s11 = " - UNDEFINED ERROR."
		$s12 = ":CON_TRY:"
		$s13 = "0    :PORTSCAN READY."
		$s14 = "END PORT INFO"
		$s15 = "NGHNOP"
		$s16 = ":CON_ERR:"
		$s17 = "0    :SCAN HALTED ON PORT:"
		$s18 = ":RECIEVE:"
		$s19 = "-----RESULTS OF SCAN FOLLOW-----"
	condition:
		all of them
}
rule ProPort {
	meta:
		description = "Auto-generated rule on file ProPort.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "c1937a86939d4d12d10fc44b7ab9ab27"
	strings:
		$s0 = "Corrupt Data!"
		$s1 = "7;[quFTX"
		$s2 = "K4p~omkIz"
		$s3 = "k/0aMcuk"
		$s4 = "DllTrojanScan"
		$s5 = "GetDllInfo"
		$s6 = "hnuR07+}"
		$s7 = "tfak.DLL"
		$s8 = "PiSu(Ma4"
		$s9 = "Compressed by Petite (c)1999 Ian Luck."
		$s10 = "DphUB|A2"
		$s11 = "@.petite"
		$s12 = "mQSeZr_]"
		$s13 = "GetFileCRC32"
		$s14 = "GetTrojanNumber"
		$s15 = "TFAKAbout"
		$s16 = "ZIwD$MWZ"
	condition:
		all of them
}
rule StealthWasp_s_Basic_PortScanner_v1_2 {
	meta:
		description = "Auto-generated rule on file StealthWasp's Basic PortScanner v1.2.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "7c0f2cab134534cd35964fe4c6a1ff00"
	strings:
		$s0 = "cmdAboutDown"
		$s1 = "cmdScanDown"
		$s2 = "StealthWasp's Basic PortScanner v1.2"
		$s3 = "Basic PortScanner"
		$s4 = "Mswinsck.ocx"
		$s5 = "C:\\Programfiler\\Microsoft Visual Studio\\VB98\\VB6.OLB"
		$s6 = "cmdAbortDown"
		$s7 = "cmdExitDown"
		$s8 = "PortScanner"
		$s9 = "frmPortScan"
		$s10 = "StealthWasp's Basic PortScanner"
		$s11 = "MS Sans Serif0"
		$s12 = "MS Sans Serif'"
		$s13 = "cmdClearDown"
		$s14 = "txtPortStart"
		$s15 = "lblPortFrom"
		$s16 = "Now scanning port:"
		$s17 = "txtPortStop"
		$s18 = "KAs0XNsaUNs"
		$s19 = "C:\\WINDOWS\\System32\\Mswinsck.oca"
	condition:
		all of them
}
rule BluesPortScan {
	meta:
		description = "Auto-generated rule on file BluesPortScan.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "6292f5fc737511f91af5e35643fc9eef"
	strings:
		$s0 = "#1bihw1("
		$s1 = "This program was made by Volker Voss"
		$s2 = "JiBOo~SSB"
		$s3 = "K1hOd[Fh"
		$s4 = "kfu?)BIw"
		$s5 = "\\{z9Qik"
		$s6 = "QtfegD{ "
		$s7 = "LIM!FJ\""
		$s8 = "The procedure entry point %s could not be located in the dynamic link library %s"
		$s9 = "FDb[viql|"
		$s10 = "x]0BBobo"
		$s11 = "The ordinal %u could not be located in the dynamic link library %s"
	condition:
		all of them
}
rule iis {
	meta:
		description = "Auto-generated rule on file iis.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "3a8fc02c62c8dd65e038cc03e5451b6e"
	strings:
		$s0 = "#1bihw1("
		$s1 = "This program was made by Volker Voss"
		$s2 = "JiBOo~SSB"
		$s3 = "K1hOd[Fh"
		$s4 = "kfu?)BIw"
		$s5 = "\\{z9Qik"
		$s6 = "QtfegD{ "
		$s7 = "LIM!FJ\""
		$s8 = "The procedure entry point %s could not be located in the dynamic link library %s"
		$s9 = "FDb[viql|"
		$s10 = "x]0BBobo"
		$s11 = "The ordinal %u could not be located in the dynamic link library %s"
	condition:
		all of them
}
rule Stealth {
	meta:
		description = "Auto-generated rule on file Stealth.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "8ce3a386ce0eae10fc2ce0177bbc8ffa"
	strings:
		$s0 = "<HTTP Scan Report (*.html)|*.html|Todos os arquivos (*.*)|*.*"
		$s1 = "\" cellspacing=\"0\" cellpadding=\"2\" border=\"1\" bordercolor=\"white\"><tr><td>"
		$s2 = "This tool may be used only by system administrators. I am not responsible for any damages, direct or indirect, caused by usage of this tool."
		$s3 = ";Comments : This is a cryptographic component for Delphi 2.0"
		$s4 = "~~~~~~~~~~~^~~~_TUVWXYZ[\\]~~~|~~~ !\"#$%&'()*+,-./0123456789~~~~~~:;<=>?@ABCDEFGHIJKLMNOPQRS"
		$s5 = "<table width=\"60%\" bgcolor=\"black\" cellspacing=\"0\" cellpadding=\"2\" border=\"1\" bordercolor=\"white\"><tr><td>"
		$s6 = "<font face=\"Tahoma,Verdana,Arial\" size=\"2\" color=\"white\">"
		$s7 = "Esta ferramenta pode ser usada somente pelo administrador do sistema. N"
		$s8 = "Stealth 1.0a. Escrito por Felipe Moniz. +55-21-9203.8587"
		$s9 = "Greetings to Andre Freitas, David Alexandre, Fabricio Leite, Marcelo Caffaro and Paulo Lopes."
		$s10 = "5Stealth 1.0a. Coded by Felipe Moniz. +55-21-9203.8587"
		$s11 = "<table width=\"60%\" bgcolor=\"white\" cellspacing=\"0\" cellpadding=\"2\" border=\"1\" bordercolor=\"white\"><tr><td>"
		$s12 = "NThis tool may be used only by system administrators. I am not responsible for "
		$s13 = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_ "
		$s14 = "`!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_"
		$s15 = " Freitas, David Alexandre, Fabricio Leite, Marcelo Caffaro e Paulo Lopes."
		$s16 = "o me responsabilizo por danos, diretos ou indiretos, causados pelo uso desta ferramenta."
		$s17 = ">any damages, direct or indirect, caused by usage of this tool."
		$s18 = "MGreetings to Andre Freitas, David Alexandre, Fabricio Leite, Marcelo Caffaro "
		$s19 = "System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x"
	condition:
		all of them
}
rule Loader {
	meta:
		description = "Auto-generated rule on file Loader.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "f4f79358a6c600c1f0ba1f7e4879a16d"
	strings:
		$s0 = "UserExcep"
		$s1 = "BTempWndO"
		$s2 = "Ghid7the\""
		$s3 = "_softwaref"
		$s4 = "XOTHREAQ%"
		$s5 = "_H/EnumDisplay/"
		$s6 = "Wad^wkkAjukA\""
		$s7 = "?\\6cuxg1"
		$s8 = "=h spacGf"
		$s9 = "AfxOldhProc423"
		$s10 = "ar%&MDIFrame\""
		$s11 = "EOhl'CDialogK"
		$s12 = "uECTED.MSVCRT0x"
		$s13 = "[3FoR8P3S"
		$s14 = " VisTC++ R9Li"
		$s15 = "akoverwriPh"
		$s16 = "@ROrgI@##"
		$s17 = "NotSupported7"
	condition:
		all of them
}
