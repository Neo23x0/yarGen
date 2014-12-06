rule sig_4d4b17ddbcf4ce397f76cf0a2e230c9d513b23065f746a5ee2de74f447be39b9 {
	meta:
		description = "Auto-generated rule - file 4d4b17ddbcf4ce397f76cf0a2e230c9d513b23065f746a5ee2de74f447be39b9"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2014/12/06"
		hash = "7e2561eb67a6ead09f727d98b71c01f18985bbb9"
	strings:
		$s0 = "cmd.exe /c wmic.exe /node:\"%s\" /user:\"%s\" /password:\"%s\" PROCESS CALL CREA" ascii
		$s1 = "cmd.exe /q /c net share shared$=%SystemRoot%" fullword ascii
		$s2 = "cmd.exe /q /c net share shared$ /delete" fullword ascii
		$s3 = "cmd.exe /q /c net share shared$=%SystemRoot% /GRANT:everyone,FULL" fullword ascii
		$s4 = "taskhosts64.exe" fullword ascii
		$s5 = "Hello Version 1.0" fullword wide
		$s6 = "\\\\%s\\shared$\\system32" fullword ascii
		$s7 = "Windows Schedule Management Service" fullword ascii
		$s8 = "\\\\%s\\admin$\\system32" fullword ascii
		$s9 = "comon32.exe" fullword ascii
		$s10 = "rdpshellex32.exe" fullword ascii
		$s11 = "expandmn32.exe" fullword ascii
		$s12 = "diskpartmg16.exe" fullword ascii
		$s13 = "hwrcompsvc64.exe" fullword ascii
		$s14 = "net_ver.dat" fullword ascii
		$s15 = "Hello World!" fullword wide
		$s16 = "mobsynclm64.exe" fullword ascii
		$s17 = "recdiscm32.exe" fullword ascii
		$s18 = "taskchg16.exe" fullword ascii
		$s19 = "igfxtrayex.exe" fullword ascii
		$s20 = "\\\\%s\\shared$\\syswow64" fullword ascii
	condition:
		all of them
}
