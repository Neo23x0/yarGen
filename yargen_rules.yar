rule AppCompatCache {
	meta:
		description = "Auto-generated rule - file AppCompatCache.exe"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015/01/05"
		hash = "bd38efcd5d56e903c4aaeaf44f1d6fd527301224"
	strings:
		$s0 = "\\SystemRoot\\AppPatch\\sysmain.sdb" fullword wide
		$s1 = "Calling %ls on %ls with command line %ls" fullword ascii
		$s2 = "Failed to get SDB tag for regsvr32" fullword ascii
		$s3 = "Error getting token user %d" fullword ascii
		$s4 = "Couldn't get fullpath to dll %d" fullword ascii
		$s5 = "C:\\sourcecode\\Eop_AppCompatCache\\Release\\AppCompatCache.pdb" fullword ascii
		$s6 = "Found regsvr32.exe tag: %08X" fullword ascii
		$s7 = "Error '%ls' occurred during operation" fullword wide
		$s8 = "Check for FakeInterface" fullword ascii
		$s9 = "Failed to load kernel32" fullword ascii
		$s10 = "Failed to load SDB file %d" fullword ascii
		$s11 = "Error opening file %ls %d" fullword ascii
		$s12 = "Failed to load apphelp" fullword ascii
		$s13 = "<requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
		$s14 = ":#:):6:Q:\\:d:i:q:w:~:" fullword ascii
		$s15 = "GetFileInformationByHandleExW" fullword ascii
		$s16 = "Error opening token %d" fullword ascii
		$s17 = "344L4e4" fullword ascii
		$s18 = "nIDispatch error #%d" fullword wide
		$s19 = ".?AVFakeObject@@" fullword ascii
		$s20 = "<$<?<X<i<" fullword ascii
	condition:
		all of them
}
rule TestDLL_vcxproj {
	meta:
		description = "Auto-generated rule - file TestDLL.vcxproj.filters"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015/01/05"
		hash = "ecbbf57771faa4d4ceac600df28645cf71d8333a"
	strings:
		$s0 = "<ClCompile Include=\"dllmain.cpp\">" fullword ascii
		$s1 = "<Project ToolsVersion=\"4.0\" xmlns=\"http://schemas.microsoft.com/developer/msb" ascii
		$s2 = "<ClCompile Include=\"TestDLL.cpp\">" fullword ascii
		$s3 = "<None Include=\"testdll.def\">" fullword ascii
		$s4 = "<ClCompile Include=\"stdafx.cpp\">" fullword ascii
		$s5 = "<ClInclude Include=\"targetver.h\">" fullword ascii
		$s6 = "<Filter Include=\"Resource Files\">" fullword ascii
		$s7 = "<Filter Include=\"Source Files\">" fullword ascii
		$s8 = "<Filter Include=\"Header Files\">" fullword ascii
		$s9 = "<Extensions>h;hh;hpp;hxx;hm;inl;inc;xsd</Extensions>" fullword ascii
		$s10 = "<Filter>Source Files</Filter>" fullword ascii
		$s11 = "<Filter>Header Files</Filter>" fullword ascii
		$s12 = "<ClInclude Include=\"stdafx.h\">" fullword ascii
		$s13 = "</None>" fullword ascii
		$s14 = "</Filter>" fullword ascii
		$s15 = "</ClInclude>" fullword ascii
		$s16 = "</Project>" fullword ascii
		$s17 = "<UniqueIdentifier>{4FC737F1-C7A5-4376-A066-2A32D752A2FF}</UniqueIdentifier>" fullword ascii
		$s18 = "<UniqueIdentifier>{67DA6AB6-F800-4c08-8B7A-83BB121AAD01}</UniqueIdentifier>" fullword ascii
		$s19 = "<UniqueIdentifier>{93995380-89BD-4b04-88EB-625FBE52EBFB}</UniqueIdentifier>" fullword ascii
		$s20 = "<Extensions>cpp;c;cc;cxx;def;odl;idl;hpj;bat;asm;asmx</Extensions>" fullword ascii
	condition:
		all of them
}
rule TestDLL_dllmain {
	meta:
		description = "Auto-generated rule - file dllmain.cpp"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015/01/05"
		hash = "67c347b1f2f8712b0cabb60e7e111ca1b3171f38"
	strings:
		$s0 = "case DLL_PROCESS_ATTACH:" fullword ascii
		$s1 = "case DLL_PROCESS_DETACH:" fullword ascii
		$s2 = "// dllmain.cpp : Defines the entry point for the DLL application." fullword ascii
		$s3 = "BOOL APIENTRY DllMain( HMODULE hModule," fullword ascii
		$s4 = "LPVOID lpReserved" fullword ascii
		$s5 = "#include \"stdafx.h\"" fullword ascii
		$s6 = "DWORD  ul_reason_for_call," fullword ascii
		$s7 = "switch (ul_reason_for_call)" fullword ascii
		$s8 = "case DLL_THREAD_ATTACH:" fullword ascii
		$s9 = "case DLL_THREAD_DETACH:" fullword ascii
	condition:
		all of them
}
rule TestDLL_testdll {
	meta:
		description = "Auto-generated rule - file testdll.def"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015/01/05"
		hash = "d4db4ec91c35cf0584c5d365d7882e9c75c58cf7"
	strings:
		$s0 = "DllRegisterServer PRIVATE" fullword ascii
	condition:
		all of them
}
rule AppCompatCache_sdb {
	meta:
		description = "Auto-generated rule - file sdb.h"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015/01/05"
		hash = "9131981d69e51ff3d0d0ec78ab4c7271edd1090e"
	strings:
		$s0 = "#define TAG_COMMAND_LINE (0x8 | TAG_TYPE_STRINGREF)  //Command line attribute th" ascii
		$s1 = "typedef BOOL (WINAPI *SdbGetTagDataSize)(PDB pdb, TAG tTag);" fullword ascii
		$s2 = "typedef DWORD (WINAPI* SdbGetShowDebugInfoOption)();" fullword ascii
		$s3 = "list of conditions and the following disclaimer." fullword ascii
		$s4 = "and/or other materials provided with the distribution." fullword ascii
		$s5 = "#define TAG_FLAG_PROCESSPARAM (0xF | TAG_TYPE_QWORD)  //Process param flag attri" ascii
		$s6 = "SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE." fullword ascii
		$s7 = "//functions " fullword ascii
		$s8 = "#define TAG_VERDATELO (0x8 | TAG_TYPE_DWORD)  //Low-order portion of the file ve" ascii
		$s9 = "#define TAG_VERDATEHI (0x7 | TAG_TYPE_DWORD)  //High-order portion of the file v" ascii
		$s10 = "either expressed or implied, of the FreeBSD Project." fullword ascii
		$s11 = "typedef void (WINAPI *SdbCloseDatabaseWrite)(PDB pdb);" fullword ascii
		$s12 = "typedef TAGID (WINAPI *SdbGetIndex)(PDB pdb, TAG tWhich, TAG tKey, LPDWORD lpdwF" ascii
		$s13 = "typedef void (WINAPI *SdbCloseDatabase)(PDB pdb);" fullword ascii
		$s14 = "#define TAG_EXPORT_NAME (0x24 | TAG_TYPE_STRINGREF)  //Export file name attribut" ascii
		$s15 = "#define ATTRIBUTE_FAILED 0x00000002" fullword ascii
		$s16 = "#define TAG_NAME (0x1 | TAG_TYPE_STRINGREF)  //Name attribute." fullword ascii
		$s17 = "#define TAG_ACTION_TYPE (0x23 | TAG_TYPE_STRINGREF)  //Unused." fullword ascii
		$s18 = "#define TAG_LIBRARY (0x2 | TAG_TYPE_LIST) //Library entry." fullword ascii
		$s19 = "#define TAG_SIZE (0x1 | TAG_TYPE_DWORD)  //File size attribute." fullword ascii
		$s20 = "#define TAG_EXE (0x7 | TAG_TYPE_LIST) //Executable entry." fullword ascii
	condition:
		all of them
}
rule TestDLL_stdafx {
	meta:
		description = "Auto-generated rule - file stdafx.h"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015/01/05"
		hash = "0f66aa1606fa0509600abc833addd6ed892adfb8"
	strings:
		$s0 = "#include \"targetver.h\"" fullword ascii
		$s1 = "// stdafx.h : include file for standard system include files," fullword ascii
		$s2 = "// are changed infrequently" fullword ascii
		$s3 = "// Windows Header Files:" fullword ascii
		$s4 = "// TODO: reference additional headers your program requires here" fullword ascii
		$s5 = "// or project specific include files that are used frequently, but" fullword ascii
		$s6 = "#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Window" ascii
	condition:
		all of them
}
rule CaptureImpersonationToken {
	meta:
		description = "Auto-generated rule - file CaptureImpersonationToken.cpp"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015/01/05"
		hash = "27794d13fceab7f04601384ead602e062040a77d"
	strings:
		$s0 = "printf(\"Error getting token user %d\\n\", GetLastError());" fullword ascii
		$s1 = "ConvertSidToStringSid(user->User.Sid, &sid_name);" fullword ascii
		$s2 = "printf(\"Error opening token %d\\n\", GetLastError());" fullword ascii
		$s3 = "CreatePointerMoniker(new FakeObject(ptoken), &pNotify);" fullword ascii
		$s4 = "printf(\"Check for FakeInterface\\n\");" fullword ascii
		$s5 = "wprintf(L\"Error '%ls' occurred during operation\", ex.ErrorMessage());" fullword ascii
		$s6 = "FakeObject(HANDLE* ptoken) {" fullword ascii
		$s7 = "else if (riid == IID_FakeInterface)" fullword ascii
		$s8 = "if (OpenThreadToken(GetCurrentThread(), MAXIMUM_ALLOWED, FALSE, &hToken))" fullword ascii
		$s9 = "// Failed to connect." fullword ascii
		$s10 = "if (GetTokenInformation(hToken, TokenUser, user, 0x1000, &ret_len))" fullword ascii
		$s11 = "hr = CoCreateInstance(__uuidof(BackgroundCopyManager), NULL," fullword ascii
		$s12 = "~FakeObject() {};" fullword ascii
		$s13 = "ULONG  ulCount = InterlockedDecrement(&m_lRefCount);" fullword ascii
		$s14 = "printf(\"Got Token: %p %ls\\n\", hToken, sid_name);" fullword ascii
		$s15 = "throw _com_error(hr);" fullword ascii
		$s16 = "PTOKEN_USER user = (PTOKEN_USER)malloc(0x1000);" fullword ascii
		$s17 = "return InterlockedIncrement(&m_lRefCount);" fullword ascii
		$s18 = "HRESULT hr = CoImpersonateClient();" fullword ascii
		$s19 = "class FakeObject : public IUnknown" fullword ascii
		$s20 = "delete this;" fullword ascii
	condition:
		all of them
}
rule Windows8_PrivEsc_PoC_poc {
	meta:
		description = "Auto-generated rule - file poc.zip"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015/01/05"
		hash = "55fc0b24399b2f5b61379a401be0258760061644"
	strings:
		$s0 = "src/AppCompatCache/sdb_functions.cpp" fullword ascii
		$s1 = "src/AppCompatCache/CaptureImpersonationToken.cpp" fullword ascii
		$s2 = "src/TestDLL/dllmain.cpp}" fullword ascii
		$s3 = "src/TestDLL/dllmain.cpp" fullword ascii
		$s4 = "src/TestDLL/testdll.def" fullword ascii
		$s5 = "bin/TestDLL.dll" fullword ascii
		$s6 = "src/TestDLL/TestDLL.cpp" fullword ascii
		$s7 = "src/TestDLL/stdafx.cpp" fullword ascii
		$s8 = "src/TestDLL/targetver.he" fullword ascii
		$s9 = "src/AppCompatCache/AppCompatCache.cpp" fullword ascii
		$s10 = "src/TestDLL/TestDLL.vcxproj.filters" fullword ascii
		$s11 = "(:e3r " fullword ascii
		$s12 = "src/TestDLL/testdll.defLIBRARY" fullword ascii
		$s13 = "?=/cer" fullword ascii
		$s14 = "-1`+ 6T" fullword ascii
		$s15 = "src/TestDLL/targetver.h" fullword ascii
		$s16 = "src/AppCompatCache/AppCompatCache.vcxproj.filters" fullword ascii
		$s17 = "src/TestDLL/TestDLL.vcxproj" fullword ascii
		$s18 = "bin/AppCompatCache.exe" fullword ascii
		$s19 = "src/TestDLL/stdafx.hUPAj" fullword ascii
		$s20 = "src/TestDLL/stdafx.cppeP=k" fullword ascii
	condition:
		all of them
}
rule TestDLL_TestDLL {
	meta:
		description = "Auto-generated rule - file TestDLL.cpp"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015/01/05"
		hash = "e1159927c1d39fa255156e0b967f02453c72a5a1"
	strings:
		$s0 = "// TestDLL.cpp : Defines the exported functions for the DLL application." fullword ascii
		$s1 = "return S_OK;" fullword ascii
		$s2 = "HRESULT __stdcall DllRegisterServer(void)" fullword ascii
		$s3 = "#include \"stdafx.h\"" fullword ascii
		$s4 = "WinExec(\"calc\", SW_SHOW);" fullword ascii
	condition:
		all of them
}
rule TestDLL_TestDLL_2 {
	meta:
		description = "Auto-generated rule - file TestDLL.vcxproj"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015/01/05"
		hash = "b8e26c7740c01c15697565732d13dd92b56b7719"
	strings:
		$s0 = "<Import Project=\"$(VCTargetsPath)\\Microsoft.Cpp.props\" />" fullword ascii
		$s1 = "<Import Project=\"$(VCTargetsPath)\\Microsoft.Cpp.targets\" />" fullword ascii
		$s2 = "<Import Project=\"$(VCTargetsPath)\\Microsoft.Cpp.Default.props\" />" fullword ascii
		$s3 = "<ImportGroup Label=\"ExtensionTargets\">" fullword ascii
		$s4 = "<Project DefaultTargets=\"Build\" ToolsVersion=\"12.0\" xmlns=\"http://schemas.m" ascii
		$s5 = "<ModuleDefinitionFile>testdll.def</ModuleDefinitionFile>" fullword ascii
		$s6 = "<Import Project=\"$(UserRootDir)\\Microsoft.Cpp.$(Platform).user.props\" Conditi" ascii
		$s7 = "<PreprocessorDefinitions>WIN32;_DEBUG;_WINDOWS;_USRDLL;TESTDLL_EXPORTS;%(Preproc" ascii
		$s8 = "<PreprocessorDefinitions>WIN32;NDEBUG;_WINDOWS;_USRDLL;TESTDLL_EXPORTS;%(Preproc" ascii
		$s9 = "<FunctionLevelLinking>true</FunctionLevelLinking>" fullword ascii
		$s10 = "<ImportGroup Label=\"ExtensionSettings\">" fullword ascii
		$s11 = "<None Include=\"testdll.def\" />" fullword ascii
		$s12 = "<ClCompile Include=\"dllmain.cpp\">" fullword ascii
		$s13 = "<IntrinsicFunctions>true</IntrinsicFunctions>" fullword ascii
		$s14 = "<ClCompile Include=\"TestDLL.cpp\" />" fullword ascii
		$s15 = "<ClCompile Include=\"stdafx.cpp\">" fullword ascii
		$s16 = "<ClInclude Include=\"targetver.h\" />" fullword ascii
		$s17 = "<GenerateDebugInformation>true</GenerateDebugInformation>" fullword ascii
		$s18 = "<ImportGroup Label=\"PropertySheets\" Condition=\"'$(Configuration)|$(Platform)'" ascii
		$s19 = "<WholeProgramOptimization>true</WholeProgramOptimization>" fullword ascii
		$s20 = "<ImportGroup Label=\"PropertySheets\" Condition=\"'$(Configuration)|$(Platform)'" ascii
	condition:
		all of them
}
rule AppCompatCache_2 {
	meta:
		description = "Auto-generated rule - file AppCompatCache.sln"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015/01/05"
		hash = "81bcc9b8c762e47eedd58299950b86848d0d85e0"
	strings:
		$s0 = "GlobalSection(ProjectConfigurationPlatforms) = postSolution" fullword ascii
		$s1 = "Microsoft Visual Studio Solution File, Format Version 12.00" fullword ascii
		$s2 = "MinimumVisualStudioVersion = 10.0.40219.1" fullword ascii
		$s3 = "VisualStudioVersion = 12.0.30723.0" fullword ascii
		$s4 = "GlobalSection(SolutionConfigurationPlatforms) = preSolution" fullword ascii
		$s5 = "Release|Mixed Platforms = Release|Mixed Platforms" fullword ascii
		$s6 = "GlobalSection(SolutionProperties) = preSolution" fullword ascii
		$s7 = "Release|Win32 = Release|Win32" fullword ascii
		$s8 = "Release|Any CPU = Release|Any CPU" fullword ascii
		$s9 = "Debug|Mixed Platforms = Debug|Mixed Platforms" fullword ascii
		$s10 = "{12A423A9-187F-4CB3-8AF2-901682BFC5AF}.Release|Mixed Platforms.Build.0 = Release" ascii
		$s11 = "{12A423A9-187F-4CB3-8AF2-901682BFC5AF}.Release|Mixed Platforms.ActiveCfg = Relea" ascii
		$s12 = "HideSolutionNode = FALSE" fullword ascii
		$s13 = "{12A423A9-187F-4CB3-8AF2-901682BFC5AF}.Release|Win32.Build.0 = Release|Win32" fullword ascii
		$s14 = "{12A423A9-187F-4CB3-8AF2-901682BFC5AF}.Release|Win32.ActiveCfg = Release|Win32" fullword ascii
		$s15 = "{12A423A9-187F-4CB3-8AF2-901682BFC5AF}.Release|Any CPU.ActiveCfg = Release|Win32" fullword ascii
		$s16 = "{12A423A9-187F-4CB3-8AF2-901682BFC5AF}.Debug|Mixed Platforms.Build.0 = Debug|Win" ascii
		$s17 = "{12A423A9-187F-4CB3-8AF2-901682BFC5AF}.Debug|Mixed Platforms.ActiveCfg = Debug|W" ascii
		$s18 = "{12A423A9-187F-4CB3-8AF2-901682BFC5AF}.Debug|Any CPU.ActiveCfg = Debug|Win32" fullword ascii
		$s19 = "{12A423A9-187F-4CB3-8AF2-901682BFC5AF}.Debug|Win32.Build.0 = Debug|Win32" fullword ascii
		$s20 = "{12A423A9-187F-4CB3-8AF2-901682BFC5AF}.Debug|Win32.ActiveCfg = Debug|Win32" fullword ascii
	condition:
		all of them
}
rule TestDLL_stdafx_2 {
	meta:
		description = "Auto-generated rule - file stdafx.cpp"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015/01/05"
		hash = "e0ab78773769e7d9e2212d6f522d2cbbc3e8136f"
	strings:
		$s0 = "// stdafx.obj will contain the pre-compiled type information" fullword ascii
		$s1 = "// TestDLL.pch will be the pre-compiled header" fullword ascii
		$s2 = "// stdafx.cpp : source file that includes just the standard includes" fullword ascii
		$s3 = "// TODO: reference any additional headers you need in STDAFX.H" fullword ascii
		$s4 = "// and not in this file" fullword ascii
		$s5 = "#include \"stdafx.h\"" fullword ascii
	condition:
		all of them
}
rule targetver {
	meta:
		description = "Auto-generated rule - file targetver.h"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015/01/05"
		hash = "03ad3cc7b864b3e1b0a198f35e01381c27a5cfbf"
	strings:
		$s0 = "// set the _WIN32_WINNT macro to the platform you wish to support before includi" ascii
		$s1 = "// Including SDKDDKVer.h defines the highest available Windows platform." fullword ascii
		$s2 = "#include <SDKDDKVer.h>" fullword ascii
		$s3 = "// If you wish to build your application for a previous Windows platform, includ" ascii
	condition:
		all of them
}
rule AppCompatCache_3 {
	meta:
		description = "Auto-generated rule - file AppCompatCache.cpp"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015/01/05"
		hash = "c5f105f9058ab074942da2c5726944317b072873"
	strings:
		$s0 = "printf(\"Couldn't get fullpath to dll %d\\n\", GetLastError());" fullword ascii
		$s1 = "printf(\"Failed to get SDB tag for regsvr32\\n\");" fullword ascii
		$s2 = "printf(\"Found regsvr32.exe tag: %08X\\n\", tag);" fullword ascii
		$s3 = "HANDLE process_handle;" fullword ascii
		$s4 = "status = GetLastError();" fullword ascii
		$s5 = "enum APPHELPCOMMAND" fullword ascii
		$s6 = "DWORD stat = GetLastError();" fullword ascii
		$s7 = "PDB db = SdbOpenDatabasePtr(L\"\\\\SystemRoot\\\\AppPatch\\\\sysmain.sdb\", NT_P" ascii
		$s8 = "if (!GetFullPathName(argv[2], MAX_PATH, dllpath_buf, nullptr))" fullword ascii
		$s9 = "// process tag types" fullword ascii
		$s10 = "fRtlInitUnicodeString(&data.file_name, full_path.c_str());" fullword ascii
		$s11 = "AppHelpEnum,  // 3 -> 0x2200F (Admin) (Looks unused)" fullword ascii
		$s12 = "printf(\"Error opening file %ls %d\\n\", argv[1], GetLastError());" fullword ascii
		$s13 = "AppHelpForward, // 7 -> 0x22001F (looks to forward communication to helper servi" ascii
		$s14 = "extern SdbGetTagFromTagID SdbGetTagFromTagIDPtr;" fullword ascii
		$s15 = "if (data.file_handle == INVALID_HANDLE_VALUE)" fullword ascii
		$s16 = "printf(\"Failed to load SDB file %d\\n\", stat);" fullword ascii
		$s17 = "int status = -1;" fullword ascii
		$s18 = "AppHelpQuery, // 0 -> 0x22003 DeviceIoControl" fullword ascii
		$s19 = "AppHelpWriteRegistry, // 5 -> 0x220017 (Admin)" fullword ascii
		$s20 = "newtid = SdbGetNextChildPtr(db, tid, newtid);" fullword ascii
	condition:
		all of them
}
rule bin_TestDLL {
	meta:
		description = "Auto-generated rule - file TestDLL.dll"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015/01/05"
		hash = "e02c187a84afc2eac5eae1dca4d2c2a2220191dc"
	strings:
		$s0 = "C:\\sourcecode\\Eop_AppCompatCache\\Release\\TestDLL.pdb" fullword ascii
		$s1 = "78:<:@:D:H:L:P:T:X:\\:`:h:" fullword ascii
		$s2 = "<requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
		$s3 = "GetFileInformationByHandleExW" fullword ascii
		$s4 = "TestDLL.dll" fullword ascii
		$s5 = ":N:T:X:\\:`:" fullword ascii
		$s6 = "343e3r3{3" fullword ascii
		$s7 = "SetFileInformationByHandleW" fullword ascii
		$s8 = "2 2$2(2,202<2@2D2H2L2P2T2X2\\2`2d2h2l2p2t2x2|2" fullword ascii
		$s9 = ";B<y<)=" fullword ascii
		$s10 = "6 6(6-636;6@6F6N6S6Y6a6f6l6t6y6~6" fullword ascii
		$s11 = "::0:g:o:" fullword ascii
		$s12 = "77$7*72777=7E7J7P7X7]7c7k7p7v7~7" fullword ascii
		$s13 = "0L0S0i0s0" fullword ascii
		$s14 = "9%9.949:9X9e9m9" fullword ascii
		$s15 = "4L8P8T8X8\\8`8d8h8l8p8t8x8[=" fullword ascii
		$s16 = "5#5;5N5T5Z5a5j5o5u5}5" fullword ascii
		$s17 = "0\"020j0o0y0" fullword ascii
		$s18 = "3&3E3`3l3{3" fullword ascii
		$s19 = "?;?B?i?v?{?" fullword ascii
		$s20 = "3N3T3Z3`3f3l3s3z3" fullword ascii
	condition:
		all of them
}
rule AppCompatCache_stdafx {
	meta:
		description = "Auto-generated rule - file stdafx.h"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015/01/05"
		hash = "d184e7076ca201ea615e22950d9f1a91ac1f2975"
	strings:
		$s0 = "#include \"targetver.h\"" fullword ascii
		$s1 = "// stdafx.h : include file for standard system include files," fullword ascii
		$s2 = "// are changed infrequently" fullword ascii
		$s3 = "#define WIN32_NO_STATUS 1" fullword ascii
		$s4 = "#undef WIN32_NO_STATUS" fullword ascii
		$s5 = "#include <Windows.h>" fullword ascii
		$s6 = "#include <ntstatus.h>" fullword ascii
		$s7 = "// or project specific include files that are used frequently, but" fullword ascii
		$s8 = "#include <winternl.h>" fullword ascii
		$s9 = "#include <tchar.h>" fullword ascii
	condition:
		all of them
}
rule sdb_functions {
	meta:
		description = "Auto-generated rule - file sdb_functions.cpp"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015/01/05"
		hash = "d7be79b3f81eb90946779385d00b18f5d12495e8"
	strings:
		$s0 = "kernel32dll = LoadLibraryA(\"kernel32.dll\");" fullword ascii
		$s1 = "SdbGetShowDebugInfoOption SdbGetShowDebugInfoOptionPtr = NULL;" fullword ascii
		$s2 = "apphelpdll = LoadLibraryA(\"apphelp.dll\");" fullword ascii
		$s3 = "SdbGetFileAttributes SdbGetFileAttributesPtr = NULL;" fullword ascii
		$s4 = "SdbGetStringTagPtr SdbGetStringTagPtrPtr = NULL;" fullword ascii
		$s5 = "SdbGetBinaryTagData SdbGetBinaryTagDataPtr = NULL;" fullword ascii
		$s6 = "SdbGetTagFromTagID SdbGetTagFromTagIDPtr = NULL;" fullword ascii
		$s7 = "SdbMakeIndexKeyFromString SdbMakeIndexKeyFromStringPtr = NULL;" fullword ascii
		$s8 = "SdbGetMatchingExe SdbGetMatchingExePtr = NULL;" fullword ascii
		$s9 = "fprintf(stderr, \"Failed to load kernel32\\n\");" fullword ascii
		$s10 = "SdbGetTagDataSize SdbGetTagDataSizePtr = NULL;" fullword ascii
		$s11 = "SdbGetAppPatchDir SdbGetAppPatchDirPtr = NULL;" fullword ascii
		$s12 = "SdbGetFirstChild SdbGetFirstChildPtr = NULL;" fullword ascii
		$s13 = "SdbGetNextChild SdbGetNextChildPtr = NULL;" fullword ascii
		$s14 = "SdbCloseDatabaseWrite SdbCloseDatabaseWritePtr = NULL;" fullword ascii
		$s15 = "SdbGetIndex SdbGetIndexPtr = NULL;" fullword ascii
		$s16 = "|| !SdbGetShowDebugInfoOptionPtr)" fullword ascii
		$s17 = "fprintf(stderr, \"Failed to load apphelp\\n\");" fullword ascii
		$s18 = "BOOL resolveSdbFunctions()" fullword ascii
		$s19 = "SdbCloseDatabase SdbCloseDatabasePtr = NULL;" fullword ascii
		$s20 = "SdbCloseDatabaseWritePtr = (SdbCloseDatabaseWrite)GetProcAddress(apphelpdll, \"S" ascii
	condition:
		all of them
}
rule AppCompatCache_stdafx_2 {
	meta:
		description = "Auto-generated rule - file stdafx.cpp"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015/01/05"
		hash = "7f263f0005ca0a094399b71203fc2314edbf7865"
	strings:
		$s0 = "// stdafx.obj will contain the pre-compiled type information" fullword ascii
		$s1 = "// AppCompatCache.pch will be the pre-compiled header" fullword ascii
		$s2 = "// stdafx.cpp : source file that includes just the standard includes" fullword ascii
		$s3 = "// TODO: reference any additional headers you need in STDAFX.H" fullword ascii
		$s4 = "// and not in this file" fullword ascii
		$s5 = "#include \"stdafx.h\"" fullword ascii
	condition:
		all of them
}
rule AppCompatCache_4 {
	meta:
		description = "Auto-generated rule - file AppCompatCache.vcxproj"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015/01/05"
		hash = "f8746a23d9f5d1bb70d30ea1d89104f87905dcdb"
	strings:
		$s0 = "<Import Project=\"$(VCTargetsPath)\\Microsoft.Cpp.props\" />" fullword ascii
		$s1 = "<Import Project=\"$(VCTargetsPath)\\Microsoft.Cpp.targets\" />" fullword ascii
		$s2 = "<Import Project=\"$(VCTargetsPath)\\Microsoft.Cpp.Default.props\" />" fullword ascii
		$s3 = "<ImportGroup Label=\"ExtensionTargets\">" fullword ascii
		$s4 = "<ClCompile Include=\"sdb_functions.cpp\" />" fullword ascii
		$s5 = "<Project DefaultTargets=\"Build\" ToolsVersion=\"12.0\" xmlns=\"http://schemas.m" ascii
		$s6 = "<Import Project=\"$(UserRootDir)\\Microsoft.Cpp.$(Platform).user.props\" Conditi" ascii
		$s7 = "<FunctionLevelLinking>true</FunctionLevelLinking>" fullword ascii
		$s8 = "<ImportGroup Label=\"ExtensionSettings\">" fullword ascii
		$s9 = "<IntrinsicFunctions>true</IntrinsicFunctions>" fullword ascii
		$s10 = "<ClCompile Include=\"stdafx.cpp\">" fullword ascii
		$s11 = "<PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;_LIB;%(PreprocessorDefinitions)</" ascii
		$s12 = "<PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;_LIB;%(PreprocessorDefinitions)</" ascii
		$s13 = "<ClCompile Include=\"CaptureImpersonationToken.cpp\" />" fullword ascii
		$s14 = "<ClInclude Include=\"targetver.h\" />" fullword ascii
		$s15 = "<GenerateDebugInformation>true</GenerateDebugInformation>" fullword ascii
		$s16 = "<ClCompile Include=\"AppCompatCache.cpp\" />" fullword ascii
		$s17 = "<ImportGroup Label=\"PropertySheets\" Condition=\"'$(Configuration)|$(Platform)'" ascii
		$s18 = "<WholeProgramOptimization>true</WholeProgramOptimization>" fullword ascii
		$s19 = "<ImportGroup Label=\"PropertySheets\" Condition=\"'$(Configuration)|$(Platform)'" ascii
		$s20 = "<ProjectConfiguration Include=\"Release|Win32\">" fullword ascii
	condition:
		all of them
}
rule AppCompatCache_vcxproj {
	meta:
		description = "Auto-generated rule - file AppCompatCache.vcxproj.filters"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015/01/05"
		hash = "2e452bb5ef53f4bfdd53953caf34b201d86111a0"
	strings:
		$s0 = "<ClCompile Include=\"sdb_functions.cpp\">" fullword ascii
		$s1 = "<Project ToolsVersion=\"4.0\" xmlns=\"http://schemas.microsoft.com/developer/msb" ascii
		$s2 = "<ClCompile Include=\"stdafx.cpp\">" fullword ascii
		$s3 = "<ClCompile Include=\"CaptureImpersonationToken.cpp\">" fullword ascii
		$s4 = "<ClInclude Include=\"targetver.h\">" fullword ascii
		$s5 = "<ClCompile Include=\"AppCompatCache.cpp\">" fullword ascii
		$s6 = "<Filter Include=\"Resource Files\">" fullword ascii
		$s7 = "<Filter Include=\"Source Files\">" fullword ascii
		$s8 = "<Filter Include=\"Header Files\">" fullword ascii
		$s9 = "<Extensions>h;hh;hpp;hxx;hm;inl;inc;xsd</Extensions>" fullword ascii
		$s10 = "<Filter>Source Files</Filter>" fullword ascii
		$s11 = "<Filter>Header Files</Filter>" fullword ascii
		$s12 = "<ClInclude Include=\"stdafx.h\">" fullword ascii
		$s13 = "<ClInclude Include=\"sdb.h\">" fullword ascii
		$s14 = "</Filter>" fullword ascii
		$s15 = "</ClInclude>" fullword ascii
		$s16 = "</Project>" fullword ascii
		$s17 = "<UniqueIdentifier>{4FC737F1-C7A5-4376-A066-2A32D752A2FF}</UniqueIdentifier>" fullword ascii
		$s18 = "<UniqueIdentifier>{67DA6AB6-F800-4c08-8B7A-83BB121AAD01}</UniqueIdentifier>" fullword ascii
		$s19 = "<UniqueIdentifier>{93995380-89BD-4b04-88EB-625FBE52EBFB}</UniqueIdentifier>" fullword ascii
		$s20 = "<Extensions>cpp;c;cc;cxx;def;odl;idl;hpj;bat;asm;asmx</Extensions>" fullword ascii
	condition:
		all of them
}
