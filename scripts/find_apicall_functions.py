"""

Run this script (File > Script File) after loading a VLL binary with apicall 
instructions disassembled using mp_apicall_7.py

This script will name functions that contain apicall instructions, 
indicating what libraries/functions they apicall to
"""

import idaapi
import idc
import struct
import ida_idp
import binascii

hashesToNames = {3514167808L: 'KERNEL32_DLL_WinExec', 3018310659L: 'NTDLL_DLL_VFS_FindNextFile', 836405768L: 'KERNEL32_DLL_CreateProcessA', 2171982857L: 'NTDLL_DLL_NtSetContextThread', 146611723L: 'NTDLL_DLL_NtWaitForMultipleObjectsWorker_PreBlock', 3009652240L: 'NTDLL_DLL_NtGetContextThread', 2721006613L: 'KERNEL32_DLL_MpReportEventEx', 2569699353L: 'NTDLL_DLL_VFS_DeleteFileByHandle', 2363540508L: 'KERNEL32_DLL_SetFileAttributesA', 561219101L: 'NTDLL_DLL_VFS_CopyFile', 6236195L: 'NTDLL_DLL_NtSetEventWorker', 1165823525L: 'NTDLL_DLL_NtReleaseSemaphoreWorker', 935667244L: 'KERNEL32_DLL_VirtualAlloc', 3604202544L: 'KERNEL32_DLL_WriteProcessMemory', 3436587068L: 'NTDLL_DLL_VFS_SetLength', 2678794302L: 'NTDLL_DLL_NtDeleteFileWorker', 3836035660L: 'KERNEL32_DLL_ExitThread', 2420465236L: 'KERNEL32_DLL_VirtualAlloc', 1185677909L: 'KERNEL32_DLL_OpenProcess', 444799073L: 'NTDLL_DLL_MpUfsMetadataOp', 3297998953L: 'NTDLL_DLL_NtCreateEventWorker', 671954542L: 'KERNEL32_DLL_GetModuleHandleA', 695509624L: 'NTDLL_DLL_NtCreateSemaphoreWorker', 938333310L: 'ADVAPI32_DLL_RegOpenKeyExW', 551072383L: 'NTDLL_DLL_VFS_SetCurrentDir', 2858148586L: 'NTDLL_DLL_NtCreateThreadWorker', 111548048L: 'ADVAPI32_DLL_RegDeleteValueW', 852225171L: 'KERNEL32_DLL_TerminateProcess', 3271098004L: 'NTDLL_DLL_NtReadFileWorker', 1672903830L: 'KERNEL32_DLL_FlushFileBuffers', 2766673560L: '__t', 4143527585L: 'KERNEL32_DLL_MoveFileWWorker', 1895208615L: 'NTDLL_DLL_NtResetEventWorker', 2154630824L: 'KERNEL32_DLL_GetCurrentThread', 643813319L: '__t', 3505432946L: 'NTDLL_DLL_MpGetSelectorBase', 389600946L: 'NTDLL_DLL_VFS_SetAttrib', 1467596470L: 'KERNEL32_DLL_Sleep', 2994738363L: 'KERNEL32_DLL_OutputDebugStringA', 2436146366L: 'KERNEL32_DLL_GetModuleFileNameA', 1832462529L: 'NTDLL_DLL_NtCloseWorker', 3832320706L: 'NTDLL_DLL_NtReleaseMutantWorker', 1423484611L: 'KERNEL32_DLL_VirtualFree', 3473119430L: 'NTDLL_DLL_NtSetContextThread', 4158726861L: 'KERNEL32_DLL_MpAddToScanQueue', 3164325074L: 'KERNEL32_DLL_ExitProcess', 2362794197L: 'NTDLL_DLL_ThrdMgr_GetCurrentThreadHandle', 3035488987L: 'KERNEL32_DLL_GetCommandLineA', 4246072031L: 'KERNEL32_DLL_GetThreadContext', 1358384353L: 'KERNEL32_DLL_GetProcAddress', 161412834L: 'ADVAPI32_DLL_RegEnumKeyExW', 37968611L: 'NTDLL_DLL_NtResumeThreadWorker', 1361304293L: 'NTDLL_DLL_NtQueryInformationThreadWorker', 3267971814L: 'KERNEL32_DLL_GetTickCount', 2469586663L: '__t', 3616703208L: 'NTDLL_DLL_NtOpenThreadWorker', 689456874L: 'KERNEL32_DLL_CloseHandle', 3496705834L: 'KERNEL32_DLL_VirtualQuery', 2521119980L: 'NTDLL_DLL_NtQueryInformationFileWorker', 805468541L: 'KERNEL32_DLL_MpCreateMemoryAliasing', 2218737917L: 'KERNEL32_DLL_GetCurrentProcessId', 813909253L: 'NTDLL_DLL_VFS_FindFirstFile', 3776785163L: 'NTDLL_DLL_ThrdMgr_SwitchThreads', 3297990413L: 'KERNEL32_DLL_VirtualProtectEx', 1169409808L: 'NTDLL_DLL_ObjMgr_ValidateVFSHandle', 950361878L: 'USER32_DLL_MessageBoxA', 3087735069L: 'KERNEL32_DLL_SetFileTime', 2931759393L: 'NTDLL_DLL_NtCreateMutantWorker', 3547756835L: 'NTDLL_DLL_NtOpenMutantWorker', 47878950L: 'NTDLL_DLL_NtSetInformationFileWorker', 2943324456L: 'KERNEL32_DLL_MpReportEventW', 2902951210L: 'NTDLL_DLL_VFS_GetHandle', 2091420465L: 'NTDLL_DLL_VFS_UnmapViewOfFile', 3118073140L: 'ADVAPI32_DLL_RegSetValueExW', 2718092597L: 'ADVAPI32_DLL_RegCreateKeyExW', 4225249085L: 'NTDLL_DLL_NtSetLdtEntries', 1887913278L: 'NTDLL_DLL_VFS_MapViewOfFile', 2766101311L: 'NTDLL_DLL_VFS_Open', 1039809345L: 'NTDLL_DLL_VFS_GetLength', 1415316291L: 'NTDLL_DLL_ThrdMgr_SaveTEB', 4288048966L: 'ADVAPI32_DLL_RegEnumValueW', 3228482890L: 'NTDLL_DLL_VFS_DeleteFile', 122791243L: 'NTDLL_DLL_NtTerminateThreadWorker', 3960623330L: 'KERNEL32_DLL_CreateDirectoryW', 1190003539L: 'ADVAPI32_DLL_RegQueryValueExW', 1850539356L: 'KERNEL32_DLL_ReadProcessMemory', 1092269921L: 'KERNEL32_DLL_ExitProcess', 4253992806L: 'NTDLL_DLL_NtWaitForMultipleObjectsWorker_PostBlock', 1484319592L: 'KERNEL32_DLL_CreateToolhelp32Snapshot', 764461426L: 'KERNEL32_DLL_CreateFileMappingA', 3517602195L: 'NTDLL_DLL_NtSuspendThreadWorker', 2994557300L: 'KERNEL32_DLL_CopyFileWWorker', 2439823221L: '__t', 2383730555L: 'NTDLL_DLL_VFS_FindClose', 343092605L: 'KERNEL32_DLL_GetCurrentThreadId', 2911700366L: 'KERNEL32_DLL_VirtualFree', 2987103123L: 'NTDLL_DLL_NtDuplicateObjectWorker', 3125450133L: 'ADVAPI32_DLL_RegDeleteKeyW', 3939937694L: 'NTDLL_DLL_VFS_FileExists', 1589306273L: 'KERNEL32_DLL_RemoveDirectoryW', 3213227941L: 'KERNEL32_DLL_UnimplementedAPIStub', 2984009638L: 'NTDLL_DLL_NtPulseEventWorker', 1202720177L: 'NTDLL_DLL_VFS_MoveFile', 1225607610L: 'KERNEL32_DLL_GetCurrentProcess', 1386109890L: 'KERNEL32_DLL_LoadLibraryW', 1902764997L: 'KERNEL32_DLL_MpReportEvent', 1591092167L: 'NTDLL_DLL_NtCreateFileWorker', 1523256266L: 'NTDLL_DLL_NtWriteFileWorker', 556905933L: 'NTDLL_DLL_NtContinue', 3860121039L: 'NTDLL_DLL_VFS_GetAttrib', 3881168849L: 'KERNEL32_DLL_MpSetSelectorBase', 4283257812L: 'ADVAPI32_DLL_RegQueryInfoKeyW', 2914346968L: 'NTDLL_DLL_NtOpenSemaphoreWorker', 174967782L: 'NTDLL_DLL_NtOpenEventWorker', 4260291559L: 'NTDLL_DLL_VFS_Write', 2476646141L: 'NTDLL_DLL_NtControlChannel', 3536558576L: 'NTDLL_DLL_VFS_FlushViewOfFile', 2566429180L: 'NTDLL_DLL_VFS_Read', 421802495L: 'KERNEL32_DLL_ExitThread'}

#NN_apicall = ida_idp.CUSTOM_INSN_ITYPE

def main():

	text_ea = None
	#for some reason SegByName() isn't working for me - maybe an IDA 7 regression?
	for seg in Segments():
		if get_segm_name(seg) == ".text":
			text_ea = seg

	if text_ea is None:
		print "ERROR: Unable to get .text segment!"
		return

	# first find all the functions
	for head in Heads(text_ea, SegEnd(text_ea)):
		func_ea = idaapi.get_func(head)
		if func_ea is None: 
			if idaapi.get_bytes(head, 13) == '\x8b\xff\xe8\x00\x00\x00\x00\x83\xc4\x04\x0f\xff\xf0':
				print  "Unrecognized apicall function at @ 0x%x"%(head)
				MakeFunction(head)

	#now name the functions
	for funcea in Functions(text_ea, SegEnd(text_ea)): 
		functionName = GetFunctionName(funcea)
		for (startea, endea) in Chunks(funcea):
			for head in Heads(startea, endea):

				insnbytes = idaapi.get_bytes(head, 3)

				if insnbytes == '\x0f\xff\xf0': 
					apicrc = idaapi.get_long(head+3)
					apiname = hashesToNames.get(apicrc)
					if apiname is None:
						print "ERROR: apicrc 0x%x NOT FOUND! @ 0x%x"%(apicrc, head)
					else:
						print "PROCESS - apicall: %s @ 0x%x"%(apiname, head)
						func_ea = idaapi.get_func(head).start_ea
						fname = idc.GetFunctionName(func_ea)
						if fname.startswith("sub_"):
							MakeName(func_ea, "apicall_" + apiname) 

main()
