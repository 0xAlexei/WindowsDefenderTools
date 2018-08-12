"""
ONLY WORKS WITH IDA 7 API

Drop this in your plugins folder. The script is only invoked for files named *.mp.dll
"""
import idaapi
import idc
import struct
import ida_idp

"""
Based on Rolf Rolles' work documented at 
http://www.msreverseengineering.com/blog/2015/6/29/transparent-deobfuscation-with-ida-processor-module-extensions

The purpose of this module is to transform the custom mpengine API call instructions into actual valid X86
The instructions look like:

0f ff f0 [4 byte crc hash]

These instructions are kept in functions that invoke these specific API emulation routines. IDA chokes on
them and does not recognize full functions. By fixing them up we can create functions, and also automatically
label the functions with the name of the API they provide emulation for

loc_7C816D1A:                         
7C816D1A                                       
7C816D1A                 mov     edi, edi
7C816D1C                 call    $+5
7C816D21                 add     esp, 4
7C816D24                 db 0Fh
7C816D25                 db 0FFh
7C816D26                 db 0F0h
7C816D27                 dd 0D06B7F2Ah
7C816D2B                 retn    0Ch

NOTE: for some reason, lines with the apicall instruction come out blue rather than the default black. I looked into changing the color, but ended up leaving it - I like that these unique instructions pop out in the disassembly.

The following C code will generate hashes. DLL names are all caps and include ".DLL"

eg:

$ ./hash KERNEL32.DLL Sleep
KERNEL32.DLL!Sleep: 0x5779beb6

	#include <stdio.h>
	#include <stdint.h>
	#include <stdlib.h>
	#include <limits.h>

	//Taviso code from https://bugs.chromium.org/p/project-zero/issues/detail?id=1260&can=1&q=MsMpEng
	uint32_t crcstr(unsigned char *message) {
	   int i, j;
	   unsigned int byte, crc, mask;

	   i = 0;
	   crc = 0xFFFFFFFF;
	   while (message[i] != 0) {
	      byte = message[i];            // Get next byte.
	      crc = crc ^ byte;
	      for (j = 7; j >= 0; j--) {    // Do eight times.
	         mask = -(crc & 1);
	         crc = (crc >> 1) ^ (0xEDB88320 & mask);
	      }
	      i = i + 1;
	   }
	   return crc;
	}

	int main(int argc, char * argv[])
	{
	   if (argc < 3)
	   {
	      printf("usage ./hash DLLNAME_ALLCAPS.DLL FuncName\n");
	      exit(1);
	   }
	   uint32_t ApiCrc = crcstr((unsigned char *)argv[1]) ^ crcstr((unsigned char *)argv[2]);

	   printf("%s!%s: 0x%x\n", argv[1], argv[2], ApiCrc);
}

"""

hashesToNames = {3514167808L: 'KERNEL32_DLL_WinExec', 3018310659L: 'NTDLL_DLL_VFS_FindNextFile', 836405768L: 'KERNEL32_DLL_CreateProcessA', 2171982857L: 'NTDLL_DLL_NtSetContextThread', 146611723L: 'NTDLL_DLL_NtWaitForMultipleObjectsWorker_PreBlock', 3009652240L: 'NTDLL_DLL_NtGetContextThread', 2721006613L: 'KERNEL32_DLL_MpReportEventEx', 2569699353L: 'NTDLL_DLL_VFS_DeleteFileByHandle', 2363540508L: 'KERNEL32_DLL_SetFileAttributesA', 561219101L: 'NTDLL_DLL_VFS_CopyFile', 6236195L: 'NTDLL_DLL_NtSetEventWorker', 1165823525L: 'NTDLL_DLL_NtReleaseSemaphoreWorker', 935667244L: 'KERNEL32_DLL_VirtualAlloc', 3604202544L: 'KERNEL32_DLL_WriteProcessMemory', 3436587068L: 'NTDLL_DLL_VFS_SetLength', 2678794302L: 'NTDLL_DLL_NtDeleteFileWorker', 3836035660L: 'KERNEL32_DLL_ExitThread', 2420465236L: 'KERNEL32_DLL_VirtualAlloc', 1185677909L: 'KERNEL32_DLL_OpenProcess', 444799073L: 'NTDLL_DLL_MpUfsMetadataOp', 3297998953L: 'NTDLL_DLL_NtCreateEventWorker', 671954542L: 'KERNEL32_DLL_GetModuleHandleA', 695509624L: 'NTDLL_DLL_NtCreateSemaphoreWorker', 938333310L: 'ADVAPI32_DLL_RegOpenKeyExW', 551072383L: 'NTDLL_DLL_VFS_SetCurrentDir', 2858148586L: 'NTDLL_DLL_NtCreateThreadWorker', 111548048L: 'ADVAPI32_DLL_RegDeleteValueW', 852225171L: 'KERNEL32_DLL_TerminateProcess', 3271098004L: 'NTDLL_DLL_NtReadFileWorker', 1672903830L: 'KERNEL32_DLL_FlushFileBuffers', 2766673560L: '__t', 4143527585L: 'KERNEL32_DLL_MoveFileWWorker', 1895208615L: 'NTDLL_DLL_NtResetEventWorker', 2154630824L: 'KERNEL32_DLL_GetCurrentThread', 643813319L: '__t', 3505432946L: 'NTDLL_DLL_MpGetSelectorBase', 389600946L: 'NTDLL_DLL_VFS_SetAttrib', 1467596470L: 'KERNEL32_DLL_Sleep', 2994738363L: 'KERNEL32_DLL_OutputDebugStringA', 2436146366L: 'KERNEL32_DLL_GetModuleFileNameA', 1832462529L: 'NTDLL_DLL_NtCloseWorker', 3832320706L: 'NTDLL_DLL_NtReleaseMutantWorker', 1423484611L: 'KERNEL32_DLL_VirtualFree', 3473119430L: 'NTDLL_DLL_NtSetContextThread', 4158726861L: 'KERNEL32_DLL_MpAddToScanQueue', 3164325074L: 'KERNEL32_DLL_ExitProcess', 2362794197L: 'NTDLL_DLL_ThrdMgr_GetCurrentThreadHandle', 3035488987L: 'KERNEL32_DLL_GetCommandLineA', 4246072031L: 'KERNEL32_DLL_GetThreadContext', 1358384353L: 'KERNEL32_DLL_GetProcAddress', 161412834L: 'ADVAPI32_DLL_RegEnumKeyExW', 37968611L: 'NTDLL_DLL_NtResumeThreadWorker', 1361304293L: 'NTDLL_DLL_NtQueryInformationThreadWorker', 3267971814L: 'KERNEL32_DLL_GetTickCount', 2469586663L: '__t', 3616703208L: 'NTDLL_DLL_NtOpenThreadWorker', 689456874L: 'KERNEL32_DLL_CloseHandle', 3496705834L: 'KERNEL32_DLL_VirtualQuery', 2521119980L: 'NTDLL_DLL_NtQueryInformationFileWorker', 805468541L: 'KERNEL32_DLL_MpCreateMemoryAliasing', 2218737917L: 'KERNEL32_DLL_GetCurrentProcessId', 813909253L: 'NTDLL_DLL_VFS_FindFirstFile', 3776785163L: 'NTDLL_DLL_ThrdMgr_SwitchThreads', 3297990413L: 'KERNEL32_DLL_VirtualProtectEx', 1169409808L: 'NTDLL_DLL_ObjMgr_ValidateVFSHandle', 950361878L: 'USER32_DLL_MessageBoxA', 3087735069L: 'KERNEL32_DLL_SetFileTime', 2931759393L: 'NTDLL_DLL_NtCreateMutantWorker', 3547756835L: 'NTDLL_DLL_NtOpenMutantWorker', 47878950L: 'NTDLL_DLL_NtSetInformationFileWorker', 2943324456L: 'KERNEL32_DLL_MpReportEventW', 2902951210L: 'NTDLL_DLL_VFS_GetHandle', 2091420465L: 'NTDLL_DLL_VFS_UnmapViewOfFile', 3118073140L: 'ADVAPI32_DLL_RegSetValueExW', 2718092597L: 'ADVAPI32_DLL_RegCreateKeyExW', 4225249085L: 'NTDLL_DLL_NtSetLdtEntries', 1887913278L: 'NTDLL_DLL_VFS_MapViewOfFile', 2766101311L: 'NTDLL_DLL_VFS_Open', 1039809345L: 'NTDLL_DLL_VFS_GetLength', 1415316291L: 'NTDLL_DLL_ThrdMgr_SaveTEB', 4288048966L: 'ADVAPI32_DLL_RegEnumValueW', 3228482890L: 'NTDLL_DLL_VFS_DeleteFile', 122791243L: 'NTDLL_DLL_NtTerminateThreadWorker', 3960623330L: 'KERNEL32_DLL_CreateDirectoryW', 1190003539L: 'ADVAPI32_DLL_RegQueryValueExW', 1850539356L: 'KERNEL32_DLL_ReadProcessMemory', 1092269921L: 'KERNEL32_DLL_ExitProcess', 4253992806L: 'NTDLL_DLL_NtWaitForMultipleObjectsWorker_PostBlock', 1484319592L: 'KERNEL32_DLL_CreateToolhelp32Snapshot', 764461426L: 'KERNEL32_DLL_CreateFileMappingA', 3517602195L: 'NTDLL_DLL_NtSuspendThreadWorker', 2994557300L: 'KERNEL32_DLL_CopyFileWWorker', 2439823221L: '__t', 2383730555L: 'NTDLL_DLL_VFS_FindClose', 343092605L: 'KERNEL32_DLL_GetCurrentThreadId', 2911700366L: 'KERNEL32_DLL_VirtualFree', 2987103123L: 'NTDLL_DLL_NtDuplicateObjectWorker', 3125450133L: 'ADVAPI32_DLL_RegDeleteKeyW', 3939937694L: 'NTDLL_DLL_VFS_FileExists', 1589306273L: 'KERNEL32_DLL_RemoveDirectoryW', 3213227941L: 'KERNEL32_DLL_UnimplementedAPIStub', 2984009638L: 'NTDLL_DLL_NtPulseEventWorker', 1202720177L: 'NTDLL_DLL_VFS_MoveFile', 1225607610L: 'KERNEL32_DLL_GetCurrentProcess', 1386109890L: 'KERNEL32_DLL_LoadLibraryW', 1902764997L: 'KERNEL32_DLL_MpReportEvent', 1591092167L: 'NTDLL_DLL_NtCreateFileWorker', 1523256266L: 'NTDLL_DLL_NtWriteFileWorker', 556905933L: 'NTDLL_DLL_NtContinue', 3860121039L: 'NTDLL_DLL_VFS_GetAttrib', 3881168849L: 'KERNEL32_DLL_MpSetSelectorBase', 4283257812L: 'ADVAPI32_DLL_RegQueryInfoKeyW', 2914346968L: 'NTDLL_DLL_NtOpenSemaphoreWorker', 174967782L: 'NTDLL_DLL_NtOpenEventWorker', 4260291559L: 'NTDLL_DLL_VFS_Write', 2476646141L: 'NTDLL_DLL_NtControlChannel', 3536558576L: 'NTDLL_DLL_VFS_FlushViewOfFile', 2566429180L: 'NTDLL_DLL_VFS_Read', 421802495L: 'KERNEL32_DLL_ExitThread'}



NN_apicall = ida_idp.CUSTOM_INSN_ITYPE

class parse_apicall_hook(idaapi.IDP_Hooks):
	def __init__(self):
		idaapi.IDP_Hooks.__init__(self)

	def ev_ana_insn(self, insn):
		global hashesToNames

		insnbytes = idaapi.get_bytes(insn.ea, 3)
		if insnbytes == '\x0f\xff\xf0': 
			apicrc = idaapi.get_long(insn.ea+3)
			apiname = hashesToNames.get(apicrc)
			if apiname is None:
				print "ERROR: apicrc 0x%x NOT FOUND!"%(apicrc)
				#apiname = "UNKNOWN_APICALL"

			print "apicall: %s @ 0x%x"%(apiname, insn.ea)

			insn.itype = NN_apicall
			insn.Op1.type = idaapi.o_imm
			insn.Op1.value = apicrc
			insn.Op1.dtyp = idaapi.dt_dword
			insn.size = 7 #eat up 7 bytes
		
			return True 
		return False

	def ev_out_mnem(self, outctx):
		insntype = outctx.insn.itype

		if insntype == NN_apicall:
			mnem = "apicall"
			outctx.out_line(mnem)

			MNEM_WIDTH = 8
			width = max(1, MNEM_WIDTH - len(mnem))
			outctx.out_line(' ' * width)

			return True
		return False

	def ev_out_operand(self, outctx, op):
		insntype = outctx.insn.itype

		if insntype == NN_apicall:
			apicrc = op.value
			apiname = hashesToNames.get(apicrc)

			if apiname is None:
				return False
			else:
				s = apiname.split("_DLL_")
				operand_name = "!".join( [s[0].lower(), s[1]] )
			print "FOUND:", operand_name

			outctx.out_line(operand_name)

			return True
		return False

class apicall_parse_t(idaapi.plugin_t):
	flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
	comment = "MsMpEng apicall x86 Parser"
	wanted_hotkey = ""
	help = "Runs transparently during analysis"
	wanted_name = "MsMpEng_apicall"
	hook = None

	def init(self):
		self.hook = None
		if not ".mp.dll" in idc.GetInputFile() or idaapi.ph_get_id() != idaapi.PLFM_386:
			return idaapi.PLUGIN_SKIP

		print "\n\n-->MsMpEng apicall x86 Parser Invoked!\n\n"
				
		self.hook = parse_apicall_hook()
		self.hook.hook()
		return idaapi.PLUGIN_KEEP

	def run(self, arg):
		pass

	def term(self):
		if self.hook:
			self.hook.unhook()

def PLUGIN_ENTRY():
	return apicall_parse_t()
