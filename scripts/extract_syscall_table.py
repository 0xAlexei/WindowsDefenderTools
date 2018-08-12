from idaapi import *

"""
Parse the mpengine.dll g_syscalls table of natively emulated APIs and dump 
hashes and names to a Python map, as used in find_apicall_functions.py and 
mp_apicall_7.py
"""


namemap = {}

#this symbol may not be present in all builds, you may need to find this table
ea_syscalls = LocByName("g_syscalls")

print "g_syscalls at", ea_syscalls

current_ea = ea_syscalls
for i in xrange(119): #esyscall_t g_syscalls[119]
	name = Demangle(get_name(Dword(current_ea)), 0).split()[2][:-7]
	funchash = Dword(current_ea+4)
	namemap[funchash] = name
	current_ea += 8

print namemap