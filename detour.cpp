#ifdef _WIN32
#include <Windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <string.h>
#include <malloc.h>
#include <vector>

#include <arm.h>
#include <capstone.h>
#include <keystone.h>

#include "detour.hpp"

#if defined __amd64__ || defined __amd64 || defined __x86_64__ || defined __x86_64 || defined _M_X64 || defined _M_AMD64
	#define COMPILER_CS_ARCH CS_ARCH_X86
	#define COMPILER_CS_MODE CS_MODE_64
	#define COMPILER_KS_ARCH KS_ARCH_X86
	#define COMPILER_KS_MODE KS_MODE_64
	#define COMPILER_MAX_TARGET_BYTES 32
	#define COMPILER_INTERNAL_X64 1
#elif defined i386 || defined __i386 || defined __i386__ || defined __i386 || defined __IA32__ || defined _M_IX86 || defined __X86__ || defined _X86__ || defined __I86__ || defined _X86_
	#define COMPILER_CS_ARCH CS_ARCH_X86
	#define COMPILER_CS_MODE CS_MODE_32
	#define COMPILER_KS_ARCH KS_ARCH_X86
	#define COMPILER_KS_MODE KS_MODE_32
	#define COMPILER_MAX_TARGET_BYTES 16
	#define COMPILER_INTERNAL_X86 1
#elif defined __arm__ || defined __arm || defined _ARM || defined _M_ARM
	#if defined __thumb__ || defined _M_ARMT
		#define COMPILER_CS_ARCH CS_ARCH_ARM
		#define COMPILER_CS_MODE CS_MODE_THUMB
		#define COMPILER_KS_ARCH KS_ARCH_ARM
		#define COMPILER_KS_MODE KS_MODE_THUMB
		#define COMPILER_MAX_TARGET_BYTES 16
		#define COMPILER_INTERNAL_THUMB 1
	#else
		#define COMPILER_CS_ARCH CS_ARCH_ARM
		#define COMPILER_CS_MODE CS_MODE_ARM
		#define COMPILER_KS_ARCH KS_ARCH_ARM
		#define COMPILER_KS_MODE KS_MODE_ARM
		#define COMPILER_MAX_TARGET_BYTES 16
		#define COMPILER_INTERNAL_ARM 1
	#endif
#else
#error Your compiler type is not supported.
#endif

#ifdef _WIN32
#define DETOUR_VM_PROTECTION_FLAGS PAGE_EXECUTE_READWRITE
#else
#define DETOUR_VM_PROTECTION_FLAGS (PROT_READ | PROT_WRITE | PROT_EXEC)
#endif

int set_page_protections_for_address(void *addr, size_t page_size, int prot)
{
#ifdef _WIN32
	DWORD dwDummy;
	return VirtualProtect(addr, 1, prot, &dwDummy);
#else
	void *page_start = (void *)((uintptr_t) addr & -page_size);
	

	return mprotect(page_start, page_size, prot);
#endif
}

void print_disasm(csh handle, void *p, size_t size) {
	cs_insn *insn;
	
	size_t count = cs_disasm(handle, (const uint8_t*) p, size, (uint64_t) p, 0, &insn);
	if (count > 0) {
		for (size_t i = 0; i < count; i++) {
			printf("print_disasm (%d): %s %s (%d)\n", i, insn[i].mnemonic, insn[i].op_str, insn[i].size);
		}
	}
	
	cs_free(insn, 1);
}

bool create_unconditional_branch_ks(void *src, void *dest, std::vector<unsigned char> *code) {
	
	if (!code)
		return false;
	
	ks_engine *ks;
	ks_err err;
	bool result = false;
	err = ks_open(COMPILER_KS_ARCH, COMPILER_KS_MODE, &ks);
	
#if defined COMPILER_INTERNAL_X64 || defined COMPILER_INTERNAL_X86
	char fmt[] = "JMP 0x%X";
#elif COMPILER_INTERNAL_THUMB
	char fmt[] = "B %p";
#elif COMPILER_INTERNAL_ARM
	char fmt[] = "LDR.W PC, =%p";	
#endif

	char s[256];
	sprintf(s, fmt, dest);

	printf("Generating unconditional branch: %s\n", s);
	
	uint64_t startAddress = (uint64_t) src;
	
	unsigned char *insn;
	size_t count;
	size_t insSize;
	if (ks_asm(ks, s, startAddress, &insn, &insSize, &count) == 0 && insSize != 0) {
		printf("%s = [ ", s);
		for (size_t i = 0; i < insSize; i++) {
			code->push_back(insn[i]);
				
			printf("%02x ", insn[i]);
		}
		printf("]\n");
			
		result = true;
	} else {
		printf("Failed to generate assembly...\n");
	}
	
	ks_free(insn);
	ks_close(ks);
	
	return result;
}

void *detour_fn(void *src, void *dest)
{
	// Variables (because goto)
	long page_size;
	csh handle;
	cs_insn *insn = nullptr;
	size_t count = 0, sizeToSave = 0;
	void *trampoline = nullptr;
	std::vector<unsigned char> fub, fubtramp;
	//
	
#ifdef _WIN32
	SYSTEM_INFO systemInfo;
	GetSystemInfo(&systemInfo);
	page_size = systemInfo.dwPageSize;
#else
	page_size = sysconf(_SC_PAGESIZE);
#endif
	
	if (page_size == -1)
		return nullptr;
	
	printf("Capstone Options: %d, %d\n", COMPILER_CS_ARCH, COMPILER_CS_MODE);
	printf("Src: %p, Dest: %p\n", src, dest);
	
	if (cs_open(COMPILER_CS_ARCH, COMPILER_CS_MODE, &handle) != CS_ERR_OK)
		return nullptr;
	
	print_disasm(handle, src, 16);

	// We can create the trampoline for the src/dest now, so we know how many bytes to save
	if (!create_unconditional_branch_ks(src, dest, &fub))
		goto bad_ret;
	
	// We now know how much we have to save, so let's do that
	count = cs_disasm(handle, (const uint8_t*) src, COMPILER_MAX_TARGET_BYTES, (uint64_t) src, 0, &insn);
	if (count == 0)
		goto bad_ret;
	
	for (size_t i = 0; i < count; i++) {
		sizeToSave += insn[i].size;
			
		printf("Instruction (%s %s) size: 0x%x\n", insn[i].mnemonic, insn[i].op_str, insn[i].size);
		
		if (sizeToSave >= fub.size())
			break;
	}
	
	printf("Size To Save: 0x%x\n", sizeToSave);
	
	trampoline = malloc(page_size);
	
	if (!trampoline)
		goto bad_ret;
	
	printf("Trampoline Allocated (%p)\n", trampoline);
	
	if (set_page_protections_for_address(trampoline, page_size, DETOUR_VM_PROTECTION_FLAGS) == -1)
		goto bad_ret;
	
	// Backup the data overwritten in the src
	memcpy(trampoline, src, sizeToSave);
	
	// The trampoline is a page, so we don't need to be concerned with how much we overwrite here
	if (!create_unconditional_branch_ks((void *)((uintptr_t) trampoline + sizeToSave), (void *)((uintptr_t) src + sizeToSave), &fubtramp))
		goto bad_ret;
	
	memcpy(((unsigned char *)trampoline) + sizeToSave, fubtramp.data(), fubtramp.size());
	
	if (set_page_protections_for_address(src, page_size, DETOUR_VM_PROTECTION_FLAGS) == -1)
		goto bad_ret;
	
	// We have the trampolines generated, and saved to the trampoline as well.
	// We can overwrite src with the fub.
	memcpy(src, fub.data(), fub.size());
	
	print_disasm(handle, trampoline, sizeToSave + fubtramp.size());
	
	return trampoline;
	
bad_ret:

	if (trampoline != nullptr) {
		free(trampoline);

		trampoline = nullptr;
	}

	if (insn != nullptr)
		cs_free(insn, 1);
	
	return nullptr;
}

void *detour(void *src, void *dest)
{
	// TODO: suspend threads
	
	void *result = detour_fn(src, dest);
	
	// TODO: resume threads
	
	return result;
}
