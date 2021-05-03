#pragma once

#include <Windows.h>
#include <TlHelp32.h>

#include <string>
#include <vector>

struct SECTION_INFO {
  uintptr_t dwStartAddress;
  DWORD dwSize;
};

std::string ToLower(std::string source_string);
std::vector<MODULEENTRY32> GetProcessModules(DWORD process_id);
SECTION_INFO GetModuleSection(std::string module_name,
                              std::string section_name);
uintptr_t SearchSignature(void *start_address, DWORD base_size, void *pattern,
                          DWORD pattern_size);