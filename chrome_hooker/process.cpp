#include "process.h"

std::string ToLower(std::string source_string) {
  std::string result = "";
  for (size_t i = 0; i < source_string.length(); i++) {
    if (source_string[i] >= 65 && source_string[i] <= 90)
      result += (char)(source_string[i] + 32);
    else
      result += source_string[i];
  }
  return result;
}

std::vector<MODULEENTRY32> GetProcessModules(DWORD process_id) {
  HANDLE snapshot_handle;
  MODULEENTRY32 module_entry;
  std::vector<MODULEENTRY32> module_entries;
  if (process_id == 0) {
    process_id = GetCurrentProcessId();
  }

  snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id);
  if (snapshot_handle == INVALID_HANDLE_VALUE) {
    return module_entries;
  }

  module_entry.dwSize = sizeof(MODULEENTRY32);
  if (!Module32First(snapshot_handle, &module_entry)) {
    return module_entries;
  }

  module_entries.push_back(module_entry);
  while (Module32Next(snapshot_handle, &module_entry)) {
    module_entries.push_back(module_entry);
  }
  return module_entries;
}

SECTION_INFO GetModuleSection(std::string module_name,
                              std::string section_name) {
  SECTION_INFO section_data = {0, 0};
  bool found = 0;
  HMODULE module_handle = 0;

  if (!module_name.empty()) {
    module_name = ToLower(module_name);
    std::vector<MODULEENTRY32> module_entries = GetProcessModules(0);

    for (size_t i = 0; i < module_entries.size(); i++) {
      if (module_name.compare(ToLower(module_entries[i].szModule)) == 0) {
        found = 1;
        module_handle = GetModuleHandle(module_entries[i].szModule);

        if (module_handle == NULL) {
          return section_data;
        }
      }
    }
  } else {
    module_handle = GetModuleHandle(0);
    if (module_handle == NULL) {
      return section_data;
    }
  }

  IMAGE_DOS_HEADER dos;
  IMAGE_NT_HEADERS nt_headers;
  IMAGE_SECTION_HEADER *sections = NULL;

  memcpy(&dos, (void *)module_handle, sizeof(IMAGE_DOS_HEADER));
  memcpy(&nt_headers, (void *)((uintptr_t)module_handle + dos.e_lfanew),
         sizeof(IMAGE_NT_HEADERS));

  try {
    sections = new IMAGE_SECTION_HEADER[nt_headers.FileHeader.NumberOfSections];
  } catch (std::bad_alloc &) {
    return section_data;
  }

  memcpy(
      sections,
      (void *)((uintptr_t)module_handle + dos.e_lfanew +
               sizeof(IMAGE_NT_HEADERS)),
      (nt_headers.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)));

  for (size_t j = 0; j < nt_headers.FileHeader.NumberOfSections; j++) {
    if (section_name.compare((char *)sections[j].Name) == 0) {
      section_data.dwSize = sections[j].SizeOfRawData;
      section_data.dwStartAddress =
          (uintptr_t)module_handle + sections[j].VirtualAddress;
      delete sections;
      return section_data;
    }
  }

  delete[] sections;
  return section_data;
}

uintptr_t SearchSignature(void *start_address, DWORD base_size, void *pattern,
                          DWORD pattern_size) {
  uintptr_t dwMax = (uintptr_t)start_address + base_size;
  unsigned char c1 = 0, c2 = 0;
  bool bOk = false;

  for (DWORD i = 0; i < base_size - pattern_size; i++) {
    bOk = false;

    for (DWORD j = 0; j < pattern_size; j++) {
      c1 = *(unsigned char *)((uintptr_t)start_address + i + j);
      c2 = *(unsigned char *)((uintptr_t)pattern + j);

      if (c1 == c2 || c2 == '?') {
        bOk = true;
        continue;
      } else {
        bOk = false;
        break;
      }
    }
    if (bOk) {
      return (uintptr_t)start_address + i;
    }
  }
  return 0;
}
