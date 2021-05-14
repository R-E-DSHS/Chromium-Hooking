#include "process.h"

// string 소문자로 변경
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

// 프로세스에 종속된 모듈(exe, dll)의 목록 - Source: unknowncheats.me
std::vector<MODULEENTRY32> GetProcessModules(DWORD process_id) {
  HANDLE snapshot_handle;
  MODULEENTRY32 module_entry;
  std::vector<MODULEENTRY32> module_entries;
  if (process_id == 0) { // 잘못된 인자 전달 확인
    process_id = GetCurrentProcessId(); 
  }

  snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id);
  if (snapshot_handle == INVALID_HANDLE_VALUE) {
    return module_entries;
  }

  module_entry.dwSize = sizeof(MODULEENTRY32);
  if (!Module32First(snapshot_handle, &module_entry)) { // 첫 모듈 찾기
    return module_entries;
  }

  module_entries.push_back(module_entry); // 모듈 리스트에 추가
  while (Module32Next(snapshot_handle, &module_entry)) { // 다음 모듈 찾기 
    module_entries.push_back(module_entry);
  }
  return module_entries;
}

// 모듈의 섹션(.text 등) 주소 찾기 
// Idea from unknowncheats.me
SECTION_INFO GetModuleSection(std::string module_name,
                              std::string section_name) {
  SECTION_INFO section_data = {0, 0};
  bool found = 0;
  HMODULE module_handle = 0;

  if (!module_name.empty()) {
    module_name = ToLower(module_name);
    std::vector<MODULEENTRY32> module_entries = GetProcessModules(0); // 전체 모듈 목록 찾기 

    for (size_t i = 0; i < module_entries.size(); i++) {
      if (module_name.compare(ToLower(module_entries[i].szModule)) == 0) { // 목표 모듈과 이름 비교 (대소문자 구분 X, 둘다 소문자로 변경 후 비교)
        found = 1;
        module_handle = GetModuleHandle(module_entries[i].szModule); // 목표 모듈의 핸들 가져옴

        if (module_handle == NULL) {
          return section_data;
        }
      }
    }
  } else {
    module_handle = GetModuleHandle(0); // 모듈 이름이 지정되지 않은 경우 현재 모듈의 핸들 가져옴
    if (module_handle == NULL) {
      return section_data;
    }
  }

  // 모듈 핸들로부터 섹션 주소 추출

  // PE 파일 헤더 구조체
  IMAGE_DOS_HEADER dos;
  IMAGE_NT_HEADERS nt_headers;
  IMAGE_SECTION_HEADER *sections = NULL;

  // 초기화 및 설정 
  memcpy(&dos, (void *)module_handle, sizeof(IMAGE_DOS_HEADER));
  memcpy(&nt_headers, (void *)((uintptr_t)module_handle + dos.e_lfanew),
         sizeof(IMAGE_NT_HEADERS));

  // 섹션 배열 메모리 할당 
  try {
    sections = new IMAGE_SECTION_HEADER[nt_headers.FileHeader.NumberOfSections];
  } catch (std::bad_alloc &) {
    return section_data;
  }

  // 초기화 및 설정
  memcpy(
      sections,
      (void *)((uintptr_t)module_handle + dos.e_lfanew +
               sizeof(IMAGE_NT_HEADERS)),
      (nt_headers.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)));

  // 섹션 검색 
  for (size_t j = 0; j < nt_headers.FileHeader.NumberOfSections; j++) {
    if (section_name.compare((char *)sections[j].Name) == 0) { // 찾은 경우 주소 설정
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

// 프로그램의 메모리로부터 특정 패턴의 주소를 가져옴 
// 예시: 메모리 - 83 27 B4 AF 39에서 27 BA를 찾는다 하면 1이라는 주소 반환 

// start_address: 검색 시작 주소
// base_size: 검색 범위
// pattern: 찾을 패턴의 시작주소 
// pattern_size: 찾을 패턴의 크기 
// Idea from unknowncheats.me
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
