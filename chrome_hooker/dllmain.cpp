#include <Windows.h>
#include <detours.h>

// detours는 Microsoft에서 제공하는 Hooking 라이브러리.
// 메모리상의 어셈블리어 코드를 수정하여 후킹함.

#include <cstdio>
#include <iostream>
#include <sstream>
#include <vector>

#include "openssl.h"
#include "process.h"

SSL_write_Def SSL_write = nullptr;

// 원본 함수를 후킹하면 프로그램이 원본 함수를 후킹할때 해당 함수가 실행.
int Hooked_SSL_write(void* ssl, void* buf, int len) {
  if (reinterpret_cast<char*>(buf)[3] == 0x00) {
    std::cout << "[DATA]" << std::endl;
    std::cout << "Length: " << len << std::endl;
    std::cout << "Content: "
              << reinterpret_cast<char*>(reinterpret_cast<uintptr_t>(buf) + 9)
              << std::endl;
  }
  return SSL_write(ssl, buf, len);
}

// 탈취된 데이터를 출력하기 위한 콘솔 
void SetupConsole() {
  AllocConsole();

  FILE* dummy_file;
  freopen_s(&dummy_file, "CONOUT$", "w", stdout);
  freopen_s(&dummy_file, "CONOUT$", "w", stderr);
  freopen_s(&dummy_file, "CONIN$", "r", stdin);
  std::cout.clear();
  std::clog.clear();
  std::cerr.clear();
  std::cin.clear();
}

// 실제 후킹 부분 
void InitHooking() {
  // 모듈 목록 가져옴 
  std::vector<MODULEENTRY32> module_entries = GetProcessModules(0); 
  for (size_t i = 0; i < module_entries.size(); i++) {
    // chromium은 SSL 라이브러리 등 많은 핵심적인 기능을 외부 dll에서 호출하지 않음. 대부분 chrome.dll에 포함 (약 140MB 이상)
    if (ToLower(module_entries[i].szModule).compare("chrome.dll") == 0) {
      // chrome.dll을 찾으면 콘솔을 해당 띄움 
      SetupConsole();
      SECTION_INFO rdata = {0, 0};
      SECTION_INFO text = {0, 0};

      // SSL_write 함수의 고정적인 메모리 패턴 (?는 와일드카드)
      // chromium은 OpenSSL을 자체적으로 Fork한 BoringSSL을 사용. (이 또한 오픈소스)
      // chromium의 DEPS(종속성) 파일에서 BoringSSL의 버전을 찾고 SSL_write 함수 주변의 컴파일되는 스트링으로 해당 함수를 찾을 수 있음. (windbg 사용)
      unsigned char write_pattern[] = {
          0x41, 0x56, 0x56, 0x57, 0x55, 0x53, 0x48, 0x83, 0xEC, 0x40,
          '?',  0x89, 0xC6, 0x48, 0x89, 0xD7, 0x48, 0x89, 0xCB, 0x48,
          0x8B, 0x05, '?',  '?',  '?',  '?',  0x48, 0x31, 0xE0, 0x48,
          0x89, 0x44, 0x24, 0x38, 0x48, 0x8B, 0x41, 0x30, 0xC7, 0x80};

      // .text 섹션 주소 검색 
      text = GetModuleSection("chrome.dll", ".text");
      if (text.dwSize == 0 || text.dwStartAddress == 0) {
        std::cout << "[ERROR] Cannot get Chrome text section!" << std::endl;
        return;
      }

      // 해당 패턴 찾음 
      uintptr_t ssl_write_address = SearchSignature(
          reinterpret_cast<void*>(text.dwStartAddress), text.dwSize,
          reinterpret_cast<void*>(write_pattern), sizeof(write_pattern));
      if (ssl_write_address == 0) {
        std::cout << "[ERROR] Cannot get Chrome SSL write function!";
        return;
      }

      SSL_write = (SSL_write_Def)ssl_write_address;
      std::cout << "[INFO] SSL_write Address: "
                << reinterpret_cast<void*>(ssl_write_address) << std::endl;

      // Detours를 사용한 후킹 진행.
      DetourTransactionBegin();
      DetourUpdateThread(GetCurrentThread());
      DetourAttach(&(PVOID&)SSL_write, Hooked_SSL_write);
      LONG error = DetourTransactionCommit();
      if (error == NO_ERROR) {
        std::cout << "[INFO] chrome_hooker.dll: Detoured SSL_write()"
                  << std::endl;
      } else {
        std::cout << "[ERROR] Detours error: " << error << std::endl;
      }
    }
  }
}

// Detours 제거
void DetachCleaning() {
  DetourTransactionBegin();
  DetourUpdateThread(GetCurrentThread());
  DetourDetach(&(PVOID&)SSL_write, Hooked_SSL_write);
  DetourTransactionCommit();
}

// EP
BOOL APIENTRY DllMain(HMODULE module_handle, DWORD reason_for_call,
                      LPVOID reserved) {
  switch (reason_for_call) {
    case DLL_PROCESS_ATTACH:
      InitHooking();
      break;
    case DLL_THREAD_ATTACH:
      break;
    case DLL_THREAD_DETACH:
      break;
    case DLL_PROCESS_DETACH:
      DetachCleaning();
      break;
  }
  return TRUE;
}
