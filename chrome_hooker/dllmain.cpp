#include <Windows.h>
#include <detours.h>

#include <cstdio>
#include <iostream>
#include <sstream>
#include <vector>

#include "openssl.h"
#include "process.h"

SSL_write_Def SSL_write = nullptr;

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

void InitHooking() {
  std::vector<MODULEENTRY32> module_entries = GetProcessModules(0);
  for (size_t i = 0; i < module_entries.size(); i++) {
    if (ToLower(module_entries[i].szModule).compare("chrome.dll") == 0) {
      SetupConsole();
      SECTION_INFO rdata = {0, 0};
      SECTION_INFO text = {0, 0};

      unsigned char write_pattern[] = {
          0x41, 0x56, 0x56, 0x57, 0x55, 0x53, 0x48, 0x83, 0xEC, 0x40,
          '?',  0x89, 0xC6, 0x48, 0x89, 0xD7, 0x48, 0x89, 0xCB, 0x48,
          0x8B, 0x05, '?',  '?',  '?',  '?',  0x48, 0x31, 0xE0, 0x48,
          0x89, 0x44, 0x24, 0x38, 0x48, 0x8B, 0x41, 0x30, 0xC7, 0x80};

      text = GetModuleSection("chrome.dll", ".text");
      if (text.dwSize == 0 || text.dwStartAddress == 0) {
        std::cout << "[ERROR] Cannot get Chrome text section!" << std::endl;
        return;
      }

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

void DetachCleaning() {
  DetourTransactionBegin();
  DetourUpdateThread(GetCurrentThread());
  DetourDetach(&(PVOID&)SSL_write, Hooked_SSL_write);
  DetourTransactionCommit();
}

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
