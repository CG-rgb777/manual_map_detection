#include <windows.h>
#include <psapi.h>
#include <vector>
#include <iostream>
#include <sstream>
#include <string>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <array>
#include <type_traits>


#if defined(_MSC_VER) && !defined(__clang__) && !defined(__llvm__)
#define _MSVC
#elif defined (__GNUC__) || defined(__clang__) || defined(__llvm__)
#define _GNUC
#endif

#ifdef _MSVC
#define NOINLINE __declspec(noinline)
#else 
#define NOINLINE __attribute__((noinline))
#endif

//#define MMP_DEBUG_MOD


namespace detail {
    constexpr uint32_t compile_time_hash(const char* str, uint32_t h = 0) {
        return !str[h] ? 5381 : (compile_time_hash(str, h + 1) * 33) ^ str[h];
    }

    template <typename CharT, size_t N>
    constexpr auto encrypt_data(const CharT(&str)[N], uint32_t key) {
        constexpr size_t total_bytes = N * sizeof(CharT);
        std::array<uint8_t, total_bytes> encrypted{};

        for (size_t i = 0; i < N; ++i) {
            CharT c = str[i];
            for (size_t j = 0; j < sizeof(CharT); ++j) {
                size_t byte_index = i * sizeof(CharT) + j;
                uint8_t b = static_cast<uint8_t>(c >> (8 * j));
                encrypted[byte_index] = b ^
                    static_cast<uint8_t>((key >> (8 * (byte_index & 3))) + static_cast<uint8_t>(byte_index));
            }
        }

        return encrypted;
    }
}

#define OBF(str) []() -> std::basic_string<std::decay_t<decltype(str[0])>> { \
    constexpr uint32_t key = detail::compile_time_hash(__TIME__ " " __DATE__); \
    using CharT = std::decay_t<decltype(str[0])>; \
    constexpr size_t N = sizeof(str) / sizeof(CharT); \
    constexpr auto encrypted = detail::encrypt_data(str, key); \
    \
    std::basic_string<CharT> result; \
    result.reserve(N - 1); \
    for (size_t i = 0; i < N - 1; ++i) { \
        CharT c = 0; \
        for (size_t j = 0; j < sizeof(CharT); ++j) { \
            size_t byte_index = i * sizeof(CharT) + j; \
            uint8_t b = encrypted[byte_index] ^ \
                static_cast<uint8_t>((key >> (8 * (byte_index & 3))) + static_cast<uint8_t>(byte_index)); \
            c |= static_cast<CharT>(b) << (8 * j); \
        } \
        result += c; \
    } \
    return result; \
}()


constexpr uint32_t DJB2_HASH(const char* str, uint32_t hash = 5381) {
    return *str ? DJB2_HASH(str + 1, ((hash << 5) + hash) ^ *str) : hash;
}

FARPROC GetProcAddressByHash(HMODULE hModule, uint32_t dwHash) {
    if (!hModule) {
        return nullptr;
    }

    PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)hModule + pDOSHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hModule + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    LPDWORD pNameRVAs = (LPDWORD)((LPBYTE)hModule + pExportDirectory->AddressOfNames);
    LPWORD pNameOrdinals = (LPWORD)((LPBYTE)hModule + pExportDirectory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExportDirectory->NumberOfNames; ++i) {
        char* pFunctionName = (char*)((LPBYTE)hModule + pNameRVAs[i]);
        if (DJB2_HASH(pFunctionName) == dwHash) {
            DWORD dwFunctionRVA = ((LPDWORD)((LPBYTE)hModule + pExportDirectory->AddressOfFunctions))[pNameOrdinals[i]];
            return (FARPROC)((LPBYTE)hModule + dwFunctionRVA);
        }
    }

    return nullptr;
}




struct ModuleInfo {
    uintptr_t baseAddress;
    size_t size;
};



using VirtualQuery_t = SIZE_T(WINAPI*)(_In_opt_ LPCVOID lpAddress, _Out_writes_bytes_to_(dwLength, return) PMEMORY_BASIC_INFORMATION lpBuffer, _In_ SIZE_T dwLength);
static VirtualQuery_t pVirtualQuery = nullptr;


using GetCurrentProcess_t = HANDLE(WINAPI*)();
static GetCurrentProcess_t pGetCurrentProcess = nullptr;
std::vector<ModuleInfo> GetLoadedModules() {
    std::vector<ModuleInfo> modules;
    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(pGetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            MODULEINFO modInfo;
            if (GetModuleInformation(pGetCurrentProcess(), hMods[i], &modInfo, sizeof(modInfo))) {
                modules.push_back({ (uintptr_t)modInfo.lpBaseOfDll, modInfo.SizeOfImage });
            }
        }
    }
    return modules;
}


using GetModuleHandleExW_t = BOOL(WINAPI*)(_In_ DWORD dwFlags, _In_opt_ LPCWSTR lpModuleName, _Out_ HMODULE* phModule);
static GetModuleHandleExW_t pGetModuleHandleExW = nullptr;
bool IsAddressInModule(uintptr_t address) {
    HMODULE hModule = nullptr;
    if (pGetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
        reinterpret_cast<LPCWSTR>(address), &hModule)) {
        return hModule != nullptr;
    }
    return false;
}



std::vector<std::pair<uint8_t, bool>> PatternToBytes(const std::string& pattern) {
    std::vector<std::pair<uint8_t, bool>> patternBytes;
    std::istringstream stream(pattern);
    std::string token;

    while (stream >> token) {
        if (token == OBF("?")) {
            patternBytes.emplace_back(0, false);
        }
        else {
            uint8_t byte = static_cast<uint8_t>(std::strtoul(token.c_str(), nullptr, 16));
            patternBytes.emplace_back(byte, true);
        }
    }

    return patternBytes;
}


using GetSystemInfo_t = VOID(WINAPI*)(_Out_ LPSYSTEM_INFO lpSystemInfo);
static GetSystemInfo_t pGetSystemInfo = nullptr;
std::vector<uintptr_t> ScanMemoryForPattern(const std::string& pattern) {
    std::vector<uintptr_t> results;
    SYSTEM_INFO si;
    pGetSystemInfo(&si);

    uintptr_t startAddress = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
    uintptr_t endAddress = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);

    auto patternBytes = PatternToBytes(pattern);
    size_t patternSize = patternBytes.size();

    while (startAddress < endAddress) {
        MEMORY_BASIC_INFORMATION mbi;
        if (pVirtualQuery(reinterpret_cast<LPCVOID>(startAddress), &mbi, sizeof(mbi)) == 0) {
            startAddress += 0x1000;
            continue;
        }

        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE)) {

            uint8_t* memStart = reinterpret_cast<uint8_t*>(mbi.BaseAddress);
            uint8_t* memEnd = memStart + mbi.RegionSize - patternSize;

            while (memStart <= memEnd) {
                bool match = true;
                for (size_t i = 0; i < patternSize; i++) {
                    if (patternBytes[i].second && memStart[i] != patternBytes[i].first) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    results.push_back(reinterpret_cast<uintptr_t>(memStart));
                    memStart += patternSize;
                }
                else {
                    memStart++;
                }
            }
        }

        startAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    }

    return results;
}


using ReadProcessMemory_t = BOOL(WINAPI*)(
    _In_ HANDLE hProcess, _In_ LPCVOID lpBaseAddress, _Out_writes_bytes_to_(nSize, *lpNumberOfBytesRead) LPVOID lpBuffer, _In_ SIZE_T nSize, _Out_opt_ SIZE_T* lpNumberOfBytesRead);
static ReadProcessMemory_t pReadProcessMemory = nullptr;
bool DetectPEHeaders() {
    auto modules = GetLoadedModules();
    SYSTEM_INFO si;
    pGetSystemInfo(&si);

    uintptr_t startAddress = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
    uintptr_t endAddress = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);

    while (startAddress < endAddress) {
        MEMORY_BASIC_INFORMATION mbi;
        if (pVirtualQuery(reinterpret_cast<LPCVOID>(startAddress), &mbi, sizeof(mbi)) == 0) {
            startAddress += 0x1000;
            continue;
        }

        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
        {
            BYTE buffer[0x1000] = {};
            SIZE_T bytesRead = 0;
            if (pReadProcessMemory(pGetCurrentProcess(), mbi.BaseAddress, buffer, sizeof(buffer), &bytesRead) && bytesRead >= sizeof(IMAGE_DOS_HEADER)) {
                auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer);
                if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                    if (dos->e_lfanew > 0 && (dos->e_lfanew < 0x1000 - sizeof(IMAGE_NT_HEADERS))) {
                        auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(buffer + dos->e_lfanew);
                        if (nt->Signature == IMAGE_NT_SIGNATURE) {
                            uintptr_t headerAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                            if (!IsAddressInModule(headerAddr)) {
#ifdef MMP_DEBUG_MOD
                                std::cout << "[!] Found unmapped PE header at 0x" << std::hex << headerAddr << std::dec << std::endl;
#endif
                                return true;
                            }
                        }
                    }
                }
            }
        }
        startAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    }
    return false;
}



NOINLINE HMODULE redirect_kernel32() {
    return GetModuleHandleW(OBF(L"kernel32.dll").c_str());
}

using GetProcAddress_t = FARPROC(WINAPI*)(HMODULE, LPCSTR);
static GetProcAddress_t pGetProcAddress = nullptr;
int MMP_DETECT() {
    static HMODULE hKernel32 = redirect_kernel32();


    static PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hKernel32;
    static PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)hKernel32 + pDos->e_lfanew);
    static PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(
        (BYTE*)hKernel32 + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
        );

    static DWORD* pAddressOfFunctions = (DWORD*)((BYTE*)hKernel32 + pExport->AddressOfFunctions);
    static DWORD* pAddressOfNames = (DWORD*)((BYTE*)hKernel32 + pExport->AddressOfNames);
    static WORD* pAddressOfNameOrdinals = (WORD*)((BYTE*)hKernel32 + pExport->AddressOfNameOrdinals);


    for (DWORD i = 0; i < pExport->NumberOfNames; ++i) {
        char* funcName = (char*)((BYTE*)hKernel32 + pAddressOfNames[i]);
        if (strcmp(funcName, OBF("GetProcAddress").c_str()) == 0) {
            pGetProcAddress = (GetProcAddress_t)((BYTE*)hKernel32 + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
            break;
        }
    }

    if (!pGetProcAddress) {
#ifdef MMP_DEBUG_MOD
        std::cerr << "[-]Failed to get address of GetProcAddress!" << std::endl;
#endif
        return -1;
    }

    for (DWORD i = 0; i < pExport->NumberOfNames; ++i) {
        char* funcName = (char*)((BYTE*)hKernel32 + pAddressOfNames[i]);
        if (strcmp(funcName, OBF("GetCurrentProcess").c_str()) == 0) {
            pGetCurrentProcess = (GetCurrentProcess_t)((BYTE*)hKernel32 + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
            break;
        }
    }

    if (!pGetCurrentProcess) {
#ifdef MMP_DEBUG_MOD
        std::cerr << "[-]Failed to get address of GetCurrentProcess!" << std::endl;
#endif
        return -1;
    }

    for (DWORD i = 0; i < pExport->NumberOfNames; ++i) {
        char* funcName = (char*)((BYTE*)hKernel32 + pAddressOfNames[i]);
        if (strcmp(funcName, OBF("GetModuleHandleExW").c_str()) == 0) {
            pGetModuleHandleExW = (GetModuleHandleExW_t)((BYTE*)hKernel32 + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
            break;
        }
    }

    if (!pGetModuleHandleExW) {
#ifdef MMP_DEBUG_MOD
        std::cerr << "[-]Failed to get address of GetModuleHandleExW!" << std::endl;
#endif
        return -1;
    }

    for (DWORD i = 0; i < pExport->NumberOfNames; ++i) {
        char* funcName = (char*)((BYTE*)hKernel32 + pAddressOfNames[i]);
        if (strcmp(funcName, OBF("GetSystemInfo").c_str()) == 0) {
            pGetSystemInfo = (GetSystemInfo_t)((BYTE*)hKernel32 + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
            break;
        }
    }

    if (!pGetSystemInfo) {
#ifdef MMP_DEBUG_MOD
        std::cerr << "[-]Failed to get address of GetSystemInfo!" << std::endl;
#endif
        return -1;
    }

    for (DWORD i = 0; i < pExport->NumberOfNames; ++i) {
        char* funcName = (char*)((BYTE*)hKernel32 + pAddressOfNames[i]);
        if (strcmp(funcName, OBF("VirtualQuery").c_str()) == 0) {
            pVirtualQuery = (VirtualQuery_t)((BYTE*)hKernel32 + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
            break;
        }
    }

    if (!pVirtualQuery) {
#ifdef MMP_DEBUG_MOD
        std::cerr << "[-]Failed to get address of VirtualQuery!" << std::endl;
#endif
        return -1;
    }


    FARPROC pDisableThreadLibraryCalls = pGetProcAddress(hKernel32, OBF("DisableThreadLibraryCalls").c_str());

    if (!pDisableThreadLibraryCalls) {
#ifdef MMP_DEBUG_MOD
        std::cerr << "[-]Failed to get address of DisableThreadLibraryCalls!" << std::endl;
#endif
        return -1;
    }


    for (DWORD i = 0; i < pExport->NumberOfNames; ++i) {
        char* funcName = (char*)((BYTE*)hKernel32 + pAddressOfNames[i]);
        if (strcmp(funcName, OBF("ReadProcessMemory").c_str()) == 0) {
            pReadProcessMemory = (ReadProcessMemory_t)((BYTE*)hKernel32 + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
            break;
        }
    }

    if (!pReadProcessMemory) {
#ifdef MMP_DEBUG_MOD
        std::cerr << "[-]Failed to get address of ReadProcessMemory!" << std::endl;
#endif
        return -1;
    }


#ifdef MMP_DEBUG_MOD
    std::cout << "[+] Scanning for headers...\n";
#endif
    if (DetectPEHeaders()) {
#ifdef MMP_DEBUG_MOD
        std::cout << "[!] Headers detected!\n";
#endif
        return 1;
    }

    static const std::vector<std::pair<const char*, std::string>> patterns = {
        {OBF("EP_7").c_str(), OBF("48 89 5C 24 08 48 89 74 24 10 57 48 83 EC ? 49 8B F8 8B DA 48 8B F1 83 FA ?").c_str()}
    };

    std::vector<uintptr_t> epAddresses;
#ifdef MMP_DEBUG_MOD
    system("cls");
    std::cout << "[+] Scanning for entry point patterns...\n";
#endif
    for (const auto& [name, pattern] : patterns) {
        std::vector<uintptr_t> addresses = ScanMemoryForPattern(pattern);
#ifdef MMP_DEBUG_MOD
        std::cout << "[+] Pattern \"" << name << "\" matches: " << addresses.size() << std::endl;
#endif
        for (uintptr_t addr : addresses) {
            MEMORY_BASIC_INFORMATION mbi;
            if (pVirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) {
#ifdef MMP_DEBUG_MOD
                std::cout << "[+] Found at: 0x" << std::hex << addr << std::dec << std::endl;
#endif
                if (!IsAddressInModule(reinterpret_cast<uintptr_t>(mbi.AllocationBase))) {
#ifdef MMP_DEBUG_MOD
                    std::wcout << L"[!] Manual mapping detected!" << std::endl;
                    system("pause");
#endif
                    return 1;
                }
                else {
                    epAddresses.push_back(addr);
                }
            }
        }
    }

#ifdef MMP_DEBUG_MOD
    std::cout << "[+] Scanning for calls to DisableThreadLibraryCalls...\n";
#endif
    std::vector<uintptr_t> callAddresses = ScanMemoryForPattern(OBF("FF 15 ? ? ? ?"));
    for (uintptr_t addr : callAddresses) {
        int32_t disp32 = *(int32_t*)(addr + 2);
        uintptr_t mem_loc = addr + 6 + disp32;

        MEMORY_BASIC_INFORMATION mbi;
        if (pVirtualQuery((LPCVOID)mem_loc, &mbi, sizeof(mbi)) &&
            (mbi.Protect & PAGE_READONLY || mbi.Protect & PAGE_READWRITE)) {
            uint64_t func_addr = *(uint64_t*)mem_loc;
            if (func_addr == (uint64_t)pDisableThreadLibraryCalls) {
#ifdef MMP_DEBUG_MOD
                std::cout << "[+] Found call to DisableThreadLibraryCalls at 0x" << std::hex << addr << std::dec << std::endl;
#endif
                if (!IsAddressInModule(addr)) {
#ifdef MMP_DEBUG_MOD
                    std::cout << "[!] DisableThreadLibraryCalls call from manually mapped region detected!" << std::endl;
#endif
                    return 1;
                }
            }
        }
    }
    return 0;
}