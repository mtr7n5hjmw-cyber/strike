#include "Hwid.h"

#include <windows.h>
#include <bcrypt.h>
#include <array>
#include <iomanip>
#include <sstream>
#include <stdexcept>

#pragma comment(lib, "bcrypt.lib")

std::string GetStrikeMenuHwid() {
    HKEY key = nullptr;
    wchar_t machineGuid[256] = {};
    DWORD size = sizeof(machineGuid);
    DWORD type = 0;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) {
        throw std::runtime_error("Unable to open the Windows machine identifier.");
    }

    const LONG result = RegQueryValueExW(key, L"MachineGuid", nullptr, &type, reinterpret_cast<LPBYTE>(machineGuid), &size);
    RegCloseKey(key);
    if (result != ERROR_SUCCESS || type != REG_SZ || machineGuid[0] == L'\0') {
        throw std::runtime_error("Unable to read the Windows machine identifier.");
    }

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectSize = 0;
    DWORD dataSize = 0;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0 ||
        BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize), &dataSize, 0) != 0) {
        throw std::runtime_error("Unable to initialize HWID hashing.");
    }

    std::string input;
    for (const wchar_t* current = machineGuid; *current; ++current) {
        input.push_back(static_cast<char>(*current));
    }

    std::string object(objectSize, '\0');
    std::array<unsigned char, 32> digest{};
    if (BCryptCreateHash(algorithm, &hash, reinterpret_cast<PUCHAR>(object.data()), objectSize, nullptr, 0, 0) != 0 ||
        BCryptHashData(hash, reinterpret_cast<PUCHAR>(input.data()), static_cast<ULONG>(input.size()), 0) != 0 ||
        BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) != 0) {
        if (hash) BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        throw std::runtime_error("Unable to calculate the HWID.");
    }

    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);

    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (const unsigned char byte : digest) output << std::setw(2) << static_cast<unsigned int>(byte);
    return output.str();
}