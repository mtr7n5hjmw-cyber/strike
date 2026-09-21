#include "Hwid.h"

#include <windows.h>
#include <winhttp.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <string>
#include <thread>
#include <cstring>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")

namespace {
constexpr unsigned short HELPER_PORT = 37891;
constexpr wchar_t BACKEND_HOST[] = L"strike-khu8.onrender.com";
constexpr wchar_t ALLOWED_ORIGIN[] = L"https://strike-khu8.onrender.com";
constexpr wchar_t HELPER_SHARED_TOKEN[] = L"e460a929fbd7867ec091225b6bf54270jhadjfoajwfgojaowngoinawroghioewhgewggggggggggggggggggggggggewfwqfwf";

std::string Narrow(const std::wstring& value) {
    return std::string(value.begin(), value.end());
}

bool IsAllowedOrigin(const std::string& request) {
    const std::string marker = "Origin: ";
    const size_t position = request.find(marker);
    if (position == std::string::npos) return false;
    const size_t end = request.find("\r\n", position);
    return request.substr(position + marker.size(), end - position - marker.size()) == Narrow(ALLOWED_ORIGIN);
}

std::string GetQueryValue(const std::string& request, const std::string& key) {
    const std::string marker = key + "=";
    const size_t start = request.find(marker);
    if (start == std::string::npos) return {};
    const size_t valueStart = start + marker.size();
    const size_t valueEnd = request.find_first_of(" &\r\n", valueStart);
    return request.substr(valueStart, valueEnd - valueStart);
}

bool SendVerification(const std::string& challenge) {
    const std::string hwid = GetStrikeMenuHwid();
    const std::wstring path = L"/api/hwid/check/complete";
    const std::string body = "{\"challenge\":\"" + challenge + "\",\"hwid\":\"" + hwid + "\",\"helperToken\":\"" + Narrow(HELPER_SHARED_TOKEN) + "\"}";

    HINTERNET session = WinHttpOpen(L"StrikeMenuHelper/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, nullptr, nullptr, 0);
    if (!session) return false;
    HINTERNET connection = WinHttpConnect(session, BACKEND_HOST, INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET request = connection ? WinHttpOpenRequest(connection, L"POST", path.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE) : nullptr;
    const wchar_t headers[] = L"Content-Type: application/json\r\n";
    const bool sent = request && WinHttpSendRequest(request, headers, static_cast<DWORD>(-1), const_cast<char*>(body.data()), static_cast<DWORD>(body.size()), static_cast<DWORD>(body.size()), 0) && WinHttpReceiveResponse(request, nullptr);
    if (request) WinHttpCloseHandle(request);
    if (connection) WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    return sent;
}

void Reply(SOCKET client, int status, const char* body) {
    const std::string response = "HTTP/1.1 " + std::to_string(status) + " OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: " + Narrow(ALLOWED_ORIGIN) + "\r\nContent-Length: " + std::to_string(strlen(body)) + "\r\nConnection: close\r\n\r\n" + body;
    send(client, response.data(), static_cast<int>(response.size()), 0);
}
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return 1;
    SOCKET server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(HELPER_PORT);
    if (server == INVALID_SOCKET || bind(server, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR || listen(server, 4) == SOCKET_ERROR) return 1;

    for (;;) {
        SOCKET client = accept(server, nullptr, nullptr);
        if (client == INVALID_SOCKET) continue;
        char request[8192]{};
        const int received = recv(client, request, sizeof(request) - 1, 0);
        const std::string text(request, received > 0 ? received : 0);
        if (!IsAllowedOrigin(text)) {
            Reply(client, 403, "{\"error\":\"Origin not allowed\"}");
        } else if (text.rfind("OPTIONS", 0) == 0) {
            Reply(client, 204, "{}");
        } else if (text.rfind("GET /check?", 0) == 0) {
            const std::string challenge = GetQueryValue(text, "challenge");
            Reply(client, !challenge.empty() && SendVerification(challenge) ? 202 : 400, "{\"accepted\":true}");
        } else {
            Reply(client, 404, "{\"error\":\"Not found\"}");
        }
        closesocket(client);
    }
}
