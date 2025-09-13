#ifndef STATIC_PARSER_HPP
#define STATIC_PARSER_HPP

#include <string>

const std::string winSockFuncs[] = {
    // Winsock
    "socket", "connect", "recv", "send", "WSAStartup", "WSACleanup", "bind", "listen", "accept", "closesocket", 
    "gethostbyname", "gethostbyaddr", "getaddrinfo", "getnameinfo", "inet_addr", "inet_ntoa", "inet_pton", 
    "inet_ntop", "shutdown", "setsockopt", "getsockopt", "select", "ioctlsocket", "WSAGetLastError", "WSASetLastError", 
    "WSARecv", "WSASend", "WSAConnect", "WSAAccept", "WSAAsyncSelect", "WSAEventSelect",
    // HTTP/WinINet/WinHTTP
    "InternetOpen", "InternetConnect", "InternetOpenUrl", "InternetReadFile", "InternetWriteFile", "HttpOpenRequest", 
    "HttpSendRequest", "HttpQueryInfo", "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest", 
    "WinHttpReceiveResponse", "WinHttpReadData", "WinHttpWriteData",
    // Service/Driver
    "OpenSCManager", "CreateService", "OpenService", "StartService", "ControlService", "DeleteService", 
    "CloseServiceHandle",
    // Misc
    "URLDownloadToFile", "NetUserAdd", "NetUserDel", "NetUserEnum", "NetLocalGroupAddMembers", 
    "NetLocalGroupDelMembers", "NetShareAdd", "NetShareDel", "NetSessionEnum", "NetWkstaUserEnum"
};

int isPE(std::string pathToFile);
int PE_ParseStrings(std::string pathToFile, std::string pathToLogFile);

#endif /* STATIC_PARSER_HPP */