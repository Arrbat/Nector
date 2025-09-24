#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <unordered_map>
#include <cctype>
#include <windows.h>
#include "static_parser.hpp" 

int isPE(std::string pathToFile)
{
    std::ifstream file(pathToFile, std::ios::binary);
    if (!file)
    {
        std::cout << "Unable to open file. \n";
        return 1;
    }

    char MZBytes[2] = {0};
    file.read(MZBytes, 2);
    if (!file)
    {
        std::cout << "Unable to read file. \n";
        return 1;
    }

    if (MZBytes[0] == 'M' && MZBytes[1] == 'Z') return 0;
    else return 1;
}

bool isOnlyDigitsAndDots(const std::string& s) 
{
    for (char c : s) {
        if (!(isdigit(c) || c == '.')) return false;
    }
    return true;
}

bool isValidDomain(const std::string& s) 
{
    if (s.empty() || s.front() == '.' || s.back() == '.') return false;
    size_t dotCount = 0;
    for (char c : s) if (c == '.') ++dotCount;
    return dotCount >= 1;
}

bool isValidEmail(const std::string& s) 
{
    size_t at = s.find('@');
    if (at == std::string::npos || at == 0 || at == s.size()-1) return false;
    return isValidDomain(s.substr(at+1));
}

bool isValidURL(const std::string& s) 
{
    size_t proto = s.find("://");
    if (proto == std::string::npos) return false;
    size_t start = proto + 3;
    size_t end = s.find('/', start);
    std::string host = (end == std::string::npos) ? s.substr(start) : s.substr(start, end-start);
    return isValidDomain(host);
}

inline bool isPrintableASCII(char c) 
{ 
    return (c >= 0x20 && c <= 0x7e); 
}

bool containsIC(const std::string& str, const std::string& pattern)
{
    if (pattern.size() > str.size()) return false;
    for (size_t i=0;i<=str.size()-pattern.size();i++)
    {
        bool match = true;
        for (size_t j=0;j<pattern.size();j++)
        {
            if (tolower(str[i+j]) != tolower(pattern[j])) { match=false; break; }
        }
        if (match) return true;
    }
    return false;
}

void extractStringsASCII(const char* buffer, size_t size, std::unordered_map<std::string,int>& counters, size_t minLen = 4)
{
    size_t i = 0;
    while (i < size)
    {
        size_t start = i;
        while (i < size && isPrintableASCII(buffer[i])) i++;
        if (i - start >= minLen)
        {
            std::string s(buffer+start, i-start);
            counters[s]++;
        }
        i = start + 1;
    }
}

void extractStringsUTF16LE(const char* buffer, size_t size, std::unordered_map<std::string, std::pair<int, size_t>>& counters, size_t minLen = 4)
{
    size_t i = 0;
    while (i + 1 < size)
    {
        size_t start = i;
        std::string s;
        while (i + 1 < size && isPrintableASCII(buffer[i]) && buffer[i+1] == 0)
        {
            s += buffer[i];
            i += 2;
        }
        if (s.length() >= minLen)
        {
            if (counters.find(s) == counters.end() || counters[s].second > start)
                counters[s] = {1, start};
            else
                counters[s].first++;
        }
        i = (s.length() > 0) ? i : i + 2;
    }
}

bool FilterIoC(const std::string& s, bool requireTLD, bool checkBlacklist) {
    const std::string domainTLDs[] = {
        ".com", ".net", ".org", ".xyz", ".info", ".top", ".ru", ".cn", ".cc", ".pw", ".biz", ".us", ".uk", ".io", ".me", ".co", ".su", ".in", ".de", ".fr", ".eu", ".pl", ".tk", ".ga", ".cf", ".ml", ".gq", ".to", ".tv", ".site", ".online", ".store", ".space", ".website", ".club", ".pro", ".vip", ".work", ".app", ".mobi", ".name", ".live", ".win", ".men", ".bid", ".stream", ".click", ".link", ".email", ".download", ".trade", ".party", ".science", ".loan", ".date", ".faith", ".review", ".host", ".press", ".fun", ".cam", ".shop", ".monster", ".gov", ".mil", ".edu", ".int", ".arpa", ".asia", ".cat", ".jobs", ".museum", ".post", ".tel", ".travel", ".aero", ".coop", ".bank", ".insurance", ".law", ".med", ".music", ".news", ".tech", ".dev", ".cloud", ".blog", ".design", ".eco", ".health", ".kids", ".love", ".page", ".video", ".zone"
    };
    const std::string blacklist[] = {
        ".cpp", ".startup", ".part.0", ".dll", ".exe", ".obj", ".lib", ".h", ".hpp", ".c", ".bss", ".data", ".text", ".rdata", ".idb", ".pdb", ".bak", ".tmp", ".log", ".manifest", ".cmd", ".bat", ".sh", ".ps1", ".json", ".xml", ".yaml", ".yml", ".ini", ".config", ".cache", ".lock", ".md", ".rst", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".zip", ".tar", ".gz", ".7z", ".rar", ".iso", ".img", ".vhd", ".vmdk"
    };
    bool isValidTLD = false;
    bool isBlacklisted = false;
    if (requireTLD) {
        for (const auto& tld : domainTLDs) {
            if (s.size() > tld.size() && s.substr(s.size() - tld.size()) == tld) {
                isValidTLD = true;
                break;
            }
        }
    } else {
        isValidTLD = true;
    }
    if (checkBlacklist) {
        for (const auto& ext : blacklist) {
            if (s.size() > ext.size() && s.substr(s.size() - ext.size()) == ext) {
                isBlacklisted = true;
                break;
            }
        }
    }
    return isValidTLD && !isBlacklisted;
}

void printIoC(const std::unordered_map<std::string,int>& counters)
{
    std::unordered_map<std::string,int> domainCounter;
    std::unordered_map<std::string,int> protocolCounter;
    std::unordered_map<std::string,int> winSockCounter;
    std::unordered_map<std::string,int> ipv4Counter;
    std::unordered_map<std::string,int> emailCounter;

    // Helper to keep only full (not substring) IoCs
    auto filter_full_iocs = [](const std::unordered_map<std::string,int>& input) {
        std::vector<std::string> keys;
        for (const auto& p : input) keys.push_back(p.first);
        std::vector<bool> is_sub(keys.size(), false);
        for (size_t i = 0; i < keys.size(); ++i) {
            for (size_t j = 0; j < keys.size(); ++j) {
                if (i != j && keys[j].find(keys[i]) != std::string::npos) {
                    if (keys[j].size() > keys[i].size()) {
                        is_sub[i] = true;
                        break;
                    }
                }
            }
        }
        std::unordered_map<std::string,int> result;
        for (size_t i = 0; i < keys.size(); ++i) {
            if (!is_sub[i]) result[keys[i]] = input.at(keys[i]);
        }
        return result;
    };

    const std::regex domainRegex(R"((?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,24})");
    const std::regex urlRegex(R"((https?|ftp|sftp|ftps|ws|wss|smtp|imap|pop3|ldap|smb|rdp|dns|irc|tcp|udp)://[a-zA-Z0-9\-._~%]+(\.[a-zA-Z]{2,24})+(:\d+)?(/[a-zA-Z0-9\-._~%!$&'()*+,;=:@/?]*)?)");
    const std::regex ipv4Regex(R"((?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3})");
    const std::regex emailRegex(R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,24})");
    const std::regex apiRegex(R"(\b(socket|connect|recv|send|WSAStartup|WSACleanup|bind|listen|accept|closesocket|gethostbyname
                                |gethostbyaddr|getaddrinfo|getnameinfo|inet_addr|inet_ntoa|inet_pton|inet_ntop|shutdown|setsockopt
                                |getsockopt|select|ioctlsocket|WSAGetLastError|WSASetLastError|WSARecv|WSASend|WSAConnect|WSAAccept
                                |WSAAsyncSelect|WSAEventSelect|InternetOpen|InternetConnect|InternetOpenUrl|InternetReadFile
                                |InternetWriteFile|HttpOpenRequest|HttpSendRequest|HttpQueryInfo|WinHttpOpen|WinHttpConnect
                                |WinHttpOpenRequest|WinHttpSendRequest|WinHttpReceiveResponse|WinHttpReadData|WinHttpWriteData
                                |URLDownloadToFile|OpenSCManager|CreateService|OpenService|StartService|ControlService|DeleteService
                                |CloseServiceHandle|NetUserAdd|NetUserDel|NetUserEnum|NetLocalGroupAddMembers|NetLocalGroupDelMembers
                                |NetShareAdd|NetShareDel|NetSessionEnum|NetWkstaUserEnum)\b)");

    for (const auto& p : counters)
    {
        const std::string& s = p.first;
        int count = p.second;

        if (s.length() >= 6 && std::regex_search(s, domainRegex) && FilterIoC(s, true, true) && isValidDomain(s))
            domainCounter[s] += count;
        if (s.length() >= 6 && std::regex_search(s, urlRegex) && FilterIoC(s, true, true) && isValidURL(s))
            protocolCounter[s] += count;
        if (s.length() >= 7 && std::regex_match(s, ipv4Regex) && FilterIoC(s, false, true) && isOnlyDigitsAndDots(s))
        {
            //common ip or version numbers (skip)
            if (s == "1.0.0.0" || s == "14.0.0.0" || s == "4.0.0.0" || s == "255.255.255.255") 
                continue;
            ipv4Counter[s] += count;
        }
        if (s.length() >= 6 && std::regex_search(s, emailRegex) && FilterIoC(s, true, true) && isValidEmail(s))
            emailCounter[s] += count;
        for(const auto& fn : winSockFuncs)
            if(containsIC(s,fn) && s.length() == fn.length()) winSockCounter[s] += count;
    }

    std::cout << "\n======  IoC Report  ======\n";

    auto filteredDomains = filter_full_iocs(domainCounter);
    auto filteredProtocols = filter_full_iocs(protocolCounter);
    auto filteredEmails = filter_full_iocs(emailCounter);

    if (filteredDomains.size() > 0)
    {
        std::cout << "\nDomains found:\n";
        for (const auto& p : filteredDomains)
            std::cout << p.first << " : " << p.second << "\n";
    }

    if (filteredProtocols.size() > 0)
    {
        std::cout << "\nProtocols/URLs found:\n";
        for (const auto& p : filteredProtocols)
            std::cout << p.first << " : " << p.second << "\n";
    }

    if (ipv4Counter.size() > 0)
    {
        std::cout << "\nIPv4 addresses found:\n";
        for (const auto& p : ipv4Counter)
            std::cout << p.first << " : " << p.second << "\n";
    }

    if (filteredEmails.size() > 0)
    {
        std::cout << "\nEmail addresses found:\n";
        for (const auto& p : filteredEmails)
            std::cout << p.first << " : " << p.second << "\n";
    }

    if (winSockCounter.size() > 0)
    {
        std::cout << "\nWindows network API functions/strings found:\n";
        for (const auto& p : winSockCounter)
            std::cout << p.first << " : " << p.second << "\n";
    }
}

int PE_ParseStrings(std::string pathToFile, std::string pathToLogFile)
{
    std::cout << "Using path:\t" << pathToFile << "\n";

    std::ifstream file(pathToFile.c_str(), std::ios::binary | std::ios::ate);
    if (!file)
    {
        std::cout << "Unable to open file. \n";
        return 1;
    }
    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    char* buffer = new char[fileSize];
    if (!file.read(buffer, fileSize))
    {
        std::cout << "Unable to read file. \n";
        delete[] buffer;
        return 1;
    }

    // Map of all strings that were found
    std::unordered_map<std::string, std::pair<int, size_t>> stringCounters;
    extractStringsASCII(buffer, fileSize, reinterpret_cast<std::unordered_map<std::string,int>&>(stringCounters), 4);
    extractStringsUTF16LE(buffer, fileSize, stringCounters, 4);

    std::unordered_map<std::string, int> simpleCounters;
    for (const auto& kv : stringCounters) {
        simpleCounters[kv.first] = kv.second.first;
    }
    printIoC(simpleCounters);

    if (pathToLogFile.empty())
    {
        /* pass */
    }
    else
    {
        if (pathToLogFile.size() >= 4 && pathToLogFile.compare(pathToLogFile.size() - 4, 4, ".txt") == 0)
        {
            std::ofstream logFile(pathToLogFile.c_str());
            if (logFile.is_open())
            {
                std::streambuf* oldCoutBuf = std::cout.rdbuf();
                std::cout.rdbuf(logFile.rdbuf());
                // Convert stringCounters to a map<string, int> for printIoC
                std::unordered_map<std::string, int> simpleCounters;
                for (const auto& kv : stringCounters) {
                    simpleCounters[kv.first] = kv.second.first;
                }
                printIoC(simpleCounters);
                std::cout.rdbuf(oldCoutBuf);
                logFile.close();

            }
            else
            {
                std::cout << "Error while opening log file for writing.";
            }
        }
        else
        {
            std::cout << "Error: log file must end with .txt";
        }
    }


    delete[] buffer;
    return 0;
}