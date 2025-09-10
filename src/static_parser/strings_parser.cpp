#include <iostream>
#include <fstream>
#include <string>
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

bool containsIC(const std::string& str, const std::string& pattern)
{
    if(pattern.size() > str.size()) return false;
    for(size_t i=0;i<=str.size()-pattern.size();i++)
    {
        bool match = true;
        for(size_t j=0;j<pattern.size();j++)
        {
            if(tolower(str[i+j]) != tolower(pattern[j])) { match=false; break; }
        }
        if(match) return true;
    }
    return false;
}

const std::string domainTLDs[] = {".com", ".net", ".org", ".xyz", ".info", ".top", ".ru"};
const std::string protocols[] = {"http://", "https://", "ftp://", "http", "https", "ftp"};
const std::string winSockFuncs[] = {
    "socket", "connect", "recv", "send", "WSAStartup", "WSACleanup", "bind", "listen", "accept"
};

inline bool isPrintable(char c) { return (c >= 0x20 && c <= 0x7e); }

void extractStringsASCII(const char* buffer, size_t size, std::unordered_map<std::string,int>& counters, size_t minLen = 4)
{
    size_t i = 0;
    while(i < size)
    {
        size_t start = i;
        while(i < size && isPrintable(buffer[i])) i++;
        if(i - start >= minLen)
        {
            std::string s(buffer+start, i-start);
            counters[s]++;
        }
        i++;
    }
}

void printIoC(const std::unordered_map<std::string,int>& counters)
{
    std::unordered_map<std::string,int> domainCounter;
    std::unordered_map<std::string,int> protocolCounter;
    std::unordered_map<std::string,int> winSockCounter;

    for(const auto& p : counters)
    {
        const std::string& s = p.first;
        int count = p.second;

        // domain
        for(const auto& tld : domainTLDs)
            if(containsIC(s,tld)) domainCounter[s]+=count;

        // protocol
        for(const auto& proto : protocols)
            if(containsIC(s,proto)) protocolCounter[s]+=count;

        // Net funcs
        for(const auto& fn : winSockFuncs)
            if(containsIC(s,fn)) winSockCounter[s]+=count;
    }

    std::cout << "\n=== IoC Report ===\n";
    std::cout << "Domains found:\n";
    for(const auto& p : domainCounter)
        std::cout << p.first << " : " << p.second << "\n";

    std::cout << "\nProtocols found:\n";
    for(const auto& p : protocolCounter)
        std::cout << p.first << " : " << p.second << "\n";

    std::cout << "\nWindows network API functions/strings found:\n";
    for(const auto& p : winSockCounter)
        std::cout << p.first << " : " << p.second << "\n";
}


int PE_ParseStrings(std::string pathToFile)
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
    std::unordered_map<std::string,int> stringCounters;
    extractStringsASCII(buffer, fileSize, stringCounters, 4);
    printIoC(stringCounters);

    delete[] buffer;
    return 0;
}