# TL;DR
Nector (Network inspector) is a tool for both static and dynamic analysis of real and possible network behaviour designed for malware analysis. 

Nector extracts Indicators of Compromise of provided sample. In terms of numbers, every new version of tool is tested on some malware samples (<=10) locally, including RATs, stealers, worms, bots and other malware classes. Families include xworm, amadey, remcos, lummastealer, infostealer etc.

Tests show that approximately 20-30% of positive real-world results were obtained when extracting IoC. Since that this tool must be considered as proof of concept, because of many false-positives f.e.

# Limitations

- Only PE format support and only Windows x64 OS support

# Functionality

- Extraction of domain names, ip (v4) addresses, urls, emails, protocols and API functions names

- ACSII, UTF16LE extraction support

- PE parsing with regular expessions 

- IoC logging if needed (.txt format support)

# Build

Just double-click on WindowsBuild.bat file or run this file with following command:

`WindowsBuild.bat`

# Usage

Since interface and functionality may be changed, actual info of some Nector version is provided with `--help` command:

`nector.exe --help`

# Example

The very successful output mey be like that (test names):

```
Starting static parsing of PE file... 
Using path:     NectorTest.exe

======  IoC Report  ======

Domains found:
server.com : 1
http://malicious.com : 1
admin@evil.org : 1
test.xyz : 1
safe.com : 1

Protocols/URLs found:
http://malicious.com : 1

IPv4 addresses found:
2.168.1.1 : 1
192.168.1.1 : 1
92.168.1.1 : 1

Email addresses found:
admin@evil.org : 1

```