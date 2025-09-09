@echo off

echo Note that building requires x86_64-w64-mingw32-g++ compiler and supports only Windows 64-bit.

:: ---------- Compile ----------
x86_64-w64-mingw32-g++                   ^
    -Iheaders                            ^
    main.cpp                             ^
    src/interface.cpp                    ^
    src/static_parser/strings_parser.cpp ^
    headers/interface.hpp                ^
    headers/static_parser.hpp            ^
    -o nector.exe

if %errorlevel% equ 0 (
    echo BUILDING SUCCESS
) else ( 
    echo BUILDING FAILED
)