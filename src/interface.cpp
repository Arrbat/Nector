#include <iostream>
#include <cstring>

int ParseCommands(int argumentsNumber, char* commands[], int& filePathIndex, int& logPathIndex) 
{
    if (argumentsNumber > 1)
    {
        for (int i = 0; i < argumentsNumber; ++i) 
        {
            // nector.exe --help
            if (strcmp(commands[i], "--help") == 0) 
            {
                return 1;
            }
            else if (strcmp(commands[i], "--static-parse") == 0)
            {
                // nector.exe --static-parse "PATH_TO_PE.pe_extension"
                if (i + 1 < argumentsNumber && i + 2 == argumentsNumber)
                {
                    filePathIndex = i + 1;
                    logPathIndex = -1;
                    return 2;
                }
                // nector.exe --static-parse "PATH_TO_PE.pe_extension" --log-file "PATH_FOR_LOG_FILE.txt"
                else if (i + 3 < argumentsNumber && strcmp(commands[i+2], "--log-file") == 0 && i + 4 == argumentsNumber)
                {
                    filePathIndex = i + 1;
                    logPathIndex = i + 3;
                    return 2;
                }
                else
                {
                    std::cout << "No file path provided for static parse.\n";
                    return 0;
                }
            }
        }
    }
    else
    {
        std::cout << "No arguments provided. Use --help command to see details. \n";
    }
    return 0;
}

int PrintHelpMessage()
{
    std::cout << "Nector (network inspector) is a tool designed for extracting IoC and analysing network behavior of malware (or other) PE files\n\n";
    std::cout << "USAGE:\n";
    std::cout << "--help\t\t\t\t\t for printing this help message\n";
    std::cout << "--static-parse <PATH_TO_PE.pe_extension> for parsing statically your PE\n";
    std::cout << "Example: nector.exe --static-parse \"file.exe\"\n\n";
    std::cout << "OPTIONS:\n";
    std::cout << "--log-file <PATH_TO_FILE.txt>\t\t for logging IoC into .txt file (existing or will be created one)\n";
    std::cout << "Example: nector.exe --static-parse \"file.exe\" --log-file \"log.txt\"\n";
    return 0;
}