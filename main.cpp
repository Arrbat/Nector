#include <iostream>
#include "interface.hpp"
#include "static_parser.hpp"

int main(int argc, char *argv[]) 
{
    int filePathIndex = -1;
    int logPathIndex = -1;

    switch (ParseCommands(argc, argv, filePathIndex, logPathIndex)) 
    {
        case 1:
            PrintHelpMessage();
            break;
        case 2:
            if (filePathIndex != -1)
            {
                if (isPE(argv[filePathIndex]) == 0)
                {
                    std::cout << "Starting static parsing of PE file... \n";
                    if (logPathIndex == -1) 
                        PE_ParseStrings(argv[filePathIndex], "");
                    else 
                        PE_ParseStrings(argv[filePathIndex], argv[logPathIndex]);
                }
                else
                {
                    std::cout << "Not a valid PE file or another error occured while validating file. Terminated. \n";
                    break;
                }
            }
        default:
            break;
    }

    return 0;
}
