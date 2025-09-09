#include <iostream>
#include "interface.hpp"
#include "static_parser.hpp"

int main(int argc, char *argv[]) 
{
    int filePathIndex = -1;
    switch (ParseCommands(argc, argv, filePathIndex)) 
    {
        case 1:
            PrintHelpMessage();
            break;
        case 2:
            if (filePathIndex != -1)
            {
                ParseStrings(argv[filePathIndex]);
            }
        default:
            break;
    }

    return 0;
}
