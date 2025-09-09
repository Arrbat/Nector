#include <iostream>
#include <cstring>

int ParseCommands(int argumentsNumber, char* commands[], int& filePathIndex) 
{
    if (argumentsNumber > 1)
    {
        for (int i = 0; i < argumentsNumber; ++i) 
        {
            if (strcmp(commands[i], "--help") == 0) 
            {
                return 1;
            }
            else if (strcmp(commands[i], "--static-parse") == 0)
            {
                if (i + 1 < argumentsNumber)
                {
                    filePathIndex = i + 1;
                    return 2;
                }
                else
                {
                    std::cout << "No file path provided for static parse.\n";
                    return 0;
                }
                return 2;
            }
        }
    }
    else
    {
        std::cout << "No arguments provided or arguments are wrong. \n";
    }
    return 0;
}

int PrintHelpMessage()
{
    std::cout << "HELL";
    return 0;
}