
#include <iostream>
#include "WSCLib.h"

int main()
{
	if (!WSCLib::Clean(WSCLib::GetCurrentProcessPath(), false, true)) {
		std::cout << "fail\n";
	}
    std::cout << "Hello World!\n";
}