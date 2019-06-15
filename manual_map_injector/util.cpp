#include <iostream>
#include "util.hpp"

namespace util
{
	void draw_header()
	{
		printf("                     _           \n");
		printf(" _ _  __ _ _ __  ___| |___ ______\n");
		printf("| ' \\/ _` | '  \\/ -_) / -_|_-<_-<\n");
		printf("|_||_\\__,_|_|_|_\\___|_\\___/__/__/\n\n");
	}

	[[noreturn]] void exception(std::string error_msg)
	{
		std::cerr << error_msg.c_str() << std::endl << std::endl << "press enter to exit...";
		getchar();
		exit(0);
	}
}