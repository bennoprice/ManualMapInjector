#include <Windows.h>
#include <iostream>
#include "util.hpp"
#include "process.hpp"
#include "portable_executable.hpp"

#include <chrono>

// return smart pointer to vectors
// come up with better name for loaded executable
// dont map section header or .pdata or .tls (decrease allocation size)
// add more console debug information
// resolve exports properly by resolving api set schema mapping
// cache text section or sections so dont get again later for making text section executable

int main()
{
	util::draw_header();

	auto local_proc				= std::make_unique<injector::process>(GetCurrentProcessId());
	auto remote_proc			= std::make_unique<injector::process>(L"var_tester.exe");
	auto portable_executable	= std::make_shared<injector::portable_executable>(L"C:\\Users\\Ben\\Documents\\Visual Studio 2017\\Projects\\hello_world_dll\\x64\\Release\\hello_world_dll.dll");

	// allocate memory in local and remote process
	auto image_size		= portable_executable->get_nt_headers()->OptionalHeader.SizeOfImage;
	auto local_image	= local_proc->allocate_memory(PAGE_READWRITE, image_size);
	auto remote_image	= remote_proc->allocate_memory(PAGE_READWRITE, image_size);

	// copy image sections to local image
	for (auto& section : portable_executable->get_sections())
		std::memcpy(reinterpret_cast<void*>(local_image->get_addr() + section.VirtualAddress), reinterpret_cast<void*>(portable_executable->get_buffer() + section.PointerToRawData), section.SizeOfRawData);
	std::cout << "[+] sections mapped to local image at: 0x" << std::hex << local_image->get_addr() << std::endl;

	// get loaded portable executable
	auto loaded_executable = std::make_unique<injector::portable_executable::loaded_executable>(portable_executable, local_image->get_addr());

	// relocate local image based on remote image
	for (auto& relocation : loaded_executable->get_relocations())
	{
		static auto delta = remote_image->get_addr() - portable_executable->get_nt_headers()->OptionalHeader.ImageBase;
		for (auto& desc : relocation.descs)
			*reinterpret_cast<std::uint64_t*>(local_image->get_addr() + relocation.rva + desc.get_offset()) += delta;
	}
	std::cout << "[+] local image relocated to remote image" << std::endl;

	// resolve imports by walking remote process export table
	// get all module exports from remote process
	auto process_exports = std::unordered_map<std::string, std::uint64_t>();
	for (auto& module : remote_proc->get_modules())
	{
		auto module_exports = remote_proc->get_module_exports(module.second);
		process_exports.insert(module_exports.begin(), module_exports.end());
	}
	// resolve imports through remote process exports
	for (auto& module_import : loaded_executable->get_imports())
	{
		for (auto& func : module_import.funcs)
		{
			if (process_exports.find(func.name.data()) == process_exports.end())
				util::exception("[-] failed resolve import for: " + std::string(func.name));
			*reinterpret_cast<std::uint64_t*>(local_image->get_addr() + func.rva) = process_exports.at(func.name.data());
		}

		/*static auto modules = remote_proc->get_modules();
		if (modules.find(module_import.name.data()) == modules.end())
			util::exception("[-] failed to find module in remote process: " + std::string(module_import.name));
		std::cout << "[" << module_import.name.data() << "]" << std::endl;

		auto module_exports = remote_proc->get_module_exports(modules.at(module_import.name.data()));
		for (auto& func : module_import.funcs)
		{
			if (module_exports.find(func.name.data()) == module_exports.end())
				util::exception("	[-] failed to resolve import: " + std::string(func.name));
			std::cout << "	resolved import: " << func.name.data() << std::endl;
		}*/
	}
	std::cout << "[+] resolved local image imports to remote image exports" << std::endl;

	// copy fixed local image to remote process
	remote_proc->wpm_raw(remote_image->get_addr(), local_image->get_addr(), remote_image->get_size());
	std::cout << "[+] copied fixed local image to remote image at: 0x" << std::hex << remote_image->get_addr() << std::endl;

	// free local image
	local_image->free();
	std::cout << "[+] freed local image" << std::endl;

	// make remote image .text section executable
	auto entry_point_rva = portable_executable->get_nt_headers()->OptionalHeader.AddressOfEntryPoint;
	for (auto& section : portable_executable->get_sections())
		if (section.VirtualAddress <= entry_point_rva && entry_point_rva < section.VirtualAddress + section.Misc.VirtualSize)
			remote_proc->set_memory_protection(remote_image->get_addr() + section.VirtualAddress, section.SizeOfRawData, PAGE_EXECUTE_READWRITE);
	std::cout << "[+] made remote image .text section executable" << std::endl;

	// call remote image entry point
	remote_proc->create_thread(remote_image->get_addr() + entry_point_rva);
	std::cout << "[+] called remote image entrypoint at: 0x" << std::hex << remote_image->get_addr() + entry_point_rva << std::endl;

	std::cout << std::endl << "press enter to exit...";
	getchar();
}