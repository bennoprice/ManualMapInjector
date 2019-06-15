#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <iostream>
#include <string_view>
#include "process.hpp"
#include "util.hpp"

namespace injector
{
	//
	// process
	//
	process::process(std::uint32_t proc_id)
	{
		// check pid
		if (!proc_id)
			util::exception("[-] failed to get process id.");
		std::cout << "[+] found process id: " << std::dec << proc_id << std::endl;

		// get handle
		_handle = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, proc_id);
		if (_handle == INVALID_HANDLE_VALUE)
			util::exception("[-] handle invalid.");
		std::cout << "[+] got handle: 0x" << std::hex << reinterpret_cast<std::uint64_t>(_handle) << std::endl;
	}

	process::process(std::wstring_view proc_name)
		: process(get_id_from_name(proc_name))
	{ }

	process::~process() noexcept
	{
		::CloseHandle(_handle);
	}

	std::unique_ptr<process::allocation> process::allocate_memory(std::uint32_t protection, std::size_t size) const
	{
		return std::make_unique<allocation>(_handle, protection, size);
	}

	std::unordered_map<std::string, std::uint64_t> process::get_modules() const
	{
		auto modules = std::unordered_map<std::string, std::uint64_t>();

		HMODULE handles[1024] = { 0 };
		DWORD size = 0;

		if (::EnumProcessModules(_handle, handles, sizeof(handles), &size))
		{
			for (auto i = 0u; i < size / sizeof(handles[0]); ++i)
			{
				char name[MAX_PATH];
				::GetModuleBaseNameA(_handle, handles[i], name, sizeof(name));
				modules[std::string(name)] = reinterpret_cast<std::uint64_t>(handles[i]);
			}
		}
		return modules;
	}

	std::unordered_map<std::string, std::uint64_t> process::get_module_exports(std::uint64_t handle) const
	{
		auto exports = std::unordered_map<std::string, std::uint64_t>();

		auto dos_header = rpm<IMAGE_DOS_HEADER>(handle);
		auto nt_headers = rpm<IMAGE_NT_HEADERS64>(handle + dos_header.e_lfanew);

		auto section = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (!section.VirtualAddress)
			return exports;
		auto export_table = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(malloc(section.Size));
		rpm_raw(reinterpret_cast<std::uint64_t>(export_table), handle + section.VirtualAddress, section.Size);

		auto delta = reinterpret_cast<std::uint64_t>(export_table) - section.VirtualAddress;
		auto function_names = reinterpret_cast<std::uint32_t*>(export_table->AddressOfNames + delta);
		auto function_addrs = reinterpret_cast<std::uint32_t*>(export_table->AddressOfFunctions + delta);
		auto ordinal_addrs = reinterpret_cast<std::uint16_t*>(export_table->AddressOfNameOrdinals + delta);

		for (auto i = 0u; i < export_table->NumberOfNames; ++i)
			exports[std::string(reinterpret_cast<char*>(function_names[i] + delta))] = handle + function_addrs[ordinal_addrs[i]];
		return exports;
	}

	void process::set_memory_protection(std::uint64_t addr, std::size_t size, std::uint32_t protection) const
	{
		DWORD old_prot;
		::VirtualProtectEx(_handle, reinterpret_cast<void*>(addr), size, protection, &old_prot);
	}

	void process::rpm_raw(std::uint64_t dest, std::uint64_t src, std::size_t size) const
	{
		::ReadProcessMemory(_handle, reinterpret_cast<void*>(src), reinterpret_cast<void*>(dest), size, nullptr);
	}

	void process::wpm_raw(std::uint64_t dest, std::uint64_t src, std::size_t size) const
	{
		::WriteProcessMemory(_handle, reinterpret_cast<void*>(dest), reinterpret_cast<void*>(src), size, nullptr);
	}

	void process::create_thread(std::uint64_t start_addr) const
	{
		::CreateRemoteThread(_handle, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(start_addr), nullptr, 0, 0);
	}

	std::uint32_t process::get_id_from_name(std::wstring_view proc_name) const
	{
		auto cur_proc_id = ::GetCurrentProcessId();
		auto snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		auto pe = PROCESSENTRY32W{ sizeof(PROCESSENTRY32W) };

		if (::Process32First(snapshot, &pe))
		{
			do {
				if (!_wcsicmp(proc_name.data(), pe.szExeFile) && pe.th32ProcessID != cur_proc_id)
				{
					::CloseHandle(snapshot);
					return pe.th32ProcessID;
				}
			} while (::Process32Next(snapshot, &pe));
		}
		::CloseHandle(snapshot);
		return 0;
	}

	//
	// allocation
	//
	process::allocation::allocation(HANDLE handle, std::uint32_t protection, std::size_t size)
		: _handle(handle)
		, _size(size)
	{
		_addr = ::VirtualAllocEx(_handle, 0, _size, MEM_RESERVE | MEM_COMMIT, protection);
	}

	void process::allocation::free() const
	{
		::VirtualFreeEx(_handle, _addr, _size, MEM_RELEASE);
	}

	std::uint64_t process::allocation::get_addr() const
	{
		return reinterpret_cast<std::uint64_t>(_addr);
	}

	std::size_t process::allocation::get_size() const
	{
		return _size;
	}
}