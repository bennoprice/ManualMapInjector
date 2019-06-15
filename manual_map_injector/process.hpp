#pragma once
#include <unordered_map>

namespace injector
{
	class process
	{
	private:
		class allocation
		{
		public:
			explicit allocation(HANDLE handle, std::uint32_t protection, std::size_t size);
			std::uint64_t get_addr() const;
			std::size_t get_size() const;
			void free() const;
		private:
			std::size_t _size;
			HANDLE _handle;
			void* _addr;
		};
	public:
		explicit process(std::wstring_view proc_name);
		explicit process(std::uint32_t proc_id);
		~process() noexcept;

		std::unique_ptr<allocation> allocate_memory(std::uint32_t protection, std::size_t size) const;
		std::unordered_map<std::string, std::uint64_t> get_modules() const;
		std::unordered_map<std::string, std::uint64_t> get_module_exports(std::uint64_t handle) const;
		void set_memory_protection(std::uint64_t addr, std::size_t size, std::uint32_t protection) const;
		void rpm_raw(std::uint64_t dest, std::uint64_t src, std::size_t size) const;
		void wpm_raw(std::uint64_t dest, std::uint64_t src, std::size_t size) const;
		void create_thread(std::uint64_t start_addr) const;

		template<typename T>
		T rpm(std::uint64_t addr) const
		{
			T buf;
			::ReadProcessMemory(_handle, reinterpret_cast<void*>(addr), reinterpret_cast<void*>(&buf), sizeof(T), nullptr);
			return buf;
		}
	private:
		std::uint32_t get_id_from_name(std::wstring_view proc_name) const;
		HANDLE _handle;
	};
}