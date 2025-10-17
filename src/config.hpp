#pragma once
#include <filesystem>
#include <map>
#include <string>
#include <sys/socket.h> // for sockaddr_storage
#include <tinykvm/common.hpp>
#include <vector>

struct Configuration
{
	std::string main_filename;
	std::string storage_filename;
	std::string snapshot_filename;
	uint16_t concurrency = 1; /* Request VMs */
	uint16_t warmup_connect_requests = 0; /* Warmup requests, individual connections */
	uint16_t warmup_intra_connect_requests = 1; /* Send N requests while connected */
	std::string warmup_path = "/"; /* Path to send requests to */

	float    max_boot_time = 20.0f; /* Seconds */
	float    max_req_time  = 8.0f; /* Seconds */
	// TODO: tinykvm option for unlimited by default
	uint64_t max_address_space = 120 * 1024; /* Megabytes */
	uint64_t max_main_memory = 8 * 1024; /* Megabytes */
	uint32_t max_req_mem   = 128; /* Megabytes of memory for request VMs */
	uint32_t limit_req_mem = 128; /* Megabytes to keep after request */
	uint32_t shared_memory = 0; /* Megabytes */
	uint64_t dylink_address_hint = 2; /* Image base address hint */
	uint64_t heap_address_hint = 256; /* Address hint for the heap */
	uint64_t storage_dylink_address_hint = 0x2000200000; /* Image base address hint for storage VMs */
	uint64_t hugepage_arena_size = 0; /* Megabytes */
	uint64_t hugepage_requests_arena = 0; /* Megabytes */
	bool     storage = false; /* Enable a single non-ephemeral storage VM */
	bool     storage_1_to_1 = false; /* Each request VM gets its own storage VM */
	bool     storage_ipre_permanent = false; /* Permanent IPRE resume */
	bool     executable_heap = true;
	bool     mmap_backed_files = true; /* Use mmap for files */
	bool     hugepages    = false;
	bool     split_hugepages = true;
	bool     transparent_hugepages = false;
	bool     ephemeral = false;
	bool     ephemeral_keep_working_memory = true;
	bool     verbose = false;
	bool     verbose_syscalls = false;
	bool     verbose_mmap_syscalls = false;
	bool     verbose_thread_syscalls = false;
	bool     verbose_pagetable = false;

	std::vector<std::string> environ;
	std::vector<std::string> main_arguments;
	std::vector<std::string> storage_arguments;

	std::vector<tinykvm::VirtualRemapping> vmem_remappings;
	std::vector<tinykvm::VirtualRemapping> storage_remappings;

	struct ComparePathSegments {
			// Sort paths so that /foo/bar < /foo./bar even though '.' < '/'
			bool operator()(const std::filesystem::path& left, const std::filesystem::path& right) const {
				auto [left_it, right_it] = std::mismatch(left.begin(), left.end(), right.begin(), right.end());
				if (left_it == left.end())
					return right_it != right.end();
				if (right_it == right.end())
					return false;
				return *left_it < *right_it;
			};
	};

	struct VirtualPath {
		std::filesystem::path real_path;
		std::filesystem::path virtual_path; /* Path inside the VM, optional */
		bool readable = false;
		bool writable = false;
		bool symlink = false; /* Treated as a symlink path, to be resolved */
	};

	friend std::ostream& operator<<(std::ostream& os, const VirtualPath& v) {
		os<< "VirtualPath{ .real_path=" << v.real_path
			<< ", .virtual_path=" << v.virtual_path
			<< ", " << (v.readable ? "r": "") << (v.writable ? "w": "") << (v.symlink ? "s": "")
			<< " }";
    return os;
	}

	std::map<std::filesystem::path, VirtualPath, ComparePathSegments> allowed_paths;
	std::string current_working_directory;

	std::vector<struct sockaddr_storage> allowed_connect_ipv4;
	std::vector<struct sockaddr_storage> allowed_listen_ipv4;
	std::vector<struct sockaddr_storage> allowed_connect_ipv6;
	std::vector<struct sockaddr_storage> allowed_listen_ipv6;

	static Configuration FromArgs(int argc, char* argv[]);
};
