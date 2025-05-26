#pragma once
#include <string>
#include <sys/socket.h> // for sockaddr_storage
#include <tinykvm/common.hpp>
#include <unordered_map>
#include <unordered_set>
#include <vector>

struct Configuration
{
	std::string filename;
	uint16_t concurrency = 1; /* Request VMs */
	uint16_t warmup_connect_requests = 0; /* Warmup requests, individual connections */
	uint16_t warmup_intra_connect_requests = 100; /* Send N requests while connected */
	std::string warmup_path = "/"; /* Path to send requests to */

	float    max_boot_time = 20.0f; /* Seconds */
	float    max_req_time  = 8.0f; /* Seconds */
	// TODO: tinykvm option for unlimited by default
	uint64_t max_address_space = 128 * 1024; /* Megabytes */
	uint64_t max_main_memory = 8 * 1024; /* Megabytes */
	uint32_t max_req_mem   = 128; /* Megabytes of memory for request VMs */
	uint32_t limit_req_mem = 128; /* Megabytes to keep after request */
	uint32_t shared_memory = 0; /* Megabytes */
	uint32_t dylink_address_hint = 2; /* Image base address hint */
	uint32_t heap_address_hint = 256; /* Address hint for the heap */
	uint64_t hugepage_arena_size = 0; /* Megabytes */
	uint64_t hugepage_requests_arena = 0; /* Megabytes */
	bool     executable_heap = true;
	bool     clock_gettime_uses_rdtsc = false;
	bool     hugepages    = false;
	bool     split_hugepages = true;
	bool     transparent_hugepages = false;
	bool     relocate_fixed_mmap = true;
	bool     ephemeral = false;
	bool     ephemeral_keep_working_memory = true;
	bool     verbose = false;
	bool     verbose_syscalls = false;
	bool     verbose_pagetable = false;

	std::vector<std::string> environ;
	std::vector<std::string> main_arguments;

	std::vector<tinykvm::VirtualRemapping> vmem_remappings;

	struct VirtualPath {
		std::string real_path;
		std::string virtual_path; /* Path inside the VM, optional */
		bool writable = false;
		bool symlink = false; /* Treated as a symlink path, to be resolved */
		bool usable_in_fork = false;
		bool prefix = false;
	};
	std::vector<VirtualPath> allowed_paths;
	std::unordered_map<std::string, size_t> rewrite_path_indices;
	std::string current_working_directory = "/";

	struct NetworkPath {
		struct sockaddr_storage sockaddr;
		bool is_listenable = false;
	};
	std::vector<NetworkPath> allowed_network_ipv4;
	std::vector<NetworkPath> allowed_network_ipv6;
	bool network_allow_connect = false; /* Allow all outgoing network connections */
	bool network_allow_listen = false; /* Allow all incoming network connections */

	static Configuration FromJsonFile(const std::string& filename);
};
