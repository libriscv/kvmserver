#include "config.hpp"
#include <fstream>
#include <nlohmann/json.hpp>
#include <thread>

static std::string apply_dollar_vars(std::string str)
{
	// Replace $HOME with the home directory
	auto find_home = str.find("$HOME");
	if (find_home != std::string::npos) {
		const char* home = getenv("HOME");
		if (home != nullptr) {
			str.replace(find_home, 5, std::string(home));
		}
	}
	// Replace $PWD with the current working directory
	auto find_pwd = str.find("$PWD");
	if (find_pwd != std::string::npos) {
		char cwd[PATH_MAX];
		if (getcwd(cwd, sizeof(cwd)) != nullptr) {
			str.replace(find_pwd, 4, std::string(cwd));
		}
	}
	return str;
}

template <typename T>
void add_remappings(const nlohmann::json& json, std::vector<T>& remappings,
	bool allow_read, bool allow_write, bool allow_execute)
{
	for (const auto& remap : json) {
		tinykvm::VirtualRemapping remapping;
		// Physical is usually 0x0, which means allocate from guest heap
		remapping.phys = 0x0;
		if (remap.is_array()) {
			// Remapping is an array of "0xADDRESS" and size pairs
			// Eg. ["0x100000000": 64] indicating a 64mb remapping
			std::string address = remap.at(0).get<std::string>();
			if (address.find("0x") != std::string::npos) {
				remapping.virt = std::stoull(address, nullptr, 16);
			} else {
				remapping.virt = std::stoull(address);
			}
			// The size is the second element in the array
			remapping.size = remap.at(1).get<uint64_t>() * (1UL << 20); // Convert MB to bytes
			// Set the permissions
			remapping.writable = allow_write;
			remapping.executable = allow_execute;
			remappings.push_back(remapping);
		}
		else if (remap.is_object())
		{
			// Remapping is an object with "virtual", "size", "executable", "writable" etc.
			// There are always virtual and size fields
			remapping.virt = remap.at("virtual").get<uint64_t>();
			remapping.size = remap.at("size").get<uint64_t>() * (1UL << 20); // Convert MB to bytes
			if (remap.contains("physical")) {
				// This should be *very* rare
				remapping.phys = remap["physical"].get<uint64_t>();
			}
			// In this case we get the permissions explicitly from the JSON
			remapping.executable = remap.value("executable", false);
			remapping.writable = remap.value("writable", false);
			remappings.push_back(remapping);
		}
		else {
			// Print the whole object for debugging
			fprintf(stderr, "Invalid remapping format in configuration:\n");
			fprintf(stderr, "%s\n", remap.dump(4).c_str());
			throw std::runtime_error("Invalid remapping format in configuration file");
		}
	}
}

Configuration Configuration::FromJsonFile(const std::string& filename)
{
	Configuration config;
	// Load the JSON file and parse it
	std::ifstream file(filename);
	if (!file.is_open()) {
		throw std::runtime_error("Could not open configuration file: " + filename);
	}

	nlohmann::json json;
	// Allow comments in the JSON file
	try {
		json = json.parse(file, nullptr, false, true);
	} catch (const nlohmann::json::parse_error& e) {
		fprintf(stderr, "Error parsing JSON file: %s\n", filename.c_str());
		fprintf(stderr, "Error: %s\n", e.what());
		throw std::runtime_error("Invalid JSON format in configuration file: " + filename);
	}

	// Parse the JSON data into the Configuration object
	try {
		config.concurrency = json.value("concurrency", config.concurrency);
		if (config.concurrency == 0) {
			config.concurrency = std::thread::hardware_concurrency();
		}
		// The filename is required
		if (!json.contains("filename")) {
			fprintf(stderr, "Missing required field 'filename' in configuration file: %s\n", filename.c_str());
			throw std::runtime_error("Missing required field 'filename' in configuration file: " + filename);
		}
		config.filename = json["filename"].get<std::string>();
		config.filename = apply_dollar_vars(config.filename);

		/* Most of these fields are optional. */
		config.max_boot_time = json.value("max_boot_time", config.max_boot_time);
		config.max_req_time = json.value("max_req_time", config.max_req_time);

		config.max_main_memory = json.value("max_memory", config.max_main_memory);
		// The address space must at least be as large as the main memory
		config.max_address_space = json.value("address_space", config.max_address_space);
		config.max_address_space = std::max(config.max_address_space, config.max_main_memory);

		if (json.contains("max_request_memory")) {
			config.max_req_mem = json["max_request_memory"].get<uint32_t>();
		}
		if (json.contains("limit_req_mem")) {
			config.limit_req_mem = json["limit_req_mem"].get<uint32_t>();
		}
		if (json.contains("shared_memory")) {
			config.shared_memory = json["shared_memory"].get<uint32_t>();
		}
		config.dylink_address_hint = json.value("dylink_address_hint", config.dylink_address_hint);
		config.heap_address_hint = json.value("heap_address_hint", config.heap_address_hint);
		config.hugepage_arena_size = json.value("hugepage_arena_size", config.hugepage_arena_size);
		config.hugepage_requests_arena = json.value("hugepage_requests_arena", config.hugepage_requests_arena);
		config.executable_heap = json.value("executable_heap", config.executable_heap);
		config.clock_gettime_uses_rdtsc = json.value("clock_gettime_uses_rdtsc", config.clock_gettime_uses_rdtsc);
		config.hugepages = json.value("hugepages", config.hugepages);
		config.split_hugepages = json.value("split_hugepages", config.split_hugepages);
		config.transparent_hugepages = json.value("transparent_hugepages", config.transparent_hugepages);
		config.relocate_fixed_mmap = json.value("relocate_fixed_mmap", config.relocate_fixed_mmap);
		config.ephemeral = json.value("ephemeral", config.ephemeral);
		config.ephemeral_keep_working_memory = json.value("ephemeral_keep_working_memory", config.ephemeral_keep_working_memory);
		config.verbose = json.value("verbose", config.verbose);
		config.verbose_syscalls = json.value("verbose_syscalls", config.verbose_syscalls);
		config.verbose_pagetable = json.value("verbose_pagetable", config.verbose_pagetable);

		if (json.contains("environment")) {
			for (const auto& env : json["environment"]) {
				std::string env_str = env.get<std::string>();
				env_str = apply_dollar_vars(env_str);
				config.environ.push_back(std::move(env_str));
			}
		}

		if (json.contains("main_arguments")) {
			for (const auto& arg : json["main_arguments"]) {
				std::string arg_str = arg.get<std::string>();
				arg_str = apply_dollar_vars(arg_str);
				config.main_arguments.push_back(std::move(arg_str));
			}
		}

		if (json.contains("remappings")) {
			add_remappings(json["remappings"], config.vmem_remappings,
				true, true, false); // +R, +W, -X
		}
		if (json.contains("executable_remappings")) {
			add_remappings(json["executable_remappings"], config.vmem_remappings,
				true, true, true); // +R, +W, +X
		}

		if (json.contains("allowed_paths")) {
			for (const auto& path : json["allowed_paths"]) {
				VirtualPath vpath;
				if (path.is_string()) {
					// If the path is a string, it is a real path
					vpath.real_path = path.get<std::string>();
					vpath.real_path = apply_dollar_vars(vpath.real_path);
					vpath.virtual_path = vpath.real_path;
					config.allowed_paths.push_back(vpath);
					continue;
				}
				if (!path.contains("real")) {
					fprintf(stderr, "Missing required field 'real' in allowed_paths in configuration file: %s\n", filename.c_str());
					throw std::runtime_error("Missing required field 'real' in allowed_paths in configuration file: " + filename);
				}
				if (!path.at("real").is_string()) {
					fprintf(stderr, "Invalid type for 'real' in allowed_paths in configuration file: %s\n", filename.c_str());
					throw std::runtime_error("Invalid type for 'real' in allowed_paths in configuration file: " + filename);
				}
				vpath.real_path = path["real"].get<std::string>();
				vpath.real_path = apply_dollar_vars(vpath.real_path);
				if (path.contains("virtual")) {
					vpath.virtual_path = path["virtual"].get<std::string>();
					// Record the index of the virtual path in the allowed paths
					// that contains a specific virtual path.
					config.rewrite_path_indices.insert_or_assign(
						vpath.virtual_path, config.allowed_paths.size());
				} else {
					vpath.virtual_path = vpath.real_path;
				}
				vpath.virtual_path = path.value("virtual_path", vpath.real_path);
				vpath.writable = path.value("writable", false);
				vpath.symlink = path.value("symlink", false);
				vpath.usable_in_fork = path.value("usable_in_fork", false);
				vpath.prefix = path.value("prefix", false);
				config.allowed_paths.push_back(vpath);
			}
		}

		// Raise the memory sizes into megabytes
		config.max_address_space = config.max_address_space * (1ULL << 20);
		config.max_main_memory = config.max_main_memory * (1ULL << 20);
		config.max_req_mem = config.max_req_mem * (1UL << 20);
		config.limit_req_mem = config.limit_req_mem * (1UL << 20);
		config.shared_memory = config.shared_memory * (1UL << 20);
		config.dylink_address_hint = config.dylink_address_hint * (1UL << 20);
		config.heap_address_hint = config.heap_address_hint * (1UL << 20);
		// As a catch-all we will make everything verbose when VERBOSE=1
		if (getenv("VERBOSE") != nullptr) {
			config.verbose = true;
			config.verbose_syscalls = true;
		}
		return config;

	} catch (const nlohmann::json::exception& e) {
		fprintf(stderr, "Error parsing JSON file: %s\n", filename.c_str());
		fprintf(stderr, "Error: %s\n", e.what());
		throw std::runtime_error("Invalid JSON format in configuration file: " + filename);
	}
}
