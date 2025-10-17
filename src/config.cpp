#include "config.hpp"
#include <CLI/CLI.hpp>
#include <filesystem>
#include <fstream>
#include <limits.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <linux/un.h>
#include <thread>
#include <unistd.h>
extern char **environ;

static std::vector<std::string> split(const std::string &s, char seperator)
{
	std::vector<std::string> output;
	std::string::size_type prev_pos = 0, pos = 0;

	while ((pos = s.find(seperator, pos)) != std::string::npos)
	{
		std::string substring(s.substr(prev_pos, pos - prev_pos));
		output.push_back(substring);
		prev_pos = ++pos;
	}
	output.push_back(s.substr(prev_pos, pos - prev_pos)); // Last word
	return output;
}

template <typename T>
void add_remapping(const std::string& remap, std::vector<T>& remappings)
{
		tinykvm::VirtualRemapping& remapping = remappings.emplace_back((tinykvm::VirtualRemapping) {});
		auto parts = split(remap, ':');
		auto it = parts.begin();
		if (it == parts.end()) {
			throw CLI::ValidationError("too few parts", remap);
		}
		std::string item((*it).begin(), (*it).end());
		try {
			remapping.virt = std::stoull(item, nullptr, 0);
		} catch (const std::invalid_argument& e) {
			throw CLI::ValidationError("invalid argument (virt)", remap);
		} catch (const std::out_of_range& e) {
			throw CLI::ValidationError("out of range (virt)", remap);
		}
		++it;
		if (it == parts.end()) {
			throw CLI::ValidationError("too few parts", remap);
		}
		item = std::string((*it).begin(), (*it).end());
		try {
			remapping.size = std::stoull(item, nullptr, 0) * (1UL << 20); // Convert MB to bytes
		} catch (const std::invalid_argument& e) {
			throw CLI::ValidationError("invalid argument (size)", remap);
		} catch (const std::out_of_range& e) {
			throw CLI::ValidationError("out of range (size)", remap);
		}
		++it;
		if (it == parts.end()) {
			remapping.writable = true;
			return;
		}
		item = std::string((*it).begin(), (*it).end());
		if (item.find_first_not_of("0123456789") != 0) {
			// Physical is usually the default 0x0, which means allocate from guest heap
			try {
				remapping.phys = std::stoull(item, nullptr, 0);
			} catch (const std::invalid_argument& e) {
				throw CLI::ValidationError("invalid argument (phys)", remap);
			} catch (const std::out_of_range& e) {
				throw CLI::ValidationError("out of range (phys)", remap);
			}
			++it;
			if (it == parts.end()) {
				remapping.writable = true;
				return;
			}
			item = std::string((*it).begin(), (*it).end());
		}
		size_t i = 0;
		if (item.length() > i && item[i] == 'r') {
			// ignore;
			i++;
		}
		if (item.length() > i && item[i] == 'w') {
			remapping.writable = true;
			i++;
		}
		if (item.length() > i && item[i] == 'x') {
			remapping.executable = true;
			i++;
		}
		if (i != item.length()) {
			throw CLI::ValidationError("invalid argument (rwx)", remap);
		}
		++it;
		if (it != parts.end()) {
			throw CLI::ValidationError("too many parts", remap);
		}
}


std::string lookup_program(const std::string& program)
{
	namespace fs = std::filesystem;
	if (program.find('/') == std::string::npos) {
		std::stringstream ss(getenv("PATH"));
		std::string dirname;
		while (std::getline(ss, dirname, ':')) {
			fs::path filepath = (fs::path(dirname) / program).lexically_normal();
			if (access(filepath.c_str(), X_OK) == 0) {
				return filepath;
			}
		}
		throw CLI::ValidationError("program: Not found on path", program);
	}
	fs::path filepath = fs::absolute(program).lexically_normal();
	if (access(filepath.c_str(), X_OK) == 0) {
		return filepath;
	}
	throw CLI::ValidationError("program: Not an executable", program);
}

static bool parse_addresses(
	const std::vector<std::string>& config,
	std::vector<struct sockaddr_storage>& allowed_ipv4,
	std::vector<struct sockaddr_storage>& allowed_ipv6,
	const bool verbose
) {
	for (const auto& value : config) {
		if (value.empty() || value == "false") {
			continue;
		}
		uint port = 0;
		std::string address(value);
		if (value == "true") {
			address = "";
		}
		size_t maybe_colon = address.find_last_not_of("0123456789");
		if (maybe_colon != std::string::npos && value[maybe_colon] == ':') {
			uint parsed_port;
			try {
				port = std::stoul(address.substr(maybe_colon + 1, std::string::npos));
			} catch (...) {
				throw CLI::ValidationError("Invalid port", value);
			}
			address = address.substr(0, maybe_colon);
		}

		if (port > std::numeric_limits<in_port_t>::max()) {
			throw CLI::ValidationError("Invalid port", value);
		}

		if (address == "") {
			if (port == 0) {
				allowed_ipv4.clear();
				allowed_ipv6.clear();
			}
			auto& storage = allowed_ipv4.emplace_back((struct sockaddr_storage) {});
			storage.ss_family = AF_INET;
			reinterpret_cast<sockaddr_in*>(&storage)->sin_port = htons(port);
			storage = allowed_ipv6.emplace_back((struct sockaddr_storage) {});
			storage.ss_family = AF_INET6;
			reinterpret_cast<sockaddr_in6*>(&storage)->sin6_port = htons(port);
			if (port == 0) {
				return true;
			};
			continue;
		}

		// IPv6
		if (address.front() == '[') {
			if (address.back() != ']') {
				throw CLI::ValidationError("Invalid ipv6 address", value);
			}
			std::string new_address(address.substr(1, value.length() - 2));
			auto& storage = allowed_ipv6.emplace_back((struct sockaddr_storage) {});
			sockaddr_in6* addr = reinterpret_cast<sockaddr_in6*>(&storage);
			addr->sin6_family = AF_INET6;
			if (inet_pton(AF_INET6, new_address.c_str(), &addr->sin6_addr) <= 0) {
				throw CLI::ValidationError("Invalid IPv6 address", value);
			}
			addr->sin6_port = htons(port);
			continue;
		}

		// IPv4
		in_addr sin_addr;
		if (inet_pton(AF_INET, address.c_str(), &sin_addr) > 0) {
			auto& storage = allowed_ipv4.emplace_back((struct sockaddr_storage) {});
			sockaddr_in* addr = reinterpret_cast<sockaddr_in*>(&storage);
			addr->sin_family = AF_INET;
			addr->sin_addr = sin_addr;
			addr->sin_port = htons(port);
			continue;
		}

		// Resolve the domain name to an IP address
		struct addrinfo hints = {};
		struct addrinfo* head;
		hints.ai_family = AF_UNSPEC; // IPv4 or IPv6
		hints.ai_socktype = SOCK_STREAM; // TCP
		if (getaddrinfo(address.c_str(), nullptr, &hints, &head) != 0) {
			throw CLI::ValidationError("Invalid domain name", value);
		}
		for (struct addrinfo* res = head; res != nullptr; res = res->ai_next) {
			if (res->ai_family == AF_INET) {
				auto& storage = allowed_ipv4.emplace_back((struct sockaddr_storage) {});
				sockaddr_in* addr = reinterpret_cast<sockaddr_in*>(&storage);
				addr->sin_family = AF_INET;
				addr->sin_addr = reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr;
				addr->sin_port = htons(port);
				if (verbose) {
					std::string found;
					found.reserve(64);
					inet_ntop(AF_INET, reinterpret_cast<void*>(&addr->sin_addr), found.data(), found.capacity());
					printf("Resolved %s to %s\n", address.c_str(), found.c_str());
				}
			} else if (res->ai_family == AF_INET6) {
				auto& storage = allowed_ipv6.emplace_back((struct sockaddr_storage) {});
				sockaddr_in6* addr = reinterpret_cast<sockaddr_in6*>(&storage);
				addr->sin6_family = AF_INET6;
				addr->sin6_addr = reinterpret_cast<sockaddr_in6*>(res->ai_addr)->sin6_addr;
				addr->sin6_port = htons(port);
				if (verbose) {
					std::string found;
					found.reserve(64);
					inet_ntop(AF_INET6, reinterpret_cast<void*>(&addr->sin6_addr), found.data(), found.capacity());
					printf("Resolved %s to %s\n", address.c_str(), found.c_str());
				}
			} else {
				throw CLI::ValidationError("Invalid address family for domain", value);
			}
		}
		freeaddrinfo(head);
	}
	return false;
}

static void ensure_path(
	std::filesystem::path src,
	std::filesystem::path dst,
	std::map<std::filesystem::path, Configuration::VirtualPath, Configuration::ComparePathSegments>& allowed_paths,
	bool readable, bool writable, bool symlink
) {
	if (src.is_relative()) {
		src = std::filesystem::current_path() / src;
	}
	src = (src / "").lexically_normal().parent_path();
	if (dst.is_relative()) {
		dst = std::filesystem::current_path() / dst;
	}
	dst = (dst / "").lexically_normal().parent_path();

	auto it = allowed_paths.find(src);
	if (it == allowed_paths.end()) {
		allowed_paths.emplace(src, Configuration::VirtualPath {
			.real_path = dst,
			.virtual_path = src,
			.readable = readable,
			.writable = writable,
			.symlink = symlink,
		});
		return;
	}
	Configuration::VirtualPath& vpath = it->second;
	vpath.real_path = dst;
	if (readable) {
		vpath.readable = true;
	}
	if (writable) {
		vpath.writable = true;
	}
	if (symlink) {
		vpath.symlink = true;
	}
}

static void fake_path(
	std::filesystem::path path,
	std::string_view content,
	std::map<std::filesystem::path, Configuration::VirtualPath, Configuration::ComparePathSegments>& allowed_paths
) {
	// Create a fake tempfile for /proc/self/maps
	std::filesystem::path dst = std::tmpnam(nullptr);
	FILE *f = fopen(dst.c_str(), "w");
	if (f == nullptr) {
		throw CLI::ValidationError("fopen: Unable to create temporary file", "");
	}
	fwrite(content.data(), 1, content.size(), f);
	fclose(f);
	ensure_path(path, dst, allowed_paths, true, false, false);
}

Configuration Configuration::FromArgs(int argc, char* argv[])
{
	Configuration config;
	std::vector<std::string> allow_read;
	std::vector<std::string> allow_write;
	std::vector<std::string> volume;
	std::vector<std::string> allow_env;
	std::vector<std::string> allow_net;
	std::vector<std::string> allow_connect;
	std::vector<std::string> allow_listen;

	CLI::App app{"kvmserver"};
	app.set_config("-c,--config", "kvmserver.toml", "Read a toml file");
	app.set_help_all_flag("--help-all", "Expand all help");

	app.add_option("--cwd", config.current_working_directory, "Set the guests working directory")
		->default_val(std::filesystem::current_path());
	// TODO: This does not allow env=[] in config file.
	app.add_option("--env", config.environ, "add an environment variable")->allow_extra_args(false);

	app.add_option("-t,--threads", config.concurrency, "Number of request VMs (0 to use cpu count)")->capture_default_str();
	app.add_flag("-e,--ephemeral", config.ephemeral, "Use ephemeral VMs");
	app.add_option("-w,--warmup", config.warmup_connect_requests, "Number of warmup requests")->capture_default_str();
	app.add_option("--snapshot-file", config.snapshot_filename, "Snapshot filename");

	app.add_flag("-v,--verbose", config.verbose, "Enable verbose output")->group("Verbose");
	app.add_flag("--verbose-syscalls", config.verbose_syscalls, "Enable verbose syscall output")->group("Verbose");
	app.add_flag("--verbose-mmap-syscalls", config.verbose_mmap_syscalls, "Enable verbose mmap syscall output")->group("Verbose");
	app.add_flag("--verbose-thread-syscalls", config.verbose_thread_syscalls, "Enable verbose thread syscall output")->group("Verbose");
	app.add_flag("--verbose-pagetables", config.verbose_pagetable, "Enable verbose pagetable output")->group("Verbose");

	app.add_flag("--allow-all", [&](bool allow_all) {
		if (allow_all) {
			allow_read.emplace_back("/");
			allow_write.emplace_back("/");
			allow_env.emplace_back("*");
			allow_net.emplace_back("true");
		}
	}, "Allow all access")->group("Permissions");
	app.add_flag("--allow-read{/}", allow_read, "Allow filesystem read access")->delimiter(',')->excludes("--allow-all")->group("Permissions");
	app.add_flag("--allow-write{/}", allow_write, "Allow filesystem write access")->delimiter(',')->excludes("--allow-all")->group("Permissions");
	app.add_flag("--allow-env{*}", allow_env, "Allow access to environment variables. Optionally specify accessible environment variables (e.g. --allow-env=USER,PATH,API_*).")->delimiter(',')->excludes("--allow-all")->group("Permissions");
	app.add_flag("--allow-net", allow_net, "Allow network access")->delimiter(',')->excludes("--allow-all")->group("Permissions");
	app.add_flag("--allow-connect", allow_connect, "Allow outgoing network access")->delimiter(',')->excludes("--allow-all")->group("Permissions");
	app.add_flag("--allow-listen", allow_listen, "Allow incoming network access")->delimiter(',')->excludes("--allow-all")->group("Permissions");
	app.add_flag("--volume", volume, "<host-path>:<guest-path>[:r?w?=r]")->delimiter(',')->excludes("--allow-all")->group("Permissions");

	app.add_option("--max-boot-time", config.max_boot_time)->capture_default_str()->group("Advanced");
	app.add_option("--max-request-time", config.max_req_time)->capture_default_str()->group("Advanced");
	app.add_option("--max-main-memory", config.max_main_memory)->capture_default_str()->group("Advanced");
	app.add_option("--max-address-space", config.max_address_space)->capture_default_str()->group("Advanced");
	app.add_option("--max-request-memory", config.max_req_mem)->capture_default_str()->group("Advanced");
	app.add_option("--limit-request-memory", config.limit_req_mem)->capture_default_str()->group("Advanced");
	app.add_option("--shared-memory", config.shared_memory)->capture_default_str()->group("Advanced");
	app.add_option("--heap-address-hint", config.heap_address_hint)->capture_default_str()->group("Advanced");
	app.add_option("--hugepage-arena-size", config.hugepage_arena_size)->capture_default_str()->group("Advanced");
	app.add_option("--hugepage-requests-arena", config.hugepage_requests_arena)->capture_default_str()->group("Advanced");
	app.add_flag("!--no-executable-heap", config.executable_heap)->capture_default_str()->group("Advanced");
	app.add_flag("!--no-mmap-backed-files", config.mmap_backed_files)->group("Advanced");
	app.add_flag("--hugepages", config.hugepages)->group("Advanced");
	app.add_flag("!--no-split-hugepages", config.split_hugepages)->group("Advanced");
	app.add_flag("--transparent-hugepages", config.transparent_hugepages)->group("Advanced");
	app.add_flag("!--no-ephemeral-keep-working-memory", config.ephemeral_keep_working_memory)->group("Advanced");

	// This allows ++ to be used as an escape from subcommand positionals.
	app.add_subcommand("++", "")->silent()->group("")->fallthrough();

	// Main VM
	auto &run = *app.add_subcommand("run", "Main VM");
	run.configurable();
	run.positionals_at_end();
	run.validate_positionals();
	run.add_option("program", config.main_filename, "Program")->required();
	run.add_option("args", config.main_arguments, "Program arguments")->check(!CLI::IsMember({"++"}));
	run.add_option("--dylink-address-hint", config.dylink_address_hint)->capture_default_str()->group("Advanced");
	run.add_option("--remapping", "virt:size(mb)[:phys=0][:r?w?x?=rw]")
		->group("Advanced")
		->delimiter(',')
		->expected(CLI::detail::expected_max_vector_size)
		->each([&](const std::string& remap) {
			add_remapping(remap, config.vmem_remappings);
		});
	run.callback([&]() {
		if (run.count() > 1) {
			throw CLI::ValidationError("run subcommand may only be called once");
		}
		config.main_filename = lookup_program(config.main_filename);
	});

	// Storage VM
	auto &storage = *app.add_subcommand("storage", "Storage VM");
	storage.needs(&run);
	storage.configurable();
	storage.positionals_at_end();
	storage.validate_positionals();
	storage.add_option("program", config.storage_filename, "Storage program")->required();
	storage.add_option("args", config.storage_arguments, "Storage arguments")->check(!CLI::IsMember({"++"}));
	storage.add_flag("--1-to-1", config.storage_1_to_1, "Each request VM gets its own storage VM");
	storage.add_flag("--ipre-permanent", config.storage_ipre_permanent, "Storage VM uses permanent IPRE resume images")->group("Advanced");
	storage.add_option("--dylink-address-hint", config.storage_dylink_address_hint)->capture_default_str()->group("Advanced");
	storage.add_option("--remapping", "virt:size(mb)[:phys=0][:r?w?x?=rw]")
		->group("Advanced")
		->delimiter(',')
		->expected(CLI::detail::expected_max_vector_size)
		->each([&](const std::string& remap) {
			add_remapping(remap, config.storage_remappings);
		});
	storage.final_callback([&]() {
		if (storage.count() > 1) {
			throw CLI::ValidationError("storage subcommand may only be used once");
		}
		config.storage = true;
		config.storage_filename = lookup_program(config.storage_filename);
	});

	CLI::Option* print_config = app.add_flag("--print-config", "Print config and exit without running program")->configurable(false);

	app.callback([&]() {
		if (app.get_subcommands([&](const CLI::App* sub) {
			return sub->get_name() != "++" && sub->count() > 0;
		}).size() == 0) {
			throw CLI::ValidationError("A subcommand is required");
		}
		if (config.concurrency == 0) {
			config.concurrency = std::thread::hardware_concurrency();
		}
		for (auto& path : allow_read) {
			ensure_path(path, path, config.allowed_paths, true, false, false);
		}
		for (auto& path : allow_write) {
			ensure_path(path, path, config.allowed_paths, false, true, false);
		}
		// Always allow these (harmless) paths
		ensure_path("/dev/urandom", "/dev/urandom", config.allowed_paths, true, false, true);
		ensure_path("/dev/null", "/dev/null", config.allowed_paths, true, true, true);
		ensure_path("/dev/zero", "/dev/zero", config.allowed_paths, true, true, true);

		// Create a fake tempfile for /proc/self/maps
		fake_path("/proc/self/maps",
			"000000000000-ffffffffffff r--p 00000000 103:02 48895346                  " + config.main_filename + "\n",
			config.allowed_paths);

		// Create a fake tempfile for /lib/libkvmserverguest.so
		extern const char _binary_libkvmserverguest_so_start, _binary_libkvmserverguest_so_end;
		std::string_view libkvmserverguest_so(
			&_binary_libkvmserverguest_so_start,
			&_binary_libkvmserverguest_so_end - &_binary_libkvmserverguest_so_start);
		fake_path("/lib/libkvmserverguest.so", libkvmserverguest_so, config.allowed_paths);

		for (const std::string& triple : volume) {
			auto parts = split(triple, ':');
			auto it = parts.begin();
			if (it == parts.end()) {
				throw CLI::ValidationError("too few parts", triple);
			}
			std::string src((*it).begin(), (*it).end());
			++it;
			if (it == parts.end()) {
				throw CLI::ValidationError("too few parts", triple);
			}
			std::string dst((*it).begin(), (*it).end());
			++it;
			if (it == parts.end()) {
				ensure_path(src, dst, config.allowed_paths, true, false, false);
			} else {
				bool r = false;
				bool w = false;
				std::string perms((*it).begin(), (*it).end());
				size_t i = 0;
				if (perms.length() > i && perms[i] == 'r') {
					r = true;
					i++;
				}
				if (perms.length() > i && perms[i] == 'w') {
					w = true;
					i++;
				}
				if (i != perms.length()) {
					throw CLI::ValidationError("invalid argument (rw)", perms);
				}
				++it;
				if (it != parts.end()) {
					throw CLI::ValidationError("too many parts", triple);
				}
				ensure_path(src, dst, config.allowed_paths, r, w, false);
			}
		}
		// Rewrite the path to the real path of the executable
		// TODO: reverse map real to virtual.
		ensure_path("/proc/self/exe", config.main_filename, config.allowed_paths, false, false, true);
		ensure_path(config.main_filename, config.main_filename, config.allowed_paths, true, false, false);
		if (config.verbose) {
			std::cerr<<"TinyKVM: allowed_paths = {\n";
			for (auto& [k, v] : config.allowed_paths) {
				std::cout<<"  "<<k<<": "<<v<<",\n";
			}
			std::cout<<"}\n";
		}

		for (const auto& name : allow_env) {
			// XXX ensure name has no = using validator
			if (name.back() == '*') {
				for (char** env = ::environ; *env != nullptr; ++env) {
					if (strncmp(*env, name.data(), name.size() - 1) == 0) {
						config.environ.push_back(*env);
					}
				}
			} else {
				std::string namestring(name.begin(), name.end());
				config.environ.push_back(namestring + "=" + getenv(namestring.c_str()));
			}
		}
		// Do we need "LC_TYPE=C", "LC_ALL=C"?
		if (
			std::find_if(config.environ.begin(), config.environ.end(),
				[](auto& value) { return value.starts_with("USER="); }
			) == config.environ.end()
		) {
			config.environ.emplace_back("USER=nobody");
		}

		bool skip_allow_connect_listen = parse_addresses(
			allow_net,
			config.allowed_connect_ipv4,
			config.allowed_connect_ipv6,
			config.verbose
		);
		config.allowed_listen_ipv4 = config.allowed_connect_ipv4;
		config.allowed_listen_ipv6 = config.allowed_connect_ipv6;
		if (!skip_allow_connect_listen) {
			parse_addresses(
				allow_connect,
				config.allowed_connect_ipv4,
				config.allowed_connect_ipv6,
				config.verbose
			);
			parse_addresses(
				allow_listen,
				config.allowed_listen_ipv4,
				config.allowed_listen_ipv6,
				config.verbose
			);
		}

		// The address space must at least be as large as the main memory
		config.max_address_space = std::max(config.max_address_space, config.max_main_memory);

		// Raise the memory sizes into megabytes
		config.max_address_space = config.max_address_space * (1ULL << 20);
		config.max_main_memory = config.max_main_memory * (1ULL << 20);
		config.max_req_mem = config.max_req_mem * (1UL << 20);
		config.limit_req_mem = config.limit_req_mem * (1UL << 20);
		config.shared_memory = config.shared_memory * (1UL << 20);
		config.dylink_address_hint = config.dylink_address_hint * (1UL << 20);
		config.heap_address_hint = config.heap_address_hint * (1UL << 20);
	});

	try {
		app.parse(argc, argv);
	} catch (const CLI::ParseError &e) {
    std::exit(app.exit(e));
	}

	if (*print_config) {
		std::cout<<app.config_to_str(false, true);
		std::exit(0);
	}

	return config;
}
