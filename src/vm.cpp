#include "vm.hpp"

#include "settings.hpp"
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <filesystem>
#include <netinet/in.h>
#include <numeric>
#include <optional>
#include <stdexcept>
#include <sys/poll.h>
#include <sys/signal.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <tinykvm/linux/threads.hpp>
extern std::vector<uint8_t> file_loader(const std::string& filename);
static std::vector<uint8_t> ld_linux_x86_64_so;

static bool is_interpreted_binary(std::string_view binary)
{
	if (binary.size() < 128U)
		throw std::runtime_error("Invalid ELF program (binary too small)");

	const tinykvm::DynamicElf dyn_elf = tinykvm::is_dynamic_elf(binary);
	return dyn_elf.has_interpreter();
}
static uint64_t detect_gigapage_from(std::string_view binary, uint64_t dylink_address_hint)
{
	if (dylink_address_hint >= (1ULL << 30U)) {
		const tinykvm::DynamicElf dyn_elf = tinykvm::is_dynamic_elf(binary);
		// We can only use a dylink address hint if the binary is dynamic
		if (dyn_elf.is_dynamic)
			return (dylink_address_hint >> 30U) << 30U; // Aligned to gigapage
	}

	if (binary.size() < 128U)
		throw std::runtime_error("Invalid ELF program (binary too small)");
	auto* elf = (Elf64_Ehdr *)binary.data();

	auto start_address_gigapage = elf->e_entry >> 30U;
	if (start_address_gigapage >= 512)
		throw std::runtime_error("Invalid ELF start address (address was > 512GiB)");

	return start_address_gigapage << 30U;
}
static const std::string_view select_main_binary(std::string_view program_binary)
{
	const tinykvm::DynamicElf dyn_elf = tinykvm::is_dynamic_elf(program_binary);
	if (dyn_elf.has_interpreter()) {
		// Add the dynamic linker as first argument
		return std::string_view((const char*)ld_linux_x86_64_so.data(),
			ld_linux_x86_64_so.size());
	}
	return program_binary;
}
static uint64_t dylink_address(const Configuration& config, bool storage)
{
	if (storage) {
		return config.storage_dylink_address_hint;
	}
	return config.dylink_address_hint;
}

static bool lookup_allowed_path(
	std::string& pathinout, const std::string& cwd,
	const std::map<std::filesystem::path, Configuration::VirtualPath, Configuration::ComparePathSegments>& allowed_paths,
	std::function<bool(const Configuration::VirtualPath&)> extract
) {
	std::filesystem::path path(pathinout);
	if (path.is_relative()) {
		path = std::filesystem::path(cwd) / path;
	}
	path = (path / "").lexically_normal().parent_path();
	// Find first key strictly greater than path, e.g.
	// { /foo: true, /foo/bar: true, /qux: true }.upper_bound(/foo/baz) -> /qux
	auto it = allowed_paths.upper_bound(path);
	size_t failsafe = allowed_paths.size();
	while (it != allowed_paths.begin()) {
		--it; // Previous key is either the path or shares a common prefix, e.g. /foo/bar.
		auto [first_it, path_it] = std::mismatch(it->first.begin(), it->first.end(), path.begin(), path.end());
		if (first_it == it->first.end()) {
			if (extract(it->second)) {
				// If that key is itself a prefix return the real_path plus the remainder of path
				pathinout = std::accumulate(path_it, path.end(), it->second.real_path, std::divides{});
				return true;
			}
			--path_it;
		}
		// otherwise lookup the common prefix
		it = allowed_paths.upper_bound(std::accumulate(path.begin(), path_it, std::filesystem::path("/"), std::divides{}));
		if (--failsafe == 0) {
			if (getenv("VERBOSE") != nullptr)
				fprintf(stderr, "lookup_allowed_path: failsafe triggered for path %s\n", pathinout.c_str());
			break;
		}
	}
	return false; // no prefix found
}

static bool validate_network_access(
	const struct sockaddr_storage& addr,
	const std::vector<struct sockaddr_storage>& allowed_ipv4,
	const std::vector<struct sockaddr_storage>& allowed_ipv6
) {
	// IPv4
	if (addr.ss_family == AF_INET)
	{
		// Compare the socket address with the allowed address
		const struct sockaddr_in* addr_ipv4 =
			reinterpret_cast<const struct sockaddr_in*>(&addr);
		for (auto& allowed : allowed_ipv4) {
			const struct sockaddr_in* addr_allowed =
				reinterpret_cast<const struct sockaddr_in*>(&allowed);
			if (addr_ipv4->sin_addr.s_addr == addr_allowed->sin_addr.s_addr ||
					addr_allowed->sin_addr.s_addr == 0) {
				// The socket address is allowed
				if (addr_ipv4->sin_port == addr_allowed->sin_port ||
					addr_allowed->sin_port == 0) {
					// The socket port is allowed
					return true;
				}
			} // in_addr
		}
		// No match found
		return false;
	}
	// IPv6 or unspecified (we are guessing IPv4-mapped IPv6)
	// XXX: is AF_UNSPEC a liability here? we should probably not allow
	//      it but some (e.g. bun uses it to mean IPv4-mapped IPv6)
	if (addr.ss_family == AF_INET6 || addr.ss_family == AF_UNSPEC)
	{
		const struct sockaddr_in6* addr_ipv6 =
			reinterpret_cast<const struct sockaddr_in6*>(&addr);
		for (auto& allowed : allowed_ipv6) {
			const struct sockaddr_in6* addr_allowed =
				reinterpret_cast<const struct sockaddr_in6*>(&allowed);
			if (memcmp(&addr_allowed->sin6_addr, &in6addr_any, sizeof(struct in6_addr)) == 0 ||
					memcmp(&addr_allowed->sin6_addr, &addr_ipv6->sin6_addr, sizeof(struct in6_addr)) == 0) {
				// The socket address is allowed
				if (addr_allowed->sin6_port == 0 ||
					addr_ipv6->sin6_port == addr_allowed->sin6_port) {
					// The socket port is allowed
					return true;
				}
			} // in6_addr
		}
		// No match found
		return false;
	}
	// Unknown address family
	fprintf(stderr, "Unknown address family: %d\n", addr.ss_family);
	return false;
}

VirtualMachine::VirtualMachine(std::string_view binary, const Configuration& config, bool storage)
	: m_machine(select_main_binary(binary), tinykvm::MachineOptions{
		.max_mem = config.max_address_space,
		.max_cow_mem = 0UL,
		.dylink_address_hint = dylink_address(config, storage),
		.heap_address_hint = storage ? 0 : config.heap_address_hint,
		.vmem_base_address = detect_gigapage_from(binary, dylink_address(config, storage)),
		.remappings {storage ? config.storage_remappings : config.vmem_remappings},
		.verbose_loader = config.verbose,
		.hugepages = config.hugepage_arena_size != 0,
		.master_direct_memory_writes = true,
		.split_hugepages = false,
		.executable_heap = config.executable_heap,
		.mmap_backed_files = config.mmap_backed_files && config.snapshot_filename.empty(),
		.snapshot_file = storage ? "" : config.snapshot_filename,
		.hugepages_arena_size = config.hugepage_arena_size,
	}),
	m_config(config),
	m_original_binary(binary),
	m_ephemeral(config.ephemeral),
	m_is_storage(storage)
{
	machine().set_userdata<VirtualMachine> (this);
	machine().install_unhandled_syscall_handler(
		[] (tinykvm::vCPU& cpu, unsigned syscall_number) {
			auto& vm = *cpu.machine().get_userdata<VirtualMachine>();
			switch (syscall_number) {
			case 67339: // sys_remote_resume
			case 0x10001:
				if (!vm.is_storage()) {
					// Remember buffer address and length values
					const uint64_t src = cpu.registers().rdi;
					const uint64_t len = cpu.registers().rsi;

					if (vm.config().storage_ipre_permanent)  {
						tinykvm::Machine& m = cpu.machine().remote();
						auto& regs = m.registers();
						m.copy_to_guest(regs.rdi, &src, sizeof(src));
						regs.rax = len;
						m.set_registers(regs);

						m.ipre_permanent_remote_resume_now();
						return;
					}

					vm.machine().ipre_remote_resume_now(false,
					[src, len] (tinykvm::Machine& m) {
						m.remote().copy_to_guest(m.registers().rdi, &src, sizeof(src));
						m.registers().rax = len;
					});
					return;
				}
				throw std::runtime_error("sys_remote_resume should *NOT* be called from storage VM");
			case 0x10002: // sys_wait_for_storage_task_paused
				if (vm.is_storage()) {
					vm.set_waiting_for_requests(true);
					cpu.stop();
					return;
				}
				throw std::runtime_error("sys_wait_for_storage_task_paused should *ONLY* be called from storage VM");
			}
			std::string info;
			if (vm.is_storage())
				info = " (storage)";
			else
				info = " (request " + std::to_string(vm.reqid()) + ")";
			fprintf(stderr, "Unhandled syscall %d in VM %s%s\n",
				syscall_number, vm.name().c_str(), info.c_str());
		});
	machine().set_verbose_system_calls(
		config.verbose_syscalls);
	machine().set_verbose_mmap_syscalls(
		config.verbose_syscalls);
	machine().set_verbose_thread_syscalls(
		config.verbose_syscalls);
	machine().fds().set_verbose(config.verbose);
	machine().fds().set_preempt_epoll_wait(true);
	// Set the current working directory
	machine().fds().set_current_working_directory(
		config.current_working_directory);
	machine().fds().set_open_writable_callback(
	[&] (std::string& path) -> bool {
		return lookup_allowed_path(path, machine().fds().current_working_directory(),
			config.allowed_paths, [](const Configuration::VirtualPath& vpath) { return vpath.writable; });
	});
	machine().fds().set_open_readable_callback(
	[&] (std::string& path) -> bool {
		return lookup_allowed_path(path, machine().fds().current_working_directory(),
			config.allowed_paths, [](const Configuration::VirtualPath& vpath) { return vpath.readable; });
	});
	machine().fds().connect_socket_callback =
	[this] (int fd, struct sockaddr_storage& addr) -> bool {
		(void)fd;

		// Validate unix socket path against allow-read and allow-write
		if (addr.ss_family == AF_UNIX)
		{
			// Compare the socket path with the allowed path
			const struct sockaddr_un *addr_unix =
				reinterpret_cast<const struct sockaddr_un *>(&addr);
			std::string sun_path = addr_unix->sun_path;
			// TODO: reverse the virtual path mapping here?
			return machine().fds().is_writable_path(sun_path) &&
				machine().fds().is_readable_path(sun_path);
		}

		// Validate network addresses against allow-connect
		return validate_network_access(
			addr, m_config.allowed_connect_ipv4, m_config.allowed_connect_ipv6);
	};
	machine().fds().bind_socket_callback =
	[this] (int fd, struct sockaddr_storage& addr) -> bool {
		(void)fd;

		// Validate unix socket path against allow-read and allow-write
		if (addr.ss_family == AF_UNIX)
		{
			// Compare the socket path with the allowed path
			const struct sockaddr_un *addr_unix =
				reinterpret_cast<const struct sockaddr_un *>(&addr);
			std::string sun_path = addr_unix->sun_path;
			// TODO: reverse the virtual path mapping here?
			return machine().fds().is_writable_path(sun_path) &&
				machine().fds().is_readable_path(sun_path);
		}

		// Validate network addresses against allow-listen
		return validate_network_access(
			addr, m_config.allowed_listen_ipv4, m_config.allowed_listen_ipv6);
	};
	machine().fds().listening_socket_callback =
	[this] (int vfd, int fd) -> bool {
		return this->validate_listener(fd);
	};

	machine().fds().set_resolve_symlink_callback(
	[&] (std::string& path) -> bool {
		bool symlink = false;
		lookup_allowed_path(path, machine().fds().current_working_directory(),
			config.allowed_paths, [&](const Configuration::VirtualPath& vpath) {
				symlink = vpath.symlink;
				// stop iteration here
				return true;
		});
		return symlink;
	});
}
VirtualMachine::VirtualMachine(const VirtualMachine& other, unsigned reqid, bool is_storage)
	: m_machine(other.m_machine, tinykvm::MachineOptions{
		.max_mem = other.config().max_main_memory,
		.max_cow_mem = other.config().max_req_mem,
		.split_hugepages = other.config().split_hugepages,
		.hugepages_arena_size = other.config().hugepage_arena_size,
	  }),
	  m_config(other.m_config),
	  m_original_binary(other.m_original_binary),
	  m_binary_type(other.m_binary_type),
	  m_reqid(reqid),
	  m_ephemeral(other.m_ephemeral),
	  m_is_storage(is_storage),
	  m_master_instance(&other),
	  m_poll_method(other.m_poll_method)
{
	machine().set_userdata<VirtualMachine> (this);
	machine().fds().set_verbose(config().verbose);
	machine().set_verbose_system_calls(config().verbose_syscalls);
	machine().set_verbose_mmap_syscalls(config().verbose_syscalls);
	machine().set_verbose_thread_syscalls(config().verbose_syscalls);
	// Set the current working directory
	machine().fds().set_current_working_directory(config().current_working_directory);
	// Disable epoll_wait() preemption when timeout=-1
	machine().fds().set_preempt_epoll_wait(false);
	/* Allow duplicating read-only FDs from the source */
	machine().fds().set_find_readonly_master_vm_fd_callback(
		[this, master = &other] (int vfd) -> std::optional<const tinykvm::FileDescriptors::Entry*> {
			return master->machine().fds().entry_for_vfd(vfd);
		});
	machine().fds().set_open_writable_callback(
	[&] (std::string& path) -> bool {
		return lookup_allowed_path(path, machine().fds().current_working_directory(),
			config().allowed_paths, [](const Configuration::VirtualPath& vpath) { return vpath.writable; });
	});
	machine().fds().set_open_readable_callback(
	[&] (std::string& path) -> bool {
		return lookup_allowed_path(path, machine().fds().current_working_directory(),
			config().allowed_paths, [](const Configuration::VirtualPath& vpath) { return vpath.readable; });
	});
	machine().fds().connect_socket_callback = other.machine().fds().connect_socket_callback;
	machine().fds().bind_socket_callback = other.machine().fds().bind_socket_callback;
	// When a VM is ephemeral we try to detect when a client
	// disconnects, so we can reset the VM and accept a new connection
	// with a clean slate.
	if (this->m_ephemeral)
	{
		machine().fds().accept_callback =
		[this](int vfd, int fd, int flags) {
			if (this->m_blocking_connections) {
					if (UNLIKELY(config().verbose_syscalls)) {
						fprintf(stderr, "accept4: fd %d (%d) is not accepting connections\n", vfd, fd);
					}
					auto& regs = machine().registers();
					regs.rax = -EAGAIN;
					machine().set_registers(regs);
					return false; // Don't call accept4
			}
			return true; // Call accept4
		};
		machine().fds().accept_socket_callback =
		[this](int listener_vfd, int listener_fd, int fd, struct sockaddr_storage& addr, socklen_t& addrlen) {
			if (this->m_tracked_client_vfd != -1) {
				fprintf(stderr, "Forked VM %u already has a connection on fd %d (%d)\n",
					this->m_reqid, this->m_tracked_client_vfd, this->m_tracked_client_fd);
				return -EAGAIN;
			}
			this->m_tracked_client_fd = fd;
			this->m_tracked_client_vfd = machine().fds().manage(fd, true, true);
			if (config().verbose) {
				printf("Forked VM %u accepted connection on vfd %d (%d)\n",
					this->m_reqid, this->m_tracked_client_vfd, fd);
			}
			this->m_blocking_connections = true;
			return this->m_tracked_client_vfd;
		};
		machine().fds().free_fd_callback =
		[this](int vfd, tinykvm::FileDescriptors::Entry& entry) -> bool {
			if (vfd == this->m_tracked_client_vfd) {
				if (config().verbose) {
					printf("Forked VM %u closed connection on fd %d (%d). Resetting...\n",
						this->m_reqid, this->m_tracked_client_vfd, this->m_tracked_client_fd);
				}
				machine().stop();
				this->m_reset_needed = true;
				return true; // The VM will be reset
			}
			return false; // Nothing happened
		};
	}
}
VirtualMachine::~VirtualMachine()
{
}

void VirtualMachine::reset_to(const VirtualMachine& other)
{
	m_machine.reset_to(other.m_machine, tinykvm::MachineOptions{
		.max_mem = other.m_machine.max_address(),
		.max_cow_mem = other.config().max_req_mem,
		.stack_size = settings::MAIN_STACK_SIZE,
		.reset_free_work_mem = other.config().limit_req_mem,
		.reset_copy_all_registers = true,
		.reset_keep_all_work_memory = other.config().ephemeral_keep_working_memory,
	});
	if (this->m_on_reset_callback) {
		this->m_on_reset_callback();
	}

	this->m_tracked_client_fd = -1;
	this->m_tracked_client_vfd = -1;
	this->m_blocking_connections = false;
}

VirtualMachine::InitResult VirtualMachine::initialize_from_file()
{
	InitResult result;
	auto start = std::chrono::high_resolution_clock::now();
	this->set_waiting_for_requests(true);
	this->machine().prepare_copy_on_write();
	if (this->machine().has_snapshot_state()) {
		this->load_state();
	}
	auto end = std::chrono::high_resolution_clock::now();
	result.initialization_time += std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
	result.warmup_time = std::chrono::milliseconds(0);
	return result;
}

VirtualMachine::InitResult VirtualMachine::initialize(std::function<void()> warmup_callback, bool just_one_vm)
{
	InitResult result;
	if (machine().has_snapshot_state()) {
		return this->initialize_from_file();
	}

	auto start = std::chrono::high_resolution_clock::now();
	try {
		// Use constrained working memory
		machine().prepare_copy_on_write(config().max_main_memory);

		const tinykvm::DynamicElf dyn_elf =
			tinykvm::is_dynamic_elf(std::string_view{
				(const char *)m_original_binary.data(),
				m_original_binary.size()});
		this->m_binary_type = dyn_elf.has_interpreter() ?
			BinaryType::Dynamic :
			(dyn_elf.is_dynamic ? BinaryType::StaticPie :
			 BinaryType::Static);

		// Main arguments: 3x mandatory + N configurable
		std::vector<std::string> args;
		args.reserve(5);
		if (dyn_elf.has_interpreter()) {
			// The real program path (which must be guest-readable)
			/// XXX: TODO: Use /proc/self/exe instead of this?
			args.push_back("/lib64/ld-linux-x86-64.so.2");
			args.push_back((m_is_storage) ? config().storage_filename : config().main_filename);
		} else {
			// Fake filename for the program using the name of the tenant
			args.push_back(name());
		}
		const std::vector<std::string>& main_arguments =
			(m_is_storage) ? config().storage_arguments : config().main_arguments;
		args.insert(args.end(), main_arguments.begin(), main_arguments.end());

		std::vector<std::string> envp = config().environ;
		envp.push_back("KVM_NAME=" + name());

		// Build stack, auxvec, envp and program arguments
		machine().setup_linux(args, envp);

		// If verbose pagetables, print them just before running
		if (config().verbose_pagetable) {
			machine().print_pagetables();
		}

		// Wait for a listening socket and then stop in epoll_wait()
		machine().fds().listening_socket_callback =
		[this](int vfd, int fd) -> bool {
			if (validate_listener(fd) == false) {
				fprintf(stderr, "Invalid listening socket %d (%d)\n", vfd, fd);
				return false;
			}
			this->m_tracked_client_vfd = vfd;
			this->m_tracked_client_fd = fd;
			return true;
		};
		machine().fds().epoll_wait_callback =
		[this](int vfd, int epfd, int timeout) {
			if (this->m_tracked_client_vfd != -1) {
				// Find the listening socket in the epoll set
				const auto& entry = machine().fds().get_epoll_entry_for_vfd(vfd);
				if (entry.epoll_fds.find(m_tracked_client_vfd) == entry.epoll_fds.end()) {
					// The listening socket is not in the epoll set
					return true; // Call epoll_wait
				}
				// If the listening socket is found, we are now waiting for
				// requests, so we can fork new VMs.
				this->m_poll_method = PollMethod::Epoll;
				this->set_waiting_for_requests(true);
				this->machine().stop();
				return false; // Don't call epoll_wait
			}
			return true; // Call epoll_wait
		};
		machine().fds().poll_callback =
		[this](struct pollfd* fds, unsigned nfds, int timeout) {
			if (this->m_tracked_client_vfd != -1) {
				// Find the listening socket in the poll set
				for (unsigned i = 0; i < nfds; i++) {
					if (fds[i].fd == this->m_tracked_client_vfd) {
						this->m_poll_method = PollMethod::Poll;
						this->set_waiting_for_requests(true);
						this->machine().stop();
						return false; // Don't call poll()
					}
				}
			}
			return true; // Call poll()
		};
		machine().fds().accept_callback =
		[this](int vfd, int fd, int flags) {
			if (this->m_tracked_client_vfd != -1 && this->m_poll_method == PollMethod::Undefined) {
				if (vfd == this->m_tracked_client_vfd) {
					// Check whether the listening socket has been set non-blocking.
					int fdflags = fcntl(fd, F_GETFL);
					assert(fdflags != -1);
					if (fdflags & SOCK_NONBLOCK) {
						return true; // Call accept4
					}
					this->m_poll_method = PollMethod::Blocking;
					this->set_waiting_for_requests(true);
					this->machine().stop();
					return false; // Don't call accept4
				}
			}
			return true; // Call accept4
		};
		// Continue/resume or run through main()
		if (getenv("DEBUG") != nullptr) {
			open_debugger();
		} else if (getenv("SAMPLING") != nullptr) {
			bool first = true;
			std::unordered_map<uint64_t, uint64_t> rip_samples;
			while (true) {
				// Run for a short time to allow the VM to initialize
				try {
					machine().run(first ? 0.29f : 0.1f);
				} catch (const tinykvm::MachineTimeoutException& tme) {
					// Grab a RIP sample
					auto& regs = machine().registers();
					const uint64_t rip = regs.rip;
					auto it = rip_samples.find(rip);
					unsigned samples = 0;
					if (it != rip_samples.end()) {
						it->second++;
						samples = it->second;
					} else {
						rip_samples.insert_or_assign(rip, 1);
						samples = 1;
					}
					const std::string sym = machine().resolve(rip,
						std::string_view((const char *)m_original_binary.data(), m_original_binary.size()));
					printf("RIP: 0x%08lX %s (%u)\n", rip, sym.c_str(), samples);
					// The VM is not initialized yet, so we can continue
					first = false;
					continue;
				}
			}
		} else if (getenv("BENCH")) {
			struct timespec ts;
			clock_gettime(CLOCK_MONOTONIC, &ts);
			machine().run();
			struct timespec ts2;
			clock_gettime(CLOCK_MONOTONIC, &ts2);
			const long elapsed_ns = (ts2.tv_sec - ts.tv_sec) * 1'000'000'000L +
				(ts2.tv_nsec - ts.tv_nsec);
			printf("[Bench] Runtime: %ldns (%ldms)\n",
				elapsed_ns, elapsed_ns / 1'000'000L);
		} else if (just_one_vm) {
			// If running with just one VM, let it run forever
			machine().run();
		} else {
			// If running with multiple VMs, startup should be fast
			machine().run( config().max_boot_time );
		}

		// Make sure the program is waiting for requests
		if (!is_waiting_for_requests()) {
			if (just_one_vm)
				return result;
			throw std::runtime_error("Program did not wait for requests");
		}

		// Measure the time taken to initialize the VM
		auto end = std::chrono::high_resolution_clock::now();
		result.initialization_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

		// If a warmup callback is provided, call it
		if (warmup_callback) {
			// Measure the time taken to warmup the VM
			start = std::chrono::high_resolution_clock::now();
			warmup_callback();
			end = std::chrono::high_resolution_clock::now();
			result.warmup_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
		}

		// Resume measuring initialization time
		start = std::chrono::high_resolution_clock::now();

		// Reset the callbacks
		machine().fds().accept_socket_callback = nullptr;
		machine().fds().free_fd_callback = nullptr;
		machine().fds().epoll_wait_callback = nullptr;
		machine().fds().poll_callback = nullptr;
		machine().fds().accept_callback = nullptr;
		machine().fds().set_preempt_epoll_wait(false);

		if (!just_one_vm && !m_is_storage)
		{
			// The VM is currently paused in kernel mode in a system call handler
			// so we need manully return to user mode
			auto& regs = machine().registers();
			// Emulate SYSRET to user mode
			regs.rip = regs.rcx;    // Restore next RIP
			regs.rflags = regs.r11; // Restore rflags
			regs.rax = -4; // EINTR: interrupted system call
			machine().set_registers(regs);

			// Make forkable (with *NO* working memory)
			machine().prepare_copy_on_write();
		} else if (is_storage()) {
			// Skip over OUT instruction
			auto& regs = machine().registers();
			regs.rip += 2;
			machine().set_registers(regs);
		}

		if (!m_is_storage && machine().main_memory().has_snapshot_area()) {
			this->save_state();
		}

		// Finish measuring initialization time
		end = std::chrono::high_resolution_clock::now();
		result.initialization_time += std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
	}
	catch (const tinykvm::MemoryException& me)
	{
		if (config().verbose_pagetable) {
			machine().print_pagetables();
		}
		fprintf(stderr,
			"Machine not initialized properly: %s\n", name().c_str());
		fprintf(stderr,
			"Memory error: %s Address: 0x%lX Size: %zu OOM: %d\n",
			me.what(), me.addr(), me.size(), me.is_oom());
		if (getenv("DEBUG") != nullptr) {
			open_debugger();
		}
		throw; /* IMPORTANT: Re-throw */
	}
	catch (const tinykvm::MachineException& me)
	{
		fprintf(stderr,
			"Machine not initialized properly: %s\n", name().c_str());
		fprintf(stderr,
			"Error: %s Data: 0x%lX\n", me.what(), me.data());
		if (getenv("DEBUG") != nullptr) {
			open_debugger();
		}
		throw; /* IMPORTANT: Re-throw */
	}
	catch (const std::exception& e)
	{
		fprintf(stderr,
			"Machine not initialized properly: %s\n", name().c_str());
		fprintf(stderr,
			"Error: %s\n", e.what());
		if (getenv("DEBUG") != nullptr) {
			open_debugger();
		}
		throw; /* IMPORTANT: Re-throw */
	}
	return result;
}

void VirtualMachine::restart_poll_syscall()
{
	switch (this->m_poll_method)
	{
	case PollMethod::Poll:
		machine().system_call(machine().cpu(), SYS_poll);
		break;
	case PollMethod::Epoll:
		machine().system_call(machine().cpu(), SYS_epoll_wait);
		break;
	case PollMethod::Blocking:
		machine().system_call(machine().cpu(), SYS_accept4);
		break;
	case PollMethod::Undefined:
		// This should never happen
		fprintf(stderr, "VM %s does not have a known polling method\n", name().c_str());
		throw std::runtime_error("VM does not have a known polling method");
	}
}

void VirtualMachine::resume_fork()
{
	if (this->m_ephemeral)
	{
		// The VM is ephemeral, so it should be residing in a system call handler now
		// In order to be fast, we will directly re-do the system call, and then
		// resume the VM.
		while (true)
		{
			this->restart_poll_syscall();
			machine().vmresume();

			if (this->m_reset_needed)
			{
				// Reset the VM
				this->reset_to(*this->m_master_instance);
				this->m_reset_needed = false;
				continue;
			}
			fprintf(stderr, "VM %s did not need reset\n", name().c_str());
			break;
		}
	}
	else
	{
		machine().vmresume();
	}
}

std::string VirtualMachine::binary_type_string() const noexcept
{
	switch (m_binary_type) {
	case BinaryType::Static:     return "static";
	case BinaryType::StaticPie:  return "static-pie";
	case BinaryType::Dynamic:    return "dynamic";
	default:                     return "unknown";
	}
}

void VirtualMachine::init_kvm()
{
	// How much misery has this misfeature caused?
	signal(SIGPIPE, SIG_IGN);

	// Load the dynamic linker
	ld_linux_x86_64_so = file_loader("/lib64/ld-linux-x86-64.so.2");

	// Initialize the KVM subsystem
	tinykvm::Machine::init();
}

#include <tinykvm/rsp_client.hpp>
void VirtualMachine::open_debugger()
{
	const uint16_t port = 2159;
	tinykvm::RSP server((m_is_storage) ? config().storage_filename : config().main_filename, machine(), port);
	while (true) {
		fprintf(stderr, "Waiting 60s for remote GDB on port %u...\n", port);
		auto client = server.accept(60);
		if (!client) {
			fprintf(stderr, "Failed to accept client\n");
			break;
		}
		fprintf(stderr, "Now debugging %s\n", name().c_str());
		bool running = true;
		while (running) {
			try {
				running = client->process_one();
			} catch (const tinykvm::MachineException& me) {
				fprintf(stderr, "Debugger error: %s Data: 0x%#lX\n",
					me.what(), me.data());
			} catch (const std::exception& e) {
				fprintf(stderr, "Debugger error: %s\n", e.what());
			}
		}
		fprintf(stderr, "Debugger client disconnected\n");
	}
}

bool VirtualMachine::validate_listener(int fd)
{
	struct sockaddr_storage addr;
	socklen_t addrlen = sizeof(addr);
	if (getsockname(fd, reinterpret_cast<struct sockaddr *>(&addr), &addrlen) < 0)
	{
		fprintf(stderr, "Listener getsockname() failed: %s\n", strerror(errno));
		throw std::runtime_error("getsockname() failed");
	}

	// Validate unix socket path against allow-read and allow-write
	if (addr.ss_family == AF_UNIX)
	{
		// Compare the socket path with the allowed path
		const struct sockaddr_un *addr_unix =
			reinterpret_cast<const struct sockaddr_un *>(&addr);
		std::string sun_path = addr_unix->sun_path;
		// TODO: reverse the virtual path mapping here?
		return machine().fds().is_writable_path(sun_path) &&
			machine().fds().is_readable_path(sun_path);
	}

	// Validate network addresses against allow listen lists
	return validate_network_access(
		addr, m_config.allowed_listen_ipv4, m_config.allowed_listen_ipv6);
}
