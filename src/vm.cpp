#include "vm.hpp"

#include <stdexcept>
#include "settings.hpp"
extern std::vector<uint8_t> file_loader(const std::string& filename);
static std::vector<uint8_t> ld_linux_x86_64_so;

static const std::vector<uint8_t>& select_main_binary(const std::vector<uint8_t>& program_binary)
{
	const tinykvm::DynamicElf dyn_elf = tinykvm::is_dynamic_elf(
		std::string_view{(const char *)program_binary.data(), program_binary.size()});
	if (dyn_elf.has_interpreter()) {
		// Add the dynamic linker as first argument
		return ld_linux_x86_64_so;
	}
	return program_binary;
}

VirtualMachine::VirtualMachine(const std::vector<uint8_t>& binary, const Configuration& config)
	: m_machine(select_main_binary(binary), tinykvm::MachineOptions{
		.max_mem = config.max_address_space,
		.max_cow_mem = 0UL,
		.dylink_address_hint = config.dylink_address_hint,
		.heap_address_hint = config.heap_address_hint,
		.remappings {config.vmem_remappings},
		.verbose_loader = config.verbose,
		.hugepages = config.hugepage_arena_size != 0,
		.master_direct_memory_writes = true,
		.split_hugepages = false,
		.relocate_fixed_mmap = config.relocate_fixed_mmap,
		.executable_heap = config.executable_heap,
		.clock_gettime_uses_rdtsc = config.clock_gettime_uses_rdtsc,
		.hugepages_arena_size = config.hugepage_arena_size,
	}),
	m_config(config),
	m_original_binary(binary),
	m_ephemeral(config.ephemeral)
{
	machine().set_userdata<VirtualMachine> (this);
	machine().set_verbose_system_calls(
		config.verbose_syscalls);
	machine().set_verbose_mmap_syscalls(
		config.verbose_syscalls);
	machine().set_verbose_thread_syscalls(
		config.verbose_syscalls);
	machine().fds().set_verbose(config.verbose);
	// Set the current working directory
	machine().fds().set_current_working_directory(
		config.current_working_directory);
	// Add all the allowed paths to the VMs file descriptor sub-system
	for (auto& path : config.allowed_paths) {
		if (path.prefix && path.writable) {
			// Add as a prefix path
			machine().fds().add_writable_prefix(path.virtual_path);
			continue;
		}
		machine().fds().add_readonly_file(path.virtual_path);
	}
	// Add a single writable file simply called 'state'
	machine().fds().set_open_writable_callback(
	[&] (std::string& path) -> bool {
		for (auto& tpath : config.allowed_paths) {
			if (tpath.virtual_path == path && tpath.writable) {
				// Rewrite the path to the allowed file
				path = tpath.real_path;
				return true;
			}
		}
		return false;
	});
	machine().fds().set_open_readable_callback(
	[&] (std::string& path) -> bool {
		// Rewrite the path if it's in the rewrite paths
		// It's also allowed to be opened (read-only)
		auto it = config.rewrite_path_indices.find(path);
		if (it != config.rewrite_path_indices.end()) {
			const size_t index = it->second;
			// Rewrite the path to the allowed file
			path = config.allowed_paths.at(index).real_path;
			return true;
		}
		return false;
	});
	machine().fds().set_connect_socket_callback(
	[&] (int fd, struct sockaddr_storage& addr) -> bool {
		(void)fd;
		(void)addr;
		return true;
	});
	machine().fds().set_resolve_symlink_callback(
	[&] (std::string& path) -> bool {
		for (auto& tpath : config.allowed_paths) {
			if (tpath.virtual_path == path && tpath.symlink) {
				// Rewrite the path to where the symlink points
				path = tpath.real_path;
				return true;
			}
		}
		return false;
	});
}
VirtualMachine::VirtualMachine(const VirtualMachine& other)
	: m_machine(other.m_machine, tinykvm::MachineOptions{
		.max_mem = other.config().max_main_memory,
		.max_cow_mem = other.config().max_req_mem,
		.split_hugepages = other.config().split_hugepages,
		.relocate_fixed_mmap = other.config().relocate_fixed_mmap,
		.clock_gettime_uses_rdtsc = other.config().clock_gettime_uses_rdtsc,
		.hugepages_arena_size = other.config().hugepage_arena_size,
	  }),
	  m_config(other.m_config),
	  m_original_binary(other.m_original_binary),
	  m_binary_type(other.m_binary_type)
{
	machine().set_userdata<VirtualMachine> (this);
	machine().fds().set_verbose(config().verbose);
	machine().set_verbose_system_calls(
		other.config().verbose_syscalls);
	machine().set_verbose_mmap_syscalls(
		other.config().verbose_syscalls);
	machine().set_verbose_thread_syscalls(
		other.config().verbose_syscalls);
	// Set the current working directory
	machine().fds().set_current_working_directory(
		other.config().current_working_directory);
	// Disable epoll_wait() preemption when timeout=-1
	machine().fds().set_preempt_epoll_wait(false);
	/* Allow open read-only files */
	for (auto& path : config().allowed_paths) {
		if (path.writable) {
			continue;
		}
		machine().fds().add_readonly_file(path.virtual_path);
	}
	/* Allow duplicating read-only FDs from the source */
	machine().fds().set_find_readonly_master_vm_fd_callback(
		[&] (int vfd) -> std::optional<const tinykvm::FileDescriptors::Entry*> {
			return other.machine().fds().entry_for_vfd(vfd);
		});
	machine().fds().set_connect_socket_callback(
	[&] (int fd, struct sockaddr_storage& addr) -> bool {
		(void)fd;
		(void)addr;
		return true;
	});
}
VirtualMachine::~VirtualMachine()
{
	// Destructor
	printf("VirtualMachine destructor\n");
}

void VirtualMachine::reset_to(VirtualMachine& other)
{
	m_machine.reset_to(other.m_machine, tinykvm::MachineOptions{
		.max_mem = other.m_machine.max_address(),
		.max_cow_mem = other.config().max_req_mem,
		.reset_free_work_mem = other.config().limit_req_mem,
		.reset_copy_all_registers = true,
		.reset_keep_all_work_memory = !this->m_reset_needed && other.config().ephemeral_keep_working_memory,
	});
	this->m_reset_needed = false;
}

void VirtualMachine::initialize(std::function<void()> warmup_callback)
{
	try {
		const auto stack = machine().mmap_allocate(settings::MAIN_STACK_SIZE);
		const auto stack_end = stack + settings::MAIN_STACK_SIZE;
		machine().set_stack_address(stack_end);

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
			m_machine.fds().add_readonly_file(config().filename);
			args.push_back("/lib64/ld-linux-x86-64.so.2");
			args.push_back(config().filename);
		} else {
			// Fake filename for the program using the name of the tenant
			args.push_back(name());
		}
		std::vector<std::string> main_arguments = config().main_arguments;
		args.insert(args.end(), main_arguments.begin(), main_arguments.end());

		std::vector<std::string> envp = config().environ;
		envp.push_back("KVM_NAME=" + name());

		// Build stack, auxvec, envp and program arguments
		machine().setup_linux(args, envp);

		// If verbose pagetables, print them just before running
		if (config().verbose_pagetable) {
			machine().print_pagetables();
		}

		// Continue/resume or run through main()
		machine().run( config().max_boot_time );

		// Make sure the program is waiting for requests
		if (!is_waiting_for_requests()) {
			throw std::runtime_error("Program did not wait for requests");
		}

		// If a warmup callback is provided, call it
		if (warmup_callback) {
			warmup_callback();
		}

		// The VM is currently paused in kernel mode in a system call handler
		// so we need manully return to user mode
		auto& regs = machine().registers();
		// Emulate SYSRET to user mode
		regs.rip = regs.rcx;    // Restore next RIP
		//regs.rflags = regs.r11; // Restore rflags
		regs.rax = -4; // EINTR: interrupted system call
		machine().set_registers(regs);

		// Make forkable (with *NO* working memory)
		machine().prepare_copy_on_write(0UL);
	}
	catch (const tinykvm::MachineException& me)
	{
		fprintf(stderr,
			"Machine not initialized properly: %s\n", name().c_str());
		fprintf(stderr,
			"Error: %s Data: 0x%#lX\n", me.what(), me.data());
		throw; /* IMPORTANT: Re-throw */
	}
	catch (const std::exception& e)
	{
		fprintf(stderr,
			"Machine not initialized properly: %s\n", name().c_str());
		fprintf(stderr,
			"Error: %s\n", e.what());
		throw; /* IMPORTANT: Re-throw */
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
	// Load the dynamic linker
	ld_linux_x86_64_so = file_loader("/lib64/ld-linux-x86-64.so.2");

	// Initialize the KVM subsystem
	tinykvm::Machine::init();
}

#include <tinykvm/rsp_client.hpp>
void VirtualMachine::open_debugger()
{
	const uint16_t port = 2159;
	tinykvm::RSP server(machine(), port);
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
