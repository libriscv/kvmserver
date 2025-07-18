#include <atomic>
#include <cstdio>
#include "mmap_file.hpp"
#include <thread>
#include "vm.hpp"
extern std::vector<uint8_t> file_loader(const std::string& filename);
static std::array<std::atomic<uint64_t>, 64> reset_counters;


int main(int argc, char* argv[], char* envp[])
{
	try {
		Configuration config = Configuration::FromArgs(argc, argv);
		VirtualMachine::init_kvm();

		// Read the binary file
		MmapFile binary_file(config.filename);

		// Create a VirtualMachine instance
		VirtualMachine vm(binary_file.view(), config);
		// Initialize the VM by running through main()
		// and then do a warmup, if required
		const bool just_one_vm = (config.concurrency == 1 && !config.ephemeral);
		auto init = vm.initialize(std::bind(&VirtualMachine::warmup, &vm), just_one_vm);
		// Check if the VM is (likely) waiting for requests
		if (!vm.is_waiting_for_requests()) {
			if (just_one_vm)
				return 0; // It exited normally
			fprintf(stderr, "The program did not wait for requests\n");
			return 1;
		}
		binary_file.dontneed(); // Lazily drop pages from the file

		// Get warmup time (if any)
		const std::string warmup_time = (init.warmup_time.count() > 0) ?
			(" warmup=" + std::to_string(init.warmup_time.count()) + "ms") : "";
		// Get /proc/self RSS
		std::string process_rss;
		FILE* fp = fopen("/proc/self/statm", "r");
		if (fp) {
			uint64_t size = 0;
			uint64_t rss = 0;
			fscanf(fp, "%lu %lu", &size, &rss);
			fclose(fp);
			rss = (rss * getpagesize()) >> 20; // Convert to MB
			process_rss = " rss=" + std::to_string(rss) + "MB";
		}

		// Print informational message
		std::string method = "epoll";
		if (vm.poll_method() == VirtualMachine::PollMethod::Poll) {
			method = "poll";
		} else if (vm.poll_method() == VirtualMachine::PollMethod::Undefined) {
			method = "undefined";
		}
		printf("Program '%s' loaded. %s vm=%u%s huge=%u/%u init=%lums%s%s\n",
			config.filename.c_str(),
			method.c_str(),
			config.concurrency,
			(config.ephemeral ? (config.ephemeral_keep_working_memory ? " ephemeral-kwm" : " ephemeral") : ""),
			config.hugepage_arena_size > 0,
			config.hugepage_requests_arena > 0,
			init.initialization_time.count(),
			warmup_time.c_str(),
			process_rss.c_str());

		// Non-ephemeral single-threaded - we already have a VM
		if (just_one_vm)
		{
			while (true)
			{
				bool failure = false;
				try {
					vm.machine().run();
				} catch (const tinykvm::MachineTimeoutException& me) {
					fprintf(stderr, "*** Main VM timed out\n");
					fprintf(stderr, "Error: %s Data: 0x%#lX\n", me.what(), me.data());
					failure = true;
				} catch (const tinykvm::MachineException& me) {
					fprintf(stderr, "*** Main VM Error: %s Data: 0x%#lX\n",
						me.what(), me.data());
					failure = true;
				} catch (const std::exception& e) {
					fprintf(stderr, "*** Main VM Error: %s\n", e.what());
					failure = true;
				}
				if (failure) {
					if (getenv("DEBUG") != nullptr) {
						vm.open_debugger();
					}
				}
			}
		}

		// Start VM forks
		std::vector<std::thread> threads;
		threads.reserve(config.concurrency);

		for (unsigned int i = 0; i < config.concurrency; ++i)
		{
			threads.emplace_back([&vm, i]()
			{
				// Fork a new VM
				VirtualMachine forked_vm(vm, i);
				forked_vm.set_on_reset_callback([&vm, i]()
				{
					if (!vm.config().verbose)
						return;
					// Progressively print the reset counter
					const uint64_t reset_counter = reset_counters.at(i).fetch_add(1);
					if (i == 0) {
						if (reset_counter % 64 == 0) {
							std::string counters_str;
							for (unsigned int j = 0; j < vm.config().concurrency; ++j) {
								counters_str += std::to_string(j) + ": " + std::to_string(reset_counters[j].load()) + " ";
							}
							fprintf(stderr, "\rForked VMs have been reset: %s\n", counters_str.c_str());
						} else {
							// Print a dot in between resets
							fprintf(stderr, ".");
						}
					}
				});
				if (getenv("DEBUG_FORK") != nullptr) {
					forked_vm.open_debugger();
				}
				while (true) {
					bool failure = false;
					try {
						forked_vm.resume_fork();
					} catch (const tinykvm::MachineTimeoutException& me) {
						fprintf(stderr, "*** Forked VM %u timed out\n", i);
						fprintf(stderr, "Error: %s Data: 0x%#lX\n", me.what(), me.data());
						failure = true;
					} catch (const tinykvm::MachineException& me) {
						fprintf(stderr, "*** Forked VM %u Error: %s Data: 0x%#lX\n",
							i, me.what(), me.data());
						failure = true;
					} catch (const std::exception& e) {
						fprintf(stderr, "*** Forked VM %u Error: %s\n", i, e.what());
						failure = true;
					}
					if (failure) {
						if (getenv("DEBUG") != nullptr) {
							forked_vm.open_debugger();
						}
					}
					if (vm.is_ephemeral() || failure) {
						printf("Forked VM %u finished. Resetting...\n", i);
						try {
							forked_vm.reset_to(vm);
						} catch (const std::exception& e) {
							fprintf(stderr, "*** Forked VM %u failed to reset: %s\n", i, e.what());
						}
					}
				}
			});
		}

		// Wait for all threads to finish
		for (auto& thread : threads) {
			thread.join();
		}

	} catch (const tinykvm::MachineTimeoutException& me) {
		fprintf(stderr, "Machine timed out\n");
		fprintf(stderr, "Error: %s Data: 0x%#lX\n", me.what(), me.data());
		fprintf(stderr, "The server has stopped.\n");
		return 1;
	} catch (const tinykvm::MachineException& me) {
		fprintf(stderr, "Machine not initialized properly\n");
		fprintf(stderr, "Error: %s Data: 0x%#lX\n", me.what(), me.data());
		fprintf(stderr, "The server has stopped.\n");
		return 1;
	} catch (const std::exception& e) {
		fprintf(stderr, "Error: %s\n", e.what());
		fprintf(stderr, "The server has stopped.\n");
		return 1;
	}
	return 0;
}
