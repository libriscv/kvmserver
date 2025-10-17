#pragma once
#include <sys/socket.h>
#include <chrono>
#include <tinykvm/machine.hpp>
#include "config.hpp"

struct VirtualMachine
{
	using gaddr_t = uint64_t;
	using machine_t = tinykvm::Machine;
	using on_reset_t = std::function<void()>;
	enum class BinaryType : uint8_t {
		Static,
		StaticPie,
		Dynamic,
	};
	enum PollMethod {
		Undefined,
		Blocking,
		Poll,
		Epoll,
	};

	void wait_for_requests_paused();
	bool is_waiting_for_requests() const noexcept { return m_waiting_for_requests; }
	void set_waiting_for_requests(bool waiting) noexcept { m_waiting_for_requests = waiting; }
	void restart_poll_syscall();
	void resume_fork();

	auto& machine() { return m_machine; }
	const auto& machine() const { return m_machine; }

	const auto& name() const noexcept { return (m_is_storage) ? m_config.storage_filename : m_config.main_filename; }
	const auto& config() const { return m_config; }
	BinaryType binary_type() const noexcept { return m_binary_type; }
	std::string binary_type_string() const noexcept;
	void set_on_reset_callback(on_reset_t callback) noexcept { m_on_reset_callback = std::move(callback); }
	void set_ephemeral(bool ephemeral) noexcept { m_ephemeral = ephemeral; }
	bool is_ephemeral() const noexcept { return m_ephemeral; }
	bool is_storage() const noexcept { return m_is_storage; }
	unsigned reqid() const noexcept { return m_reqid; }
	PollMethod poll_method() const noexcept { return m_poll_method; }

	void warmup();
	void open_debugger();

	VirtualMachine(std::string_view binary, const Configuration& config, bool storage = false);
	VirtualMachine(const VirtualMachine& other, unsigned reqid, bool storage);
	~VirtualMachine();
	struct InitResult {
		std::chrono::milliseconds initialization_time;
		std::chrono::milliseconds warmup_time;
	};
	InitResult initialize(std::function<void()> warmup, bool just_one_vm);
	void reset_to(const VirtualMachine&);
	static void init_kvm();

private:
	void begin_warmup_client();
	void stop_warmup_client();
	bool connect_and_send_requests(const sockaddr* serv_addr, socklen_t serv_addr_len);
	bool validate_listener(int fd);
	InitResult initialize_from_file();
	void save_state();
	void load_state();

	tinykvm::Machine m_machine;
	const Configuration& m_config;
	std::string_view m_original_binary;
	BinaryType m_binary_type = BinaryType::Static;
	unsigned m_reqid = 0;
	bool m_ephemeral = false;
	bool m_is_storage = false;
	bool m_reset_needed = false;
	bool m_waiting_for_requests = false;
	bool m_blocking_connections = false;
	// The tracked client fd for ephemeral VMs
	int m_tracked_client_fd = -1;
	int m_tracked_client_vfd = -1;
	PollMethod m_poll_method = Undefined;
	on_reset_t m_on_reset_callback = nullptr;
	const VirtualMachine* m_master_instance = nullptr;
};
