#include "vm.hpp"
#include <cstring>
#include <fcntl.h>
#include <stdexcept>
#include <sys/socket.h>
static constexpr bool VERBOSE_SNAPSHOT = false;

struct AppSnapshotState {
	VirtualMachine::PollMethod poll_method;
	int tracked_client_vfd;
	int backlog;
	int domain;
	int type;
	int protocol;
	int flags;
	int reuseaddr;
	socklen_t addr_len;
	struct sockaddr_storage addr;
};

void VirtualMachine::save_state()
{
	machine().save_snapshot_state_now();
	void* map = machine().get_snapshot_state_user_area();
	if (map == nullptr) {
		throw std::runtime_error("snapshot user area is null");
	}
	AppSnapshotState& state = *reinterpret_cast<AppSnapshotState*>(map);
	state.poll_method = this->m_poll_method;
	state.tracked_client_vfd = this->m_tracked_client_vfd;
	state.backlog = 128; // XXX

	const auto fd = this->m_tracked_client_fd;
	int len = sizeof(state.domain);
	if(getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &(state.domain), (socklen_t*) &len) < 0) {
		throw std::runtime_error(strerror(errno));
	}
	len = sizeof(state.type);
	if(getsockopt(fd, SOL_SOCKET, SO_TYPE, &(state.type), (socklen_t*) &len) < 0) {
		throw std::runtime_error(strerror(errno));
	}
	len = sizeof(state.protocol);
	if(getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &(state.protocol), (socklen_t*) &len) < 0) {
		throw std::runtime_error(strerror(errno));
	}
	len = sizeof(state.reuseaddr);
	if (getsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(state.reuseaddr), (socklen_t*) &len) < 0) {
		throw std::runtime_error(strerror(errno));
	}
	state.flags = fcntl(fd, F_GETFL, 0);
	if (state.flags < 0) {
		throw std::runtime_error(strerror(errno));
	}
	state.addr_len = sizeof(state.addr);
	if (getsockname(fd, (struct sockaddr*)&(state.addr), &(state.addr_len)) < 0) {
		throw std::runtime_error(strerror(errno));
	}
}

void VirtualMachine::load_state()
{
	auto map = machine().get_snapshot_state_user_area();
	if (map == NULL) {
		throw std::runtime_error("snapshot user area is null");
	}
	AppSnapshotState& state = *reinterpret_cast<AppSnapshotState*>(map);
	const auto fdm = machine().fds();
	this->m_poll_method = state.poll_method;
	int fd = socket(state.domain, state.type, state.protocol);
	if (fd < 0) {
		throw std::runtime_error(strerror(errno));
	}
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(state.reuseaddr), sizeof(state.reuseaddr)) < 0) {
		throw std::runtime_error(strerror(errno));
	}
	if (fcntl(fd, F_SETFL, state.flags) < 0) {
		throw std::runtime_error(strerror(errno));
	}
	if (bind(fd, (struct sockaddr*) &(state.addr), state.addr_len) < 0) {
		throw std::runtime_error(strerror(errno));
	}
	if (listen(fd, state.backlog) < 0) {
		throw std::runtime_error(strerror(errno));
	}
	this->m_tracked_client_vfd = state.tracked_client_vfd;
	this->m_tracked_client_fd = fd;
	this->machine().fds().manage_as(state.tracked_client_vfd, fd, true, true);

	// Look through epoll systems
	for (auto& [vfd, epoll_entry] : fdm.get_epoll_entries())
	{
		// Find the tracked client vfd in the epoll entries
		auto it = epoll_entry->epoll_fds.find(this->m_tracked_client_vfd);
		if (it != epoll_entry->epoll_fds.end()) {
			const int entry_vfd = it->first;
			auto& event = it->second;
			const int epoll_fd = this->machine().fds().translate(vfd);
			// Remove old entry (with old fd)
			int old_fd = this->machine().fds().translate(entry_vfd);
			if (old_fd >= 0) {
				epoll_ctl(epoll_fd, EPOLL_CTL_DEL, old_fd, &event);
			}
			// Add new entry (with new fd)
			epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event);
			if constexpr (VERBOSE_SNAPSHOT) {
				printf("TinyKVM: Restored epoll entry for vfd %d to new fd %d\n", entry_vfd, fd);
			}
		}
		// Remove entries where we don't have the tracked fd
		for (auto it = epoll_entry->epoll_fds.begin(); it != epoll_entry->epoll_fds.end(); ) {
			const int entry_vfd = it->first;
			const int entry_fd = this->machine().fds().translate(entry_vfd);
			if (entry_fd < 0) {
				// Remove the fd from the epoll entry since we can't use it anymore
				it = epoll_entry->epoll_fds.erase(it);
				if constexpr (VERBOSE_SNAPSHOT) {
					printf("TinyKVM: Removed stale epoll entry for vfd %d\n", entry_vfd);
				}
			} else {
				++it;
			}
		}
	}
}
