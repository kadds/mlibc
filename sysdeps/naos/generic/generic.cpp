#include <abi-bits/ioctls.h>
#include <abi-bits/seek-whence.h>
#include <abi-bits/stat.h>
#include <abi-bits/vm-flags.h>
#include <bits/ansi/timespec.h>
#include <bits/ensure.h>
#include <bits/off_t.h>
#include <bits/ssize_t.h>
#include <cstddef>
#include <cstdint>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/allocator.hpp>
#include <mlibc/debug.hpp>
#include <mlibc/fsfd_target.hpp>
#include <mlibc/tcb.hpp>
#include <mlibc/threads.hpp>
#include <naos/abi.h>
#include <naos/canonical.hpp>
#include <linux/fb.h>
#include <naos/generated/system/Directory.hpp>
#include <naos/generated/system/File.hpp>
#include <naos/generated/system/Process.hpp>
#include <naos/generated/system/ServiceDirectory_client.hpp>
#include <naos/generated/system/Stream.hpp>
#include <naos/generated/system/TerminalJobControl_client.hpp>
#include <naos/generated/system/TerminalManager.hpp>
#include <naos/generated/system/TerminalManager_client.hpp>
#include <naos/generated/system/TerminalMaster.hpp>
#include <naos/generated/system/TerminalMaster_client.hpp>
#include <naos/generated/system/TerminalSlave.hpp>
#include <naos/generated/system/TerminalSlave_client.hpp>
#include <naos/generated/system_uapi.h>
#include <naos/outcome.hpp>
#include <naos/service_directory.hpp>
#include <naos/syscall.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>
#include <termios.h>

#define SYS_CALL(index, name)                                                                      \
	__asm__(".globl " #name " \n\t "                                                               \
	        ".type	" #name ",	@function \n\t" #name ": \n\t"                                     \
	        "movq $" #index ", %rax \n\t"                                                          \
	        "pushq %r10 \n\t"                                                                      \
	        "pushq %r11 \n\t"                                                                      \
	        "pushq %r12 \n\t"                                                                      \
	        "movq %rcx, %r12 \n\t"                                                                 \
	        "movq %rsp, %r10 \n\t"                                                                 \
	        "syscall \n\t"                                                                         \
	        "popq %r12 \n\t"                                                                       \
	        "popq %r11 \n\t"                                                                       \
	        "popq %r10 \n\t"                                                                       \
	        "retq");

SYS_CALL(0, _s_none)
SYS_CALL(1, _s_log)
SYS_CALL(2, _s_clock)

// Native object-call ABI. These wrappers intentionally expose the kernel's
// status return directly; the adapter below maps it to POSIX errno values.
SYS_CALL(17, _na_handle_close)
SYS_CALL(18, _na_channel_create)
SYS_CALL(19, _na_channel_send)
SYS_CALL(20, _na_channel_receive)
SYS_CALL(21, _na_channel_discard)
SYS_CALL(22, _na_handle_wait_many)
SYS_CALL(23, _na_handle_duplicate)
SYS_CALL(24, _na_handle_restrict)
SYS_CALL(25, _na_handle_get_info)
SYS_CALL(26, _na_protocol_descriptor_create)
SYS_CALL(27, _na_protocol_endpoint_create)
SYS_CALL(28, _na_invoke_submit)
SYS_CALL(29, _na_invoke_oneway)
SYS_CALL(30, _na_invocation_cancel)
SYS_CALL(31, _na_invocation_take_result)
SYS_CALL(32, _na_responder_reply)
SYS_CALL(33, _na_responder_fail)
SYS_CALL(34, _na_bootstrap)
SYS_CALL(36, _na_memory_map)
SYS_CALL(37, _na_memory_unmap)
SYS_CALL(38, _na_process_exec)
SYS_CALL(39, _na_process_handle_open)
SYS_CALL(40, _na_process_spawn)
SYS_CALL(41, _na_pipe_create)

#define OPEN_MODE_READ 1
#define OPEN_MODE_WRITE 2
#define OPEN_MODE_BIN 4
#define OPEN_MODE_APPEND 8
#define OPEN_MODE_UNLINK_ON_CLOSE 32

#define STDIN 0
#define STDOUT 1
#define STDERR 2
typedef int fd_t;

namespace {

// Kernel syscalls return negative POSIX errno values. Convert them to the
// positive errno values expected by libc. -1 remains the legacy EOF/internal
// sentinel used by a few older kernel paths.
int naos_syscall_error(int64_t status) {
	if (status == -1)
		return EIO;
	return status < 0 ? static_cast<int>(-status) : static_cast<int>(status);
}

// NaOS does not yet have a user-space signal trampoline. Keep the registered
// actions so libc callers can query and restore them, while the kernel still
// applies its default signal behavior.
struct sigaction naos_signal_actions[NSIG] = {};

} // namespace

static_assert(sizeof(struct termios) == 60, "NaOS termios ABI must match x86-64 Linux layout");
static_assert(offsetof(struct termios, c_iflag) == 0);
static_assert(offsetof(struct termios, c_oflag) == 4);
static_assert(offsetof(struct termios, c_cflag) == 8);
static_assert(offsetof(struct termios, c_lflag) == 12);
static_assert(offsetof(struct termios, c_line) == 16);
static_assert(offsetof(struct termios, c_cc) == 17);
static_assert(offsetof(struct termios, c_ibaud) == 52);
static_assert(offsetof(struct termios, c_obaud) == 56);
static_assert(sizeof(struct winsize) == 8, "NaOS winsize ABI must contain four 16-bit fields");
static_assert(offsetof(struct winsize, ws_row) == 0);
static_assert(offsetof(struct winsize, ws_col) == 2);
static_assert(offsetof(struct winsize, ws_xpixel) == 4);
static_assert(offsetof(struct winsize, ws_ypixel) == 6);

#define OPEN_ATTR_AUTO_CREATE_FILE 1
#define OPEN_ATTR_TRUNC 256
#define OPEN_ATTR_APPEND 2048
#define OPEN_ATTR_WRITE 512
#define OPEN_ATTR_EXEC 1024
#define OPEN_ATTR_FILE 32

#define RWFLAGS_NO_BLOCK 1
#define RWFLAGS_OVERRIDE 2

#define LSEEK_MODE_CURRENT 0
#define LSEEK_MODE_BEGIN 1
#define LSEEK_MODE_END 2

// SYS_CALL(10, int64_t, _s_get_pipe, fd_t *fd1, fd_t *fd2)
// SYS_CALL(11, int, _s_create_fifo, const char *path, uint64_t mode)

struct dentry {
	uint64_t inode;
	uint32_t name_offset; // offset of entry_name_buffer
	uint32_t type;
};

struct dentries {
	int64_t offset;
	char *entry_name_buffer;
	uint64_t buffer_size;
	uint64_t entry_count;
	dentry entry[0];
};

#define FUTEX_WAIT 1
#define FUTEX_WAKE 2

SYS_CALL(3, _s_futex)
SYS_CALL(4, _s_exit)
SYS_CALL(5, _s_exit_thread)
SYS_CALL(6, _s_sleep)
SYS_CALL(7, _s_current_pid)
SYS_CALL(8, _s_current_tid)
#define CP_FLAG_NORETURN 1
#define CP_FLAG_BINARY 2
#define CP_FLAG_SHARED_FILE 8
#define CP_FLAG_SHARED_NOROOT 16
#define CP_FLAG_SHARED_WORK_DIR 32

#define CT_FLAG_IMMEDIATELY 1
#define CT_FLAG_NORETURN 4

#define SIGHUP 1
#define SIGINT 2
#define SIGQUIT 3
#define SIGILL 4
#define SIGTRAP 5
#define SIGABRT 6
#define SIGBUS 7
#define SIGFPE 8
#define SIGKILL 9
#define SIGUSR1 10
#define SIGSEGV 11
#define SIGUSR2 12
#define SIGPIPE 13
#define SIGALRM 14
#define SIGTERM 15
#define SIGSTKFLT 16
#define SIGCHILD 17
#define SIGCOUT 18
#define SIGSTOP 19
#define SIGPWR 30
#define SIGSYS 31
// more ...

#define SIGOPT_GET 1
#define SIGOPT_SET 2
#define SIGOPT_OR 3
#define SIGOPT_AND 4
#define SIGOPT_XOR 5
#define SIGOPT_INVALID_ALL 6

#define SIGTGT_PROC 1
#define SIGTGT_GROUP 2

static inline void sig_mask_init(na_signal_mask_t &mask) { mask = 0; }

static inline void sig_mask_set(na_signal_mask_t &mask, int idx) { mask |= (1ul << idx); }

static inline void sig_mask_clear(na_signal_mask_t &mask, int idx) { mask &= ~(1ul << idx); }

static inline bool sig_mask_get(na_signal_mask_t mask, int idx) { return mask & (1ul << idx); }

SYS_CALL(9, _s_sigsend)
SYS_CALL(10, _s_sigmask)
SYS_CALL(11, _s_tcb_set)
SYS_CALL(12, _s_fork)
SYS_CALL(13, _s_clone)
SYS_CALL(14, _s_yield)

SYS_CALL(15, _s_brk)
SYS_CALL(16, _s_sbrk)

#define MMAP_READ 1
#define MMAP_WRITE 2
#define MMAP_EXEC 4
#define MMAP_FILE 8
#define MMAP_SHARED 16

struct NaosThreadContext {
	void *entry;
	void *user_arg;
	void *tcb;
};

extern "C" [[noreturn]] void __mlibc_naos_thread_entry(void *raw_context);

namespace mlibc {

namespace naos_native {

constexpr uint64_t result_capacity = NA_CHANNEL_MAX_MESSAGE_BYTES;
constexpr uint64_t resource_capacity = NA_CHANNEL_MAX_RESOURCES;
constexpr int max_fds = 1024;
constexpr uint64_t terminal_status_nonblock = 4;
constexpr uint64_t terminal_clone_share_open_description = 8;
constexpr uint64_t terminal_clone_initial_nonblock = 16;

enum class descriptor_kind : uint8_t {
	stream,
	file,
	terminal,
};

struct fd_slot {
	na_handle_t handle = NA_HANDLE_INVALID;
	int flags = 0;
	int fd_flags = 0;
	descriptor_kind kind = descriptor_kind::stream;
	bool terminal = false;
	bool master = false;
	na_handle_t job_control = NA_HANDLE_INVALID;
	bool tostop = false;
	int pty_number = -1;
	na_terminal_locator_t pty_locator{};
	bool has_pty_locator = false;
};

struct call_result {
	uint8_t *bytes;
	uint64_t byte_count;
	na_handle_t resources[resource_capacity];
	uint64_t resource_count;
	na_result_frame_t frame;
};

void destroy_result(call_result &result);
int native_call(
    na_handle_t target,
    uint64_t method,
    const void *request,
    uint64_t request_bytes,
    call_result &result
);

template <typename Request, typename Encoder>
int encoded_native_call(
    na_handle_t target,
    uint64_t method,
    const Request &request,
    Encoder encoder,
    call_result &result
) {
	auto *wire = static_cast<uint8_t *>(getAllocator().allocate(result_capacity));
	if (wire == nullptr)
		return ENOMEM;
	uint64_t written = 0;
	if (!encoder(wire, result_capacity, request, written)) {
		getAllocator().deallocate(wire, result_capacity);
		return EINVAL;
	}
	const int error = native_call(target, method, written == 0 ? nullptr : wire, written, result);
	getAllocator().deallocate(wire, result_capacity);
	return error;
}

template <typename StatValue>
void assign_stat(const StatValue &stat, struct stat &value) {
	value = {};
	value.st_dev = stat.device;
	value.st_ino = stat.inode;
	value.st_nlink = stat.links;
	value.st_mode = stat.mode;
	value.st_uid = stat.uid;
	value.st_gid = stat.gid;
	value.__pad0 = stat.padding;
	value.st_rdev = stat.device_id;
	value.st_size = stat.size;
	value.st_blksize = stat.block_size;
	value.st_blocks = stat.blocks;
	value.st_atim.tv_sec = stat.access_seconds;
	value.st_atim.tv_nsec = stat.access_nanoseconds;
	value.st_mtim.tv_sec = stat.modify_seconds;
	value.st_mtim.tv_nsec = stat.modify_nanoseconds;
	value.st_ctim.tv_sec = stat.change_seconds;
	value.st_ctim.tv_nsec = stat.change_nanoseconds;
}

bool decode_stat(const uint8_t *bytes, uint64_t size, struct stat &value) {
	naos::system::File::stat_response response{};
	if (!naos::system::File::decode_stat_response(bytes, size, response))
		return false;
	assign_stat(response.value, value);
	return true;
}

bool decode_directory_stat(const uint8_t *bytes, uint64_t size, struct stat &value) {
	naos::system::Directory::stat_response response{};
	if (!naos::system::Directory::decode_stat_response(bytes, size, response))
		return false;
	assign_stat(response.value, value);
	return true;
}

fd_slot fd_slots[max_fds] = {};
na_handle_t root_directory = NA_HANDLE_INVALID;
na_handle_t current_directory = NA_HANDLE_INVALID;
na_handle_t service_directory = NA_HANDLE_INVALID;
na_bootstrap_capability_t bootstrap_capabilities[NA_BOOTSTRAP_MAX_CAPABILITIES] = {};
uint32_t bootstrap_capability_count = 0;
bool bootstrapped = false;
volatile uint32_t fd_lock = 0;

int ensure_bootstrap();
extern "C" int naos_take_bootstrap_capability(uint32_t kind, na_handle_t *handle);
int terminal_job_control_for(na_handle_t endpoint, bool master, na_handle_t &job_control);
int terminal_clone_binding(
    na_handle_t endpoint,
    bool master,
    na_handle_t &clone,
    bool share_open_description,
    bool initial_nonblock = false
);
int terminal_get_status_flags(const fd_slot &slot, int &flags);
int terminal_set_status_flags(const fd_slot &slot, int flags);
int update_status_flags(int fd, int flags);

void lock_fds() {
	while (__atomic_exchange_n(&fd_lock, 1, __ATOMIC_ACQUIRE))
		__asm__ volatile("pause");
}

void unlock_fds() { __atomic_store_n(&fd_lock, 0, __ATOMIC_RELEASE); }

void reset_after_fork() {
	fd_slot snapshot[max_fds] = {};
	na_handle_t original_terminal_handles[max_fds] = {};
	na_handle_t original_terminal_jobs[max_fds] = {};
	na_handle_t snapshot_root = NA_HANDLE_INVALID;
	na_handle_t snapshot_current = NA_HANDLE_INVALID;
	na_handle_t snapshot_service = NA_HANDLE_INVALID;
	na_bootstrap_capability_t snapshot_bootstrap_capabilities[NA_BOOTSTRAP_MAX_CAPABILITIES] = {};
	uint32_t snapshot_bootstrap_capability_count = 0;
	lock_fds();
	for (int fd = 0; fd < max_fds; fd++) {
		snapshot[fd] = fd_slots[fd];
		if (snapshot[fd].terminal) {
			original_terminal_handles[fd] = snapshot[fd].handle;
			original_terminal_jobs[fd] = snapshot[fd].job_control;
		}
	}
	snapshot_root = root_directory;
	snapshot_current = current_directory;
	snapshot_service = service_directory;
	snapshot_bootstrap_capability_count = bootstrap_capability_count;
	for (uint32_t i = 0; i < snapshot_bootstrap_capability_count; i++) {
		snapshot_bootstrap_capabilities[i] = bootstrap_capabilities[i];
		bootstrap_capabilities[i].handle = NA_HANDLE_INVALID;
	}
	bootstrap_capability_count = 0;
	unlock_fds();
	for (uint32_t i = 0; i < snapshot_bootstrap_capability_count; i++) {
		if (snapshot_bootstrap_capabilities[i].handle != NA_HANDLE_INVALID)
			_na_handle_close(snapshot_bootstrap_capabilities[i].handle);
	}

	// Fork copies the process resource table, but typed endpoint capabilities
	// remain single-owner connections. Rebind every unique terminal binding in
	// the child, while preserving same-process dup sharing.
	for (int fd = 0; fd < max_fds; fd++) {
		if (!snapshot[fd].terminal || snapshot[fd].handle == NA_HANDLE_INVALID)
			continue;
		bool shared_binding = false;
		for (int previous = 0; previous < fd; previous++) {
			if (original_terminal_handles[previous] != original_terminal_handles[fd])
				continue;
			if (snapshot[previous].handle != NA_HANDLE_INVALID) {
				snapshot[fd].handle = snapshot[previous].handle;
				snapshot[fd].job_control = snapshot[previous].job_control;
				shared_binding = true;
			}
			break;
		}
		if (shared_binding)
			continue;
		na_handle_t clone = NA_HANDLE_INVALID;
		na_handle_t job_control = NA_HANDLE_INVALID;
		if (terminal_clone_binding(snapshot[fd].handle, snapshot[fd].master, clone, true) != 0
		    || terminal_job_control_for(clone, snapshot[fd].master, job_control) != 0) {
			if (clone != NA_HANDLE_INVALID)
				_na_handle_close(clone);
			// If re-binding fails, retain the inherited capability. A child must
			// never observe an open terminal descriptor as silently closed.
			continue;
		}
		snapshot[fd].handle = clone;
		snapshot[fd].job_control = job_control;
	}
	for (int fd = 0; fd < max_fds; fd++) {
		if (original_terminal_handles[fd] == NA_HANDLE_INVALID)
			continue;
		bool first_handle = true;
		bool first_job = true;
		for (int previous = 0; previous < fd; previous++) {
			first_handle = first_handle
			               && original_terminal_handles[previous] != original_terminal_handles[fd];
			first_job = first_job && original_terminal_jobs[previous] != original_terminal_jobs[fd];
		}
		bool inherited_handle_still_used = false;
		bool inherited_job_still_used = false;
		for (int current = 0; current < max_fds; current++) {
			inherited_handle_still_used =
			    inherited_handle_still_used
			    || snapshot[current].handle == original_terminal_handles[fd];
			inherited_job_still_used =
			    inherited_job_still_used
			    || (original_terminal_jobs[fd] != NA_HANDLE_INVALID
			        && snapshot[current].job_control == original_terminal_jobs[fd]);
		}
		if (first_handle && !inherited_handle_still_used)
			_na_handle_close(original_terminal_handles[fd]);
		if (first_job && original_terminal_jobs[fd] != NA_HANDLE_INVALID
		    && !inherited_job_still_used)
			_na_handle_close(original_terminal_jobs[fd]);
	}

	auto inspect = [](na_handle_t handle, na_handle_info_t &info) {
		if (handle == NA_HANDLE_INVALID)
			return false;
		info = {};
		info.struct_size = sizeof(info);
		return _na_handle_get_info(handle, &info) == NA_STATUS_OK;
	};
	auto is_directory = [&](na_handle_t handle) {
		na_handle_info_t info{};
		return inspect(handle, info) && info.binding == NA_BINDING_KERNEL_VIEW
		       && info.scope == NA_SCOPE_DIRECTORY;
	};
	auto is_service_directory = [&](na_handle_t handle) {
		na_handle_info_t info{};
		return inspect(handle, info) && info.binding == NA_BINDING_KERNEL_VIEW
		       && info.scope == NA_SCOPE_SERVICE_DIRECTORY;
	};
	auto is_stream = [&](na_handle_t handle) {
		na_handle_info_t info{};
		return inspect(handle, info) && info.binding == NA_BINDING_KERNEL_VIEW
		       && (info.scope == NA_SCOPE_STREAM || info.scope == NA_SCOPE_FILE);
	};

	bool valid_fd_slots[max_fds] = {};
	for (int fd = 0; fd < max_fds; fd++) {
		if (snapshot[fd].handle != NA_HANDLE_INVALID) {
			na_handle_info_t info{};
			valid_fd_slots[fd] = snapshot[fd].terminal || inspect(snapshot[fd].handle, info);
		}
	}
	const bool bootstrap_valid =
	    is_directory(snapshot_root) && is_directory(snapshot_current)
	    && is_service_directory(snapshot_service) && valid_fd_slots[STDIN] && valid_fd_slots[STDOUT]
	    && valid_fd_slots[STDERR] && (is_stream(snapshot[STDIN].handle) || snapshot[STDIN].terminal)
	    && (is_stream(snapshot[STDOUT].handle) || snapshot[STDOUT].terminal)
	    && (is_stream(snapshot[STDERR].handle) || snapshot[STDERR].terminal);
	const na_handle_t rebound_stdin = snapshot[STDIN].handle;
	const na_handle_t rebound_stdout = snapshot[STDOUT].handle;
	const na_handle_t rebound_stderr = snapshot[STDERR].handle;

	na_handle_t handles[max_fds + 3] = {};
	uint64_t handle_count = 0;
	auto queue_close = [&](na_handle_t handle) {
		if (handle == NA_HANDLE_INVALID)
			return;
		for (uint64_t i = 0; i < handle_count; i++) {
			if (handles[i] == handle)
				return;
		}
		if (handle_count < sizeof(handles) / sizeof(handles[0]))
			handles[handle_count++] = handle;
	};

	lock_fds();
	for (int fd = 0; fd < max_fds; fd++) {
		const bool replace_stdio = !bootstrap_valid && fd <= STDERR;
		if (snapshot[fd].handle == NA_HANDLE_INVALID || !valid_fd_slots[fd] || replace_stdio) {
			if (snapshot[fd].handle != NA_HANDLE_INVALID)
				queue_close(snapshot[fd].handle);
			fd_slots[fd] = {};
		} else
			fd_slots[fd] = snapshot[fd];
	}
	if (bootstrap_valid) {
		root_directory = snapshot_root;
		current_directory = snapshot_current;
		service_directory = snapshot_service;
	} else {
		queue_close(snapshot_root);
		queue_close(snapshot_current);
		queue_close(snapshot_service);
		root_directory = NA_HANDLE_INVALID;
		current_directory = NA_HANDLE_INVALID;
		service_directory = NA_HANDLE_INVALID;
	}
	bootstrapped = bootstrap_valid;
	unlock_fds();

	for (uint64_t i = 0; i < handle_count; i++)
		_na_handle_close(handles[i]);

	if (!bootstrap_valid)
		(void)ensure_bootstrap();
	else {
		na_bootstrap_frame_t frame{};
		frame.struct_size = sizeof(frame);
		frame.flags = NA_BOOTSTRAP_FLAG_REBIND_CONSOLE;
		frame.stdin_stream = rebound_stdin;
		frame.stdout_stream = rebound_stdout;
		frame.stderr_stream = rebound_stderr;
		(void)_na_bootstrap(&frame);
	}
}

void close_cloexec() {
	na_handle_t handles[max_fds * 2] = {};
	uint64_t handle_count = 0;
	auto queue_close = [&](na_handle_t handle) {
		if (handle == NA_HANDLE_INVALID)
			return;
		for (uint64_t i = 0; i < handle_count; i++) {
			if (handles[i] == handle)
				return;
		}
		handles[handle_count++] = handle;
	};
	lock_fds();
	for (int fd = 0; fd < max_fds; fd++) {
		if (fd_slots[fd].handle != NA_HANDLE_INVALID && (fd_slots[fd].fd_flags & FD_CLOEXEC) != 0) {
			const auto handle = fd_slots[fd].handle;
			const auto job_control = fd_slots[fd].job_control;
			const bool terminal = fd_slots[fd].terminal;
			fd_slots[fd] = {};
			bool close_handle = true;
			bool close_job_control = true;
			if (terminal) {
				for (int candidate = 0; candidate < max_fds; candidate++) {
					if (!fd_slots[candidate].terminal)
						continue;
					if (fd_slots[candidate].handle == handle)
						close_handle = false;
					if (fd_slots[candidate].job_control == job_control)
						close_job_control = false;
				}
			}
			if (close_handle)
				queue_close(handle);
			if (close_job_control)
				queue_close(job_control);
		}
	}
	unlock_fds();
	for (uint64_t i = 0; i < handle_count; i++)
		_na_handle_close(handles[i]);
}

int status_errno(uint64_t status) {
	switch (status) {
		case NA_STATUS_OK:
			return 0;
		case NA_STATUS_INVALID_HANDLE:
			return EBADF;
		case NA_STATUS_WRONG_BINDING:
			return ENOTTY;
		case NA_STATUS_WRONG_SCOPE:
			return EINVAL;
		case NA_STATUS_ACCESS_DENIED:
			return EACCES;
		case NA_STATUS_INVALID_ARGUMENT:
		case NA_STATUS_INVALID_MESSAGE:
			return EINVAL;
		case NA_STATUS_BUFFER_TOO_SMALL:
			return EOVERFLOW;
		case NA_STATUS_WOULD_BLOCK:
			return EAGAIN;
		case NA_STATUS_WAIT_TIMED_OUT:
			return ETIMEDOUT;
		case NA_STATUS_RESOURCE_EXHAUSTED:
			return ENOMEM;
		case NA_STATUS_FAULT:
			return EFAULT;
		case NA_STATUS_OBJECT_REVOKED:
			return EIO;
		case NA_STATUS_PEER_CLOSED:
			return EPIPE;
		case NA_STATUS_ALREADY_CONSUMED:
			return EALREADY;
		case NA_STATUS_NOT_SUPPORTED:
			return ENOTSUP;
		default:
			return EIO;
	}
}

int result_errno(const na_result_frame_t &frame) { return naos::result_errno(frame); }

bool terminal_handle_scope(na_handle_t handle, bool &master) {
	na_handle_info_t info{};
	info.struct_size = sizeof(info);
	if (_na_handle_get_info(handle, &info) != NA_STATUS_OK)
		return false;
	if (info.scope == NA_SCOPE_TERMINAL_MASTER) {
		master = true;
		return true;
	}
	if (info.scope == NA_SCOPE_TERMINAL_SLAVE) {
		master = false;
		return true;
	}
	return false;
}

descriptor_kind descriptor_kind_for_handle(na_handle_t handle, bool terminal) {
	if (terminal)
		return descriptor_kind::terminal;
	na_handle_info_t info{};
	info.struct_size = sizeof(info);
	if (_na_handle_get_info(handle, &info) == NA_STATUS_OK && info.scope == NA_SCOPE_FILE)
		return descriptor_kind::file;
	return descriptor_kind::stream;
}

int ensure_bootstrap() {
	if (bootstrapped)
		return 0;
	na_bootstrap_frame_t frame{};
	frame.struct_size = sizeof(frame);
	const auto status = _na_bootstrap(&frame);
	if (status != NA_STATUS_OK)
		return status_errno(status);
	if (frame.capability_count > NA_BOOTSTRAP_MAX_CAPABILITIES)
		return EIO;
	if (frame.root_directory == NA_HANDLE_INVALID || frame.current_directory == NA_HANDLE_INVALID
	    || frame.service_directory == NA_HANDLE_INVALID || frame.stdin_stream == NA_HANDLE_INVALID
	    || frame.stdout_stream == NA_HANDLE_INVALID || frame.stderr_stream == NA_HANDLE_INVALID) {
		return EIO;
	}
	na_handle_t stdin_job_control = NA_HANDLE_INVALID;
	na_handle_t stdout_job_control = NA_HANDLE_INVALID;
	na_handle_t stderr_job_control = NA_HANDLE_INVALID;
	bool master = false;
	if (terminal_handle_scope(frame.stdin_stream, master)) {
		const int error = terminal_job_control_for(frame.stdin_stream, master, stdin_job_control);
		if (error != 0)
			return EIO;
	}
	if (frame.stdout_stream == frame.stdin_stream) {
		stdout_job_control = stdin_job_control;
	} else if (
	    terminal_handle_scope(frame.stdout_stream, master)
	    && terminal_job_control_for(frame.stdout_stream, master, stdout_job_control) != 0
	) {
		if (stdin_job_control != NA_HANDLE_INVALID)
			_na_handle_close(stdin_job_control);
		return EIO;
	}
	if (frame.stderr_stream == frame.stdin_stream) {
		stderr_job_control = stdin_job_control;
	} else if (frame.stderr_stream == frame.stdout_stream) {
		stderr_job_control = stdout_job_control;
	} else if (
	    terminal_handle_scope(frame.stderr_stream, master)
	    && terminal_job_control_for(frame.stderr_stream, master, stderr_job_control) != 0
	) {
		if (stdin_job_control != NA_HANDLE_INVALID)
			_na_handle_close(stdin_job_control);
		if (stdout_job_control != NA_HANDLE_INVALID && stdout_job_control != stdin_job_control)
			_na_handle_close(stdout_job_control);
		return EIO;
	}

	lock_fds();
	auto install_stdio = [](na_handle_t handle, bool write, na_handle_t job_control) {
		bool master = false;
		const bool terminal = terminal_handle_scope(handle, master);
		return fd_slot{
		    handle,
		    write ? O_WRONLY : O_RDONLY,
		    0,
		    descriptor_kind_for_handle(handle, terminal),
		    terminal,
		    master,
		    job_control
		};
	};
	fd_slots[STDIN] = install_stdio(frame.stdin_stream, false, stdin_job_control);
	fd_slots[STDOUT] = install_stdio(frame.stdout_stream, true, stdout_job_control);
	fd_slots[STDERR] = install_stdio(frame.stderr_stream, true, stderr_job_control);
	root_directory = frame.root_directory;
	current_directory = frame.current_directory;
	service_directory = frame.service_directory;
	bootstrap_capability_count = frame.capability_count;
	for (uint32_t i = 0; i < bootstrap_capability_count; i++)
		bootstrap_capabilities[i] = frame.capabilities[i];
	bootstrapped = true;
	unlock_fds();
	return 0;
}

extern "C" int naos_take_terminal_driver_factory(na_handle_t *handle) {
	return naos_take_bootstrap_capability(NA_BOOTSTRAP_CAPABILITY_TERMINAL_DRIVER_FACTORY, handle);
}

extern "C" int naos_take_bootstrap_capability(uint32_t kind, na_handle_t *handle) {
	if (handle == nullptr)
		return EFAULT;
	const int bootstrap_error = ensure_bootstrap();
	if (bootstrap_error != 0)
		return bootstrap_error;

	lock_fds();
	for (uint32_t i = 0; i < bootstrap_capability_count; i++) {
		if (bootstrap_capabilities[i].kind != kind)
			continue;
		*handle = bootstrap_capabilities[i].handle;
		for (uint32_t j = i + 1; j < bootstrap_capability_count; j++)
			bootstrap_capabilities[j - 1] = bootstrap_capabilities[j];
		bootstrap_capability_count--;
		bootstrap_capabilities[bootstrap_capability_count] = {};
		unlock_fds();
		return 0;
	}
	unlock_fds();
	return ENOENT;
}

extern "C" int naos_take_console_frontend(na_handle_t *handle) {
	return naos_take_bootstrap_capability(NA_BOOTSTRAP_CAPABILITY_CONSOLE_FRONTEND, handle);
}

extern "C" int naos_take_input_event_source(na_handle_t *handle) {
	return naos_take_bootstrap_capability(NA_BOOTSTRAP_CAPABILITY_INPUT_EVENT_SOURCE, handle);
}

bool valid_fd(int fd) {
	return fd >= 0 && fd < max_fds && fd_slots[fd].handle != NA_HANDLE_INVALID;
}

na_handle_t handle_for_fd(int fd) {
	if (fd < 0 || fd >= max_fds)
		return NA_HANDLE_INVALID;
	lock_fds();
	const auto handle = fd_slots[fd].handle;
	unlock_fds();
	return handle;
}

int status_flags_for_fd(int fd) {
	if (fd < 0 || fd >= max_fds)
		return 0;
	lock_fds();
	const auto slot = fd_slots[fd];
	unlock_fds();
	if (slot.terminal) {
		int flags = slot.flags;
		if (terminal_get_status_flags(slot, flags) == 0) {
			(void)update_status_flags(fd, flags);
			return flags;
		}
	}
	return slot.flags;
}

int descriptor_flags_for_fd(int fd) {
	if (fd < 0 || fd >= max_fds)
		return -1;
	lock_fds();
	const int result = valid_fd(fd) ? fd_slots[fd].fd_flags : -1;
	unlock_fds();
	return result;
}

int update_descriptor_flags(int fd, int flags) {
	if (fd < 0 || fd >= max_fds)
		return EBADF;
	lock_fds();
	if (!valid_fd(fd)) {
		unlock_fds();
		return EBADF;
	}
	fd_slots[fd].fd_flags = flags & FD_CLOEXEC;
	unlock_fds();
	return 0;
}

int update_status_flags(int fd, int flags) {
	if (fd < 0 || fd >= max_fds)
		return EBADF;
	lock_fds();
	if (!valid_fd(fd)) {
		unlock_fds();
		return EBADF;
	}
	const auto handle = fd_slots[fd].handle;
	const int updated_flags =
	    (fd_slots[fd].flags & ~(O_APPEND | O_NONBLOCK)) | (flags & (O_APPEND | O_NONBLOCK));
	if (fd_slots[fd].terminal) {
		for (int candidate = 0; candidate < max_fds; candidate++) {
			if (fd_slots[candidate].terminal && fd_slots[candidate].handle == handle)
				fd_slots[candidate].flags = updated_flags;
		}
	} else {
		fd_slots[fd].flags = updated_flags;
	}
	unlock_fds();
	return 0;
}

int allocate_fd(
    na_handle_t handle,
    int flags,
    int fd_flags = 0,
    bool terminal = false,
    bool master = false,
    na_handle_t job_control = NA_HANDLE_INVALID
) {
	if (handle == NA_HANDLE_INVALID)
		return -1;
	const auto kind = descriptor_kind_for_handle(handle, terminal);
	lock_fds();
	for (int fd = 3; fd < max_fds; fd++) {
		if (fd_slots[fd].handle == NA_HANDLE_INVALID) {
			fd_slots[fd] = {handle, flags, fd_flags, kind, terminal, master, job_control};
			unlock_fds();
			return fd;
		}
	}
	unlock_fds();
	return -1;
}

int close_fd(int fd) {
	lock_fds();
	if (!valid_fd(fd)) {
		unlock_fds();
		return EBADF;
	}
	const auto handle = fd_slots[fd].handle;
	const auto job_control = fd_slots[fd].job_control;
	const bool terminal = fd_slots[fd].terminal;
	fd_slots[fd] = {};
	bool close_handle = true;
	bool close_job_control = true;
	if (terminal) {
		for (int candidate = 0; candidate < max_fds; candidate++) {
			if (!fd_slots[candidate].terminal)
				continue;
			if (fd_slots[candidate].handle == handle)
				close_handle = false;
			if (fd_slots[candidate].job_control == job_control)
				close_job_control = false;
		}
	}
	unlock_fds();
	const auto close_status = close_handle ? status_errno(_na_handle_close(handle)) : 0;
	if (close_job_control && job_control != NA_HANDLE_INVALID)
		(void)_na_handle_close(job_control);
	return close_status;
}

int duplicate_fd(int fd, int requested_fd, int requested_fd_flags = 0) {
	lock_fds();
	if (!valid_fd(fd)) {
		unlock_fds();
		return -EBADF;
	}
	const auto source = fd_slots[fd].handle;
	const int source_flags = fd_slots[fd].flags;
	const bool source_terminal = fd_slots[fd].terminal;
	const auto source_kind = fd_slots[fd].kind;
	const bool source_master = fd_slots[fd].master;
	const auto source_job_control = fd_slots[fd].job_control;
	const bool source_tostop = fd_slots[fd].tostop;
	const int source_pty_number = fd_slots[fd].pty_number;
	const auto source_pty_locator = fd_slots[fd].pty_locator;
	const bool source_has_pty_locator = fd_slots[fd].has_pty_locator;
	unlock_fds();

	na_handle_t duplicate = NA_HANDLE_INVALID;
	na_handle_t job_duplicate = NA_HANDLE_INVALID;
	if (source_terminal) {
		// POSIX dup shares the same open-description within one process.
		duplicate = source;
		job_duplicate = source_job_control;
	} else {
		const auto status = _na_handle_duplicate(source, 0, &duplicate);
		if (status != NA_STATUS_OK)
			return -status_errno(status);
	}
	if (!source_terminal && source_job_control != NA_HANDLE_INVALID) {
		const auto job_status = _na_handle_duplicate(source_job_control, 0, &job_duplicate);
		if (job_status != NA_STATUS_OK) {
			_na_handle_close(duplicate);
			return -status_errno(job_status);
		}
	}

	if (requested_fd >= 0) {
		if (requested_fd >= max_fds || requested_fd == fd) {
			if (!source_terminal) {
				_na_handle_close(duplicate);
				if (job_duplicate != NA_HANDLE_INVALID)
					_na_handle_close(job_duplicate);
			}
			return requested_fd == fd ? requested_fd : -EBADF;
		}
		lock_fds();
		const auto old = fd_slots[requested_fd].handle;
		const auto old_job = fd_slots[requested_fd].job_control;
		const bool old_terminal = fd_slots[requested_fd].terminal;
		fd_slots[requested_fd] = {
		    duplicate,
		    source_flags,
		    requested_fd_flags,
		    source_kind,
		    source_terminal,
		    source_master,
		    job_duplicate,
		    source_tostop,
		    source_pty_number
		};
		fd_slots[requested_fd].pty_locator = source_pty_locator;
		fd_slots[requested_fd].has_pty_locator = source_has_pty_locator;
		bool close_old = old != NA_HANDLE_INVALID;
		bool close_old_job = old_job != NA_HANDLE_INVALID;
		if (old_terminal) {
			for (int candidate = 0; candidate < max_fds; candidate++) {
				if (!fd_slots[candidate].terminal)
					continue;
				if (fd_slots[candidate].handle == old)
					close_old = false;
				if (fd_slots[candidate].job_control == old_job)
					close_old_job = false;
			}
		}
		unlock_fds();
		if (close_old)
			_na_handle_close(old);
		if (close_old_job)
			_na_handle_close(old_job);
		return requested_fd;
	}

	const int new_fd = allocate_fd(
	    duplicate, source_flags, requested_fd_flags, source_terminal, source_master, job_duplicate
	);
	if (new_fd < 0) {
		if (!source_terminal) {
			_na_handle_close(duplicate);
			if (job_duplicate != NA_HANDLE_INVALID)
				_na_handle_close(job_duplicate);
		}
		return -EMFILE;
	}
	if (source_terminal) {
		lock_fds();
		fd_slots[new_fd].tostop = source_tostop;
		fd_slots[new_fd].pty_number = source_pty_number;
		fd_slots[new_fd].pty_locator = source_pty_locator;
		fd_slots[new_fd].has_pty_locator = source_has_pty_locator;
		unlock_fds();
	}
	return new_fd;
}

int duplicate_fd_min(int fd, int minimum, int new_fd_flags) {
	if (minimum < 0)
		return -EINVAL;
	lock_fds();
	if (!valid_fd(fd)) {
		unlock_fds();
		return -EBADF;
	}
	const auto source = fd_slots[fd].handle;
	const int source_flags = fd_slots[fd].flags;
	const bool source_terminal = fd_slots[fd].terminal;
	const auto source_kind = fd_slots[fd].kind;
	const bool source_master = fd_slots[fd].master;
	const auto source_job_control = fd_slots[fd].job_control;
	const bool source_tostop = fd_slots[fd].tostop;
	const int source_pty_number = fd_slots[fd].pty_number;
	const auto source_pty_locator = fd_slots[fd].pty_locator;
	const bool source_has_pty_locator = fd_slots[fd].has_pty_locator;
	unlock_fds();

	na_handle_t duplicate = NA_HANDLE_INVALID;
	na_handle_t job_duplicate = NA_HANDLE_INVALID;
	if (source_terminal) {
		duplicate = source;
		job_duplicate = source_job_control;
	} else {
		const auto status = _na_handle_duplicate(source, 0, &duplicate);
		if (status != NA_STATUS_OK)
			return -status_errno(status);
	}
	if (!source_terminal && source_job_control != NA_HANDLE_INVALID) {
		const auto job_status = _na_handle_duplicate(source_job_control, 0, &job_duplicate);
		if (job_status != NA_STATUS_OK) {
			_na_handle_close(duplicate);
			return -status_errno(job_status);
		}
	}
	lock_fds();
	int new_fd = -1;
	for (int candidate = minimum < 3 ? 3 : minimum; candidate < max_fds; candidate++) {
		if (fd_slots[candidate].handle == NA_HANDLE_INVALID) {
			fd_slots[candidate] = {
			    duplicate,
			    source_flags,
			    new_fd_flags,
			    source_kind,
			    source_terminal,
			    source_master,
			    job_duplicate,
			    source_tostop,
			    source_pty_number
			};
			fd_slots[candidate].pty_locator = source_pty_locator;
			fd_slots[candidate].has_pty_locator = source_has_pty_locator;
			new_fd = candidate;
			break;
		}
	}
	unlock_fds();
	if (new_fd < 0) {
		if (!source_terminal) {
			_na_handle_close(duplicate);
			if (job_duplicate != NA_HANDLE_INVALID)
				_na_handle_close(job_duplicate);
		}
		return -EMFILE;
	}
	return new_fd;
}

uint64_t get_u64(const uint8_t *buffer) {
	uint64_t value = 0;
	for (uint64_t i = 0; i < sizeof(value); i++)
		value |= static_cast<uint64_t>(buffer[i]) << (i * 8);
	return value;
}

uint32_t get_u32(const uint8_t *buffer) {
	uint32_t value = 0;
	for (uint64_t i = 0; i < sizeof(value); i++)
		value |= static_cast<uint32_t>(buffer[i]) << (i * 8);
	return value;
}

naoidl::native_transport make_transport() {
	naoidl::native_transport_api api{};
	api.handle_close = [](void *, na_handle_t handle) {
		return static_cast<na_status_t>(_na_handle_close(handle));
	};
	api.handle_get_info = [](void *, na_handle_t handle, na_handle_info_t *info) {
		return static_cast<na_status_t>(_na_handle_get_info(handle, info));
	};
	api.invoke_submit =
	    [](void *, na_handle_t target, const na_submit_frame_t *frame, na_handle_t *invocation) {
		    return static_cast<na_status_t>(_na_invoke_submit(target, frame, invocation));
	    };
	api.invoke_send_oneway = [](void *, na_handle_t target, const na_submit_frame_t *frame) {
		return static_cast<na_status_t>(_na_invoke_oneway(target, frame));
	};
	api.invocation_take_result = [](void *, na_handle_t invocation, na_result_frame_t *frame) {
		return static_cast<na_status_t>(_na_invocation_take_result(invocation, frame));
	};
	api.channel_receive = [](void *, na_handle_t endpoint, na_channel_receive_frame_t *frame) {
		return static_cast<na_status_t>(_na_channel_receive(endpoint, frame));
	};
	api.responder_reply = [](void *, na_handle_t responder, const na_reply_frame_t *frame) {
		return static_cast<na_status_t>(_na_responder_reply(responder, frame));
	};
	api.responder_fail = [](void *, na_handle_t responder, const na_fail_frame_t *frame) {
		return static_cast<na_status_t>(_na_responder_fail(responder, frame));
	};
	return naoidl::native_transport(api);
}

int service_uri(const char *uri, std::uint32_t &size) {
	constexpr std::size_t max_service_uri_bytes = 65536;
	if (uri == nullptr)
		return EFAULT;
	const auto length = strlen(uri);
	if (length == 0)
		return EINVAL;
	if (length > max_service_uri_bytes)
		return ENAMETOOLONG;
	constexpr char prefix[] = "naos://";
	if (length <= sizeof(prefix) - 1 || memcmp(uri, prefix, sizeof(prefix) - 1) != 0)
		return EINVAL;
	bool segment_has_value = false;
	bool segment_is_dot = true;
	std::size_t segment_size = 0;
	for (std::size_t i = sizeof(prefix) - 1; i < length; i++) {
		const auto value = static_cast<unsigned char>(uri[i]);
		if (value == '/') {
			if (!segment_has_value || segment_is_dot || segment_size == 2)
				return EINVAL;
			segment_has_value = false;
			segment_is_dot = true;
			segment_size = 0;
			continue;
		}
		const bool alpha = (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z');
		const bool digit = value >= '0' && value <= '9';
		if (!alpha && !digit && value != '-' && value != '_' && value != '.' && value != '~')
			return EINVAL;
		segment_has_value = true;
		segment_size++;
		if (segment_size > 2 || value != '.')
			segment_is_dot = false;
	}
	if (!segment_has_value || segment_is_dot || segment_size == 2)
		return EINVAL;
	size = static_cast<std::uint32_t>(length);
	return 0;
}

int wait_service_invocation(na_handle_t invocation, const struct timespec *deadline = nullptr) {
	na_wait_item_t wait_item{invocation, NA_SIGNAL_COMPLETED | NA_SIGNAL_PEER_CLOSED, 0};
	const auto status = _na_handle_wait_many(&wait_item, 1, deadline);
	if (status == NA_STATUS_WAIT_TIMED_OUT)
		return ETIMEDOUT;
	return naos_syscall_error(status);
}

int terminal_job_control_for(na_handle_t endpoint, bool master, na_handle_t &job_control) {
	job_control = NA_HANDLE_INVALID;
	uint8_t wire[256] = {};
	na_handle_t invocation = NA_HANDLE_INVALID;
	na_handle_t resources[1] = {NA_HANDLE_INVALID};
	na_result_frame_t result = {};
	auto transport = make_transport();
	na_status_t status = NA_STATUS_OK;
	int error = 0;
	if (master) {
		naos::system::TerminalMaster::get_job_control_request request{};
		auto client =
		    naos::system::TerminalMaster::TerminalMasterClient(transport.async(), endpoint);
		status =
		    client.submit_get_job_control(request, nullptr, 0, &invocation, wire, sizeof(wire));
		if (status == NA_STATUS_OK)
			error = wait_service_invocation(invocation);
		if (error == 0) {
			naos::system::TerminalMaster::get_job_control_response response{};
			status = client.take_get_job_control(
			    invocation, response, wire, sizeof(wire), resources, 1, result
			);
			if (status == NA_STATUS_OK && result_errno(result) == 0 && result.actual_resources == 1
			    && response.job_control.value == 0) {
				job_control = resources[0];
				resources[0] = NA_HANDLE_INVALID;
			} else if (status == NA_STATUS_OK) {
				error = result_errno(result) != 0 ? result_errno(result) : EIO;
			}
		}
	} else {
		naos::system::TerminalSlave::get_job_control_request request{};
		auto client = naos::system::TerminalSlave::TerminalSlaveClient(transport.async(), endpoint);
		status =
		    client.submit_get_job_control(request, nullptr, 0, &invocation, wire, sizeof(wire));
		if (status == NA_STATUS_OK)
			error = wait_service_invocation(invocation);
		if (error == 0) {
			naos::system::TerminalSlave::get_job_control_response response{};
			status = client.take_get_job_control(
			    invocation, response, wire, sizeof(wire), resources, 1, result
			);
			if (status == NA_STATUS_OK && result_errno(result) == 0 && result.actual_resources == 1
			    && response.job_control.value == 0) {
				job_control = resources[0];
				resources[0] = NA_HANDLE_INVALID;
			} else if (status == NA_STATUS_OK) {
				error = result_errno(result) != 0 ? result_errno(result) : EIO;
			}
		}
	}
	if (invocation != NA_HANDLE_INVALID)
		_na_handle_close(invocation);
	if (resources[0] != NA_HANDLE_INVALID)
		_na_handle_close(resources[0]);
	if (error != 0)
		return error;
	return status == NA_STATUS_OK && job_control != NA_HANDLE_INVALID ? 0 : status_errno(status);
}

int terminal_clone_binding(
    na_handle_t endpoint,
    bool master,
    na_handle_t &clone,
    bool share_open_description,
    bool initial_nonblock
) {
	clone = NA_HANDLE_INVALID;
	uint8_t wire[256] = {};
	na_handle_t invocation = NA_HANDLE_INVALID;
	na_handle_t resources[1] = {NA_HANDLE_INVALID};
	na_result_frame_t result = {};
	auto transport = make_transport();
	na_status_t status = NA_STATUS_OK;
	int error = 0;
	if (master) {
		naos::system::TerminalMaster::clone_binding_request request{};
		request.flags = (share_open_description ? terminal_clone_share_open_description : 0)
		                | (initial_nonblock ? terminal_clone_initial_nonblock : 0);
		auto client =
		    naos::system::TerminalMaster::TerminalMasterClient(transport.async(), endpoint);
		status = client.submit_clone_binding(request, nullptr, 0, &invocation, wire, sizeof(wire));
		if (status == NA_STATUS_OK)
			error = wait_service_invocation(invocation);
		if (error == 0) {
			naos::system::TerminalMaster::clone_binding_response response{};
			status = client.take_clone_binding(
			    invocation, response, wire, sizeof(wire), resources, 1, result
			);
			if (status == NA_STATUS_OK && result_errno(result) == 0 && result.actual_resources == 1
			    && response.endpoint.value == 0) {
				clone = resources[0];
				resources[0] = NA_HANDLE_INVALID;
			} else if (status == NA_STATUS_OK) {
				error = result_errno(result) != 0 ? result_errno(result) : EIO;
			}
		}
	} else {
		naos::system::TerminalSlave::clone_binding_request request{};
		request.flags = (share_open_description ? terminal_clone_share_open_description : 0)
		                | (initial_nonblock ? terminal_clone_initial_nonblock : 0);
		auto client = naos::system::TerminalSlave::TerminalSlaveClient(transport.async(), endpoint);
		status = client.submit_clone_binding(request, nullptr, 0, &invocation, wire, sizeof(wire));
		if (status == NA_STATUS_OK)
			error = wait_service_invocation(invocation);
		if (error == 0) {
			naos::system::TerminalSlave::clone_binding_response response{};
			status = client.take_clone_binding(
			    invocation, response, wire, sizeof(wire), resources, 1, result
			);
			if (status == NA_STATUS_OK && result_errno(result) == 0 && result.actual_resources == 1
			    && response.endpoint.value == 0) {
				clone = resources[0];
				resources[0] = NA_HANDLE_INVALID;
			} else if (status == NA_STATUS_OK) {
				error = result_errno(result) != 0 ? result_errno(result) : EIO;
			}
		}
	}
	if (invocation != NA_HANDLE_INVALID)
		_na_handle_close(invocation);
	if (resources[0] != NA_HANDLE_INVALID)
		_na_handle_close(resources[0]);
	if (error != 0)
		return error;
	return status == NA_STATUS_OK && clone != NA_HANDLE_INVALID ? 0 : status_errno(status);
}

int terminal_get_status_flags(const fd_slot &slot, int &flags) {
	if (!slot.terminal || slot.handle == NA_HANDLE_INVALID)
		return EBADF;
	uint8_t wire[256] = {};
	na_handle_t invocation = NA_HANDLE_INVALID;
	na_result_frame_t result = {};
	na_status_t status = NA_STATUS_OK;
	int error = 0;
	uint64_t protocol_flags = 0;
	auto transport = make_transport();
	if (slot.master) {
		naos::system::TerminalMaster::get_status_flags_request request{};
		auto client =
		    naos::system::TerminalMaster::TerminalMasterClient(transport.async(), slot.handle);
		status =
		    client.submit_get_status_flags(request, nullptr, 0, &invocation, wire, sizeof(wire));
		if (status == NA_STATUS_OK)
			error = wait_service_invocation(invocation);
		if (error == 0) {
			naos::system::TerminalMaster::get_status_flags_response response{};
			status = client.take_get_status_flags(
			    invocation, response, wire, sizeof(wire), nullptr, 0, result
			);
			if (status == NA_STATUS_OK)
				protocol_flags = response.flags;
		}
	} else {
		naos::system::TerminalSlave::get_status_flags_request request{};
		auto client =
		    naos::system::TerminalSlave::TerminalSlaveClient(transport.async(), slot.handle);
		status =
		    client.submit_get_status_flags(request, nullptr, 0, &invocation, wire, sizeof(wire));
		if (status == NA_STATUS_OK)
			error = wait_service_invocation(invocation);
		if (error == 0) {
			naos::system::TerminalSlave::get_status_flags_response response{};
			status = client.take_get_status_flags(
			    invocation, response, wire, sizeof(wire), nullptr, 0, result
			);
			if (status == NA_STATUS_OK)
				protocol_flags = response.flags;
		}
	}
	if (invocation != NA_HANDLE_INVALID)
		_na_handle_close(invocation);
	if (error != 0)
		return error;
	if (status != NA_STATUS_OK)
		return status_errno(status);
	if (result.execution_outcome != NA_EXECUTION_NONE || result.protocol_error != 0)
		return result_errno(result);
	flags = (slot.flags & ~(O_APPEND | O_NONBLOCK))
	        | ((protocol_flags & terminal_status_nonblock) != 0 ? O_NONBLOCK : 0);
	return 0;
}

int terminal_set_status_flags(const fd_slot &slot, int flags) {
	if (!slot.terminal || slot.handle == NA_HANDLE_INVALID)
		return EBADF;
	uint8_t wire[256] = {};
	na_handle_t invocation = NA_HANDLE_INVALID;
	na_result_frame_t result = {};
	na_status_t status = NA_STATUS_OK;
	int error = 0;
	const auto protocol_flags = (flags & O_NONBLOCK) != 0 ? terminal_status_nonblock : 0;
	auto transport = make_transport();
	if (slot.master) {
		naos::system::TerminalMaster::set_status_flags_request request{};
		request.flags = protocol_flags;
		auto client =
		    naos::system::TerminalMaster::TerminalMasterClient(transport.async(), slot.handle);
		status =
		    client.submit_set_status_flags(request, nullptr, 0, &invocation, wire, sizeof(wire));
		if (status == NA_STATUS_OK)
			error = wait_service_invocation(invocation);
		if (error == 0) {
			naos::system::TerminalMaster::set_status_flags_response response{};
			status = client.take_set_status_flags(
			    invocation, response, wire, sizeof(wire), nullptr, 0, result
			);
		}
	} else {
		naos::system::TerminalSlave::set_status_flags_request request{};
		request.flags = protocol_flags;
		auto client =
		    naos::system::TerminalSlave::TerminalSlaveClient(transport.async(), slot.handle);
		status =
		    client.submit_set_status_flags(request, nullptr, 0, &invocation, wire, sizeof(wire));
		if (status == NA_STATUS_OK)
			error = wait_service_invocation(invocation);
		if (error == 0) {
			naos::system::TerminalSlave::set_status_flags_response response{};
			status = client.take_set_status_flags(
			    invocation, response, wire, sizeof(wire), nullptr, 0, result
			);
		}
	}
	if (invocation != NA_HANDLE_INVALID)
		_na_handle_close(invocation);
	if (error != 0)
		return error;
	if (status != NA_STATUS_OK)
		return status_errno(status);
	if (result.execution_outcome != NA_EXECUTION_NONE || result.protocol_error != 0)
		return result_errno(result);
	return 0;
}

na_handle_t ttyd_manager_handle = NA_HANDLE_INVALID;

void invalidate_ttyd_manager_if_dead(uint64_t status) {
	if (status == NA_STATUS_PEER_CLOSED || status == NA_STATUS_OBJECT_REVOKED
	    || status == NA_STATUS_INVALID_HANDLE) {
		if (ttyd_manager_handle != NA_HANDLE_INVALID) {
			(void)_na_handle_close(ttyd_manager_handle);
			ttyd_manager_handle = NA_HANDLE_INVALID;
		}
	}
}

int ensure_ttyd_manager() {
	if (ttyd_manager_handle != NA_HANDLE_INVALID)
		return 0;
	const int bootstrap_error = ensure_bootstrap();
	if (bootstrap_error != 0)
		return bootstrap_error;
	return naos_service_connect_versioned(
	    "naos://system/terminal",
	    &naos::system::TerminalManager::protocol_uuid,
	    NA_PROTOCOL_RIGHT_INVOKE,
	    naos::system::TerminalManager::revision,
	    naos::system::TerminalManager::features,
	    &ttyd_manager_handle
	);
}

uint64_t terminal_open_mode(int flags);

naos::system::TerminalManager::create_pty_request default_create_pty_request() {
	naos::system::TerminalManager::create_pty_request request{};
	request.attributes.input_flags = 0400 | 02000;
	request.attributes.output_flags = 0001 | 0004;
	request.attributes.control_flags = 0060 | 0200;
	request.attributes.local_flags = 0001 | 0002 | 0010 | 0020 | 0040 | 0100000;
	request.attributes.control_chars[0] = 3;
	request.attributes.control_chars[1] = 28;
	request.attributes.control_chars[2] = 127;
	request.attributes.control_chars[3] = 21;
	request.attributes.control_chars[4] = 4;
	request.attributes.control_chars[5] = 0;
	request.attributes.control_chars[6] = 1;
	request.attributes.control_chars[10] = 26;
	request.attributes.input_baud = 15;
	request.attributes.output_baud = 15;
	request.size.rows = 24;
	request.size.columns = 80;
	request.locked = 1;
	return request;
}

int allocate_terminal_fd(
    na_handle_t handle,
    int flags,
    bool master,
    int fd_flags = 0,
    na_handle_t job_control = NA_HANDLE_INVALID
) {
	if (handle == NA_HANDLE_INVALID)
		return -1;
	lock_fds();
	for (int fd = 3; fd < max_fds; fd++) {
		if (fd_slots[fd].handle == NA_HANDLE_INVALID) {
			fd_slots[fd] = {
			    handle, flags, fd_flags, descriptor_kind::terminal, true, master, job_control
			};
			unlock_fds();
			return fd;
		}
	}
	unlock_fds();
	return -1;
}

int ttyd_create_pty(int flags, int *fd) {
	if (fd == nullptr)
		return EFAULT;
	const int manager_error = ensure_ttyd_manager();
	if (manager_error != 0)
		return manager_error;

	auto transport = make_transport();
	auto client = naos::system::TerminalManager::TerminalManagerClient(
	    transport.async(), ttyd_manager_handle
	);
	auto request = default_create_pty_request();
	request.mode = terminal_open_mode(flags);
	const auto wire_capacity = static_cast<std::uint64_t>(NA_CHANNEL_MAX_MESSAGE_BYTES);
	auto *wire = static_cast<std::uint8_t *>(getAllocator().allocate(wire_capacity));
	if (wire == nullptr)
		return ENOMEM;
	na_handle_t invocation = NA_HANDLE_INVALID;
	auto status = client.submit_create_pty(request, nullptr, 0, &invocation, wire, wire_capacity);
	if (status != NA_STATUS_OK) {
		invalidate_ttyd_manager_if_dead(status);
		getAllocator().deallocate(wire, wire_capacity);
		return status_errno(status);
	}
	int error = wait_service_invocation(invocation);
	if (error != 0) {
		invalidate_ttyd_manager_if_dead(static_cast<uint64_t>(error));
		_na_handle_close(invocation);
		getAllocator().deallocate(wire, wire_capacity);
		return error;
	}
	naos::system::TerminalManager::create_pty_response response{};
	na_handle_t resources[NA_CHANNEL_MAX_RESOURCES]{};
	na_result_frame_t result{};
	status = client.take_create_pty(
	    invocation, response, wire, wire_capacity, resources, NA_CHANNEL_MAX_RESOURCES, result
	);
	_na_handle_close(invocation);
	getAllocator().deallocate(wire, wire_capacity);
	if (status != NA_STATUS_OK) {
		invalidate_ttyd_manager_if_dead(status);
		return status_errno(status);
	}
	error = result_errno(result);
	if (error != 0) {
		for (std::uint64_t i = 0; i < result.actual_resources; i++)
			_na_handle_close(resources[i]);
		return error;
	}
	if (result.actual_resources != 2 || response.number == 0) {
		for (std::uint64_t i = 0; i < result.actual_resources; i++)
			_na_handle_close(resources[i]);
		return EIO;
	}
	const auto master_handle = resources[response.master.value];
	const auto job_control = resources[response.job_control.value];
	const int new_fd = allocate_terminal_fd(
	    master_handle, flags, true, (flags & O_CLOEXEC) != 0 ? FD_CLOEXEC : 0, job_control
	);
	if (new_fd < 0) {
		_na_handle_close(master_handle);
		if (job_control != NA_HANDLE_INVALID)
			_na_handle_close(job_control);
		return EMFILE;
	}
	{
		lock_fds();
		fd_slots[new_fd].pty_number = static_cast<int>(response.number);
		fd_slots[new_fd].pty_locator.terminal_id = response.slave_locator.pair_id;
		fd_slots[new_fd].pty_locator.generation = response.slave_locator.generation;
		for (std::size_t i = 0; i < sizeof(response.slave_locator.token); i++)
			fd_slots[new_fd].pty_locator.token[i] = response.slave_locator.token[i];
		fd_slots[new_fd].has_pty_locator = true;
		unlock_fds();
	}
	*fd = new_fd;
	return 0;
}

int ttyd_open_pty_slave(std::uint32_t number, int flags, int *fd) {
	if (fd == nullptr || number == 0)
		return EFAULT;
	const int manager_error = ensure_ttyd_manager();
	if (manager_error != 0)
		return manager_error;
	auto transport = make_transport();
	auto client = naos::system::TerminalManager::TerminalManagerClient(
	    transport.async(), ttyd_manager_handle
	);
	naos::system::TerminalManager::open_pty_slave_by_number_request request{};
	request.number = number;
	request.mode = terminal_open_mode(flags);
	const auto wire_capacity = static_cast<std::uint64_t>(NA_CHANNEL_MAX_MESSAGE_BYTES);
	auto *wire = static_cast<std::uint8_t *>(getAllocator().allocate(wire_capacity));
	if (wire == nullptr)
		return ENOMEM;
	na_handle_t invocation = NA_HANDLE_INVALID;
	auto status = client.submit_open_pty_slave_by_number(
	    request, nullptr, 0, &invocation, wire, wire_capacity
	);
	if (status != NA_STATUS_OK) {
		invalidate_ttyd_manager_if_dead(status);
		getAllocator().deallocate(wire, wire_capacity);
		return status_errno(status);
	}
	int error = wait_service_invocation(invocation);
	if (error != 0) {
		invalidate_ttyd_manager_if_dead(static_cast<uint64_t>(error));
		_na_handle_close(invocation);
		getAllocator().deallocate(wire, wire_capacity);
		return error;
	}
	naos::system::TerminalManager::open_pty_slave_by_number_response response{};
	na_handle_t resources[NA_CHANNEL_MAX_RESOURCES]{};
	na_result_frame_t result{};
	status = client.take_open_pty_slave_by_number(
	    invocation, response, wire, wire_capacity, resources, NA_CHANNEL_MAX_RESOURCES, result
	);
	_na_handle_close(invocation);
	getAllocator().deallocate(wire, wire_capacity);
	if (status != NA_STATUS_OK) {
		invalidate_ttyd_manager_if_dead(status);
		return status_errno(status);
	}
	error = result_errno(result);
	if (error != 0) {
		for (std::uint64_t i = 0; i < result.actual_resources; i++)
			_na_handle_close(resources[i]);
		return error;
	}
	if (result.actual_resources != 2) {
		for (std::uint64_t i = 0; i < result.actual_resources; i++)
			_na_handle_close(resources[i]);
		return EIO;
	}
	const auto slave_handle = resources[response.slave.value];
	const auto job_control = resources[response.job_control.value];
	const int new_fd = allocate_terminal_fd(
	    slave_handle, flags, false, (flags & O_CLOEXEC) != 0 ? FD_CLOEXEC : 0, job_control
	);
	if (new_fd < 0) {
		_na_handle_close(slave_handle);
		if (job_control != NA_HANDLE_INVALID)
			_na_handle_close(job_control);
		return EMFILE;
	}
	*fd = new_fd;
	return 0;
}

int ttyd_open_controlling(const na_terminal_locator_t &locator, int flags, int *fd) {
	if (fd == nullptr)
		return EFAULT;
	const int manager_error = ensure_ttyd_manager();
	if (manager_error != 0)
		return manager_error;

	auto transport = make_transport();
	auto client = naos::system::TerminalManager::TerminalManagerClient(
	    transport.async(), ttyd_manager_handle
	);
	naos::system::TerminalManager::open_controlling_request request{};
	request.locator.pair_id = locator.terminal_id;
	request.locator.generation = locator.generation;
	for (std::size_t i = 0; i < sizeof(locator.token); i++)
		request.locator.token[i] = locator.token[i];
	request.mode = terminal_open_mode(flags);
	const auto wire_capacity = static_cast<std::uint64_t>(NA_CHANNEL_MAX_MESSAGE_BYTES);
	auto *wire = static_cast<std::uint8_t *>(getAllocator().allocate(wire_capacity));
	if (wire == nullptr)
		return ENOMEM;
	na_handle_t invocation = NA_HANDLE_INVALID;
	auto status =
	    client.submit_open_controlling(request, nullptr, 0, &invocation, wire, wire_capacity);
	if (status != NA_STATUS_OK) {
		invalidate_ttyd_manager_if_dead(status);
		getAllocator().deallocate(wire, wire_capacity);
		return status_errno(status);
	}
	int error = wait_service_invocation(invocation);
	if (error != 0) {
		invalidate_ttyd_manager_if_dead(static_cast<uint64_t>(error));
		_na_handle_close(invocation);
		getAllocator().deallocate(wire, wire_capacity);
		return error;
	}
	naos::system::TerminalManager::open_controlling_response response{};
	na_handle_t resources[NA_CHANNEL_MAX_RESOURCES]{};
	na_result_frame_t result{};
	status = client.take_open_controlling(
	    invocation, response, wire, wire_capacity, resources, NA_CHANNEL_MAX_RESOURCES, result
	);
	_na_handle_close(invocation);
	getAllocator().deallocate(wire, wire_capacity);
	if (status != NA_STATUS_OK) {
		invalidate_ttyd_manager_if_dead(status);
		return status_errno(status);
	}
	error = result_errno(result);
	if (error != 0 || result.actual_resources != 2
	    || response.slave.value >= result.actual_resources
	    || response.job_control.value >= result.actual_resources
	    || response.slave.value == response.job_control.value) {
		for (std::uint64_t i = 0; i < result.actual_resources; i++)
			_na_handle_close(resources[i]);
		return error != 0 ? error : EIO;
	}
	const auto slave_handle = resources[response.slave.value];
	const auto job_control = resources[response.job_control.value];
	const int new_fd = allocate_terminal_fd(
	    slave_handle, flags, false, (flags & O_CLOEXEC) != 0 ? FD_CLOEXEC : 0, job_control
	);
	if (new_fd < 0) {
		_na_handle_close(slave_handle);
		_na_handle_close(job_control);
		return EMFILE;
	}
	*fd = new_fd;
	return 0;
}

uint64_t terminal_open_mode(int flags) {
	uint64_t mode = 0;
	switch (flags & O_ACCMODE) {
		case O_WRONLY:
			mode = 2;
			break;
		case O_RDWR:
			mode = 1 | 2;
			break;
		default:
			mode = 1;
			break;
	}
	if ((flags & O_NONBLOCK) != 0)
		mode |= 4;
	return mode;
}

int ttyd_open_console(int flags, int *fd) {
	if (fd == nullptr)
		return EFAULT;
	const int manager_error = ensure_ttyd_manager();
	if (manager_error != 0)
		return manager_error;

	auto transport = make_transport();
	auto client = naos::system::TerminalManager::TerminalManagerClient(
	    transport.async(), ttyd_manager_handle
	);
	naos::system::TerminalManager::open_console_request request{};
	request.mode = terminal_open_mode(flags);
	const auto wire_capacity = static_cast<std::uint64_t>(NA_CHANNEL_MAX_MESSAGE_BYTES);
	auto *wire = static_cast<std::uint8_t *>(getAllocator().allocate(wire_capacity));
	if (wire == nullptr)
		return ENOMEM;
	na_handle_t invocation = NA_HANDLE_INVALID;
	auto status = client.submit_open_console(request, nullptr, 0, &invocation, wire, wire_capacity);
	if (status != NA_STATUS_OK) {
		invalidate_ttyd_manager_if_dead(status);
		getAllocator().deallocate(wire, wire_capacity);
		return status_errno(status);
	}
	int error = wait_service_invocation(invocation);
	if (error != 0) {
		invalidate_ttyd_manager_if_dead(static_cast<uint64_t>(error));
		_na_handle_close(invocation);
		getAllocator().deallocate(wire, wire_capacity);
		return error;
	}
	naos::system::TerminalManager::open_console_response response{};
	na_handle_t resources[NA_CHANNEL_MAX_RESOURCES]{};
	na_result_frame_t result{};
	status = client.take_open_console(
	    invocation, response, wire, wire_capacity, resources, NA_CHANNEL_MAX_RESOURCES, result
	);
	_na_handle_close(invocation);
	getAllocator().deallocate(wire, wire_capacity);
	if (status != NA_STATUS_OK) {
		invalidate_ttyd_manager_if_dead(status);
		return status_errno(status);
	}
	error = result_errno(result);
	if (error != 0 || result.actual_resources != 2
	    || response.slave.value >= result.actual_resources
	    || response.job_control.value >= result.actual_resources
	    || response.slave.value == response.job_control.value) {
		for (std::uint64_t i = 0; i < result.actual_resources; i++)
			_na_handle_close(resources[i]);
		return error != 0 ? error : EIO;
	}
	const auto slave_handle = resources[response.slave.value];
	const auto job_control = resources[response.job_control.value];
	const int new_fd = allocate_terminal_fd(
	    slave_handle, flags, false, (flags & O_CLOEXEC) != 0 ? FD_CLOEXEC : 0, job_control
	);
	if (new_fd < 0) {
		_na_handle_close(slave_handle);
		_na_handle_close(job_control);
		return EMFILE;
	}
	*fd = new_fd;
	return 0;
}

fd_slot slot_for_fd(int fd) {
	if (fd < 0 || fd >= max_fds)
		return {};
	lock_fds();
	const auto result = fd_slots[fd];
	unlock_fds();
	return result;
}

bool is_controlling_terminal(const fd_slot &slot) {
	if (!slot.terminal || slot.job_control == NA_HANDLE_INVALID)
		return false;
	const auto wire_capacity = static_cast<std::uint64_t>(256);
	auto *wire = static_cast<std::uint8_t *>(getAllocator().allocate(wire_capacity));
	if (wire == nullptr)
		return false;
	auto transport = make_transport();
	auto client = naos::system::TerminalJobControl::TerminalJobControlClient(
	    transport.async(), slot.job_control
	);
	naos::system::TerminalJobControl::query_request request{};
	na_handle_t invocation = NA_HANDLE_INVALID;
	na_status_t status = client.submit_query(request, nullptr, 0, &invocation, wire, wire_capacity);
	bool controlling = false;
	if (status == NA_STATUS_OK && wait_service_invocation(invocation) == 0) {
		naos::system::TerminalJobControl::query_response response{};
		na_result_frame_t result{};
		status = client.take_query(invocation, response, wire, wire_capacity, nullptr, 0, result);
		controlling = status == NA_STATUS_OK && result_errno(result) == 0
		              && response.state.has_controlling_terminal != 0;
	}
	if (invocation != NA_HANDLE_INVALID)
		_na_handle_close(invocation);
	getAllocator().deallocate(wire, wire_capacity);
	return controlling;
}

int terminal_check_io(const fd_slot &slot, bool input, bool tostop) {
	if (slot.master)
		return 0;
	if (slot.job_control == NA_HANDLE_INVALID)
		return EIO;
	std::uint8_t wire[256] = {};
	na_handle_t invocation = NA_HANDLE_INVALID;
	na_result_frame_t result{};
	auto transport = make_transport();
	auto client = naos::system::TerminalJobControl::TerminalJobControlClient(
	    transport.async(), slot.job_control
	);
	naos::system::TerminalJobControl::check_io_request request{};
	request.direction = input ? 1 : 2;
	request.tostop = tostop ? 1 : 0;
	auto status = client.submit_check_io(request, nullptr, 0, &invocation, wire, sizeof(wire));
	if (status != NA_STATUS_OK)
		return status_errno(status);
	const int wait_error = wait_service_invocation(invocation);
	if (wait_error != 0) {
		(void)_na_invocation_cancel(invocation);
		(void)_na_handle_close(invocation);
		return wait_error;
	}
	naos::system::TerminalJobControl::check_io_response response{};
	status = client.take_check_io(invocation, response, wire, sizeof(wire), nullptr, 0, result);
	(void)_na_handle_close(invocation);
	if (status != NA_STATUS_OK)
		return status_errno(status);
	return result_errno(result);
}

int terminal_read(const fd_slot &slot, void *buf, std::size_t count, ssize_t *bytes_read) {
	if (bytes_read == nullptr)
		return EFAULT;
	if ((slot.flags & O_ACCMODE) == O_WRONLY)
		return EBADF;
	if (count == 0) {
		*bytes_read = 0;
		return 0;
	}
	if (buf == nullptr)
		return EFAULT;
	if (const int error = terminal_check_io(slot, true, false); error != 0)
		return error;
	const bool nonblock = (slot.flags & O_NONBLOCK) != 0;
	const auto wire_capacity = static_cast<std::uint64_t>(NA_CHANNEL_MAX_MESSAGE_BYTES);
	auto *wire = static_cast<std::uint8_t *>(getAllocator().allocate(wire_capacity));
	if (wire == nullptr)
		return ENOMEM;
	auto transport = make_transport();
	na_handle_t invocation = NA_HANDLE_INVALID;
	na_result_frame_t result{};
	std::uint8_t *data = nullptr;
	std::uint32_t data_size = 0;
	na_status_t status = NA_STATUS_OK;
	if (slot.master) {
		naos::system::TerminalMaster::read_request request{count, nonblock ? 1 : 0};
		auto client =
		    naos::system::TerminalMaster::TerminalMasterClient(transport.async(), slot.handle);
		status = client.submit_read(request, nullptr, 0, &invocation, wire, wire_capacity);
		if (status != NA_STATUS_OK) {
			getAllocator().deallocate(wire, wire_capacity);
			return status_errno(status);
		}
		int error = wait_service_invocation(invocation);
		if (error != 0) {
			_na_handle_close(invocation);
			getAllocator().deallocate(wire, wire_capacity);
			return error;
		}
		naos::system::TerminalMaster::read_response response{};
		status = client.take_read(invocation, response, wire, wire_capacity, nullptr, 0, result);
		data = const_cast<std::uint8_t *>(response.data.data);
		data_size = response.data.size;
	} else {
		naos::system::TerminalSlave::read_request request{count, nonblock ? 1 : 0};
		auto client =
		    naos::system::TerminalSlave::TerminalSlaveClient(transport.async(), slot.handle);
		status = client.submit_read(request, nullptr, 0, &invocation, wire, wire_capacity);
		if (status != NA_STATUS_OK) {
			getAllocator().deallocate(wire, wire_capacity);
			return status_errno(status);
		}
		int error = wait_service_invocation(invocation);
		if (error != 0) {
			_na_handle_close(invocation);
			getAllocator().deallocate(wire, wire_capacity);
			return error;
		}
		naos::system::TerminalSlave::read_response response{};
		status = client.take_read(invocation, response, wire, wire_capacity, nullptr, 0, result);
		data = const_cast<std::uint8_t *>(response.data.data);
		data_size = response.data.size;
	}
	_na_handle_close(invocation);
	if (status != NA_STATUS_OK) {
		getAllocator().deallocate(wire, wire_capacity);
		return status_errno(status);
	}
	if (result.execution_outcome != NA_EXECUTION_NONE || result.protocol_error != 0) {
		getAllocator().deallocate(wire, wire_capacity);
		return result_errno(result);
	}
	if (nonblock && data_size == 0) {
		getAllocator().deallocate(wire, wire_capacity);
		return EAGAIN;
	}
	if (data_size > count) {
		getAllocator().deallocate(wire, wire_capacity);
		return EIO;
	}
	memcpy(buf, data, data_size);
	*bytes_read = static_cast<ssize_t>(data_size);
	getAllocator().deallocate(wire, wire_capacity);
	return 0;
}

int
terminal_write(const fd_slot &slot, const void *buf, std::size_t count, ssize_t *bytes_written) {
	if (bytes_written == nullptr)
		return EFAULT;
	if ((slot.flags & O_ACCMODE) == O_RDONLY)
		return EBADF;
	if (count == 0) {
		*bytes_written = 0;
		return 0;
	}
	if (buf == nullptr)
		return EFAULT;
	if (const int error = terminal_check_io(slot, false, slot.tostop); error != 0)
		return error;
	const bool nonblock = (slot.flags & O_NONBLOCK) != 0;
	if (count > NA_CHANNEL_MAX_MESSAGE_BYTES - 16)
		return EOVERFLOW;
	const auto wire_capacity = static_cast<std::uint64_t>(NA_CHANNEL_MAX_MESSAGE_BYTES);
	auto *wire = static_cast<std::uint8_t *>(getAllocator().allocate(wire_capacity));
	if (wire == nullptr)
		return ENOMEM;
	auto transport = make_transport();
	na_handle_t invocation = NA_HANDLE_INVALID;
	na_result_frame_t result{};
	std::uint64_t written = 0;
	na_status_t status = NA_STATUS_OK;
	if (slot.master) {
		naos::system::TerminalMaster::write_request request{};
		request.size = count;
		request.flags = nonblock ? 1 : 0;
		request.data = {static_cast<const std::uint8_t *>(buf), static_cast<std::uint32_t>(count)};
		auto client =
		    naos::system::TerminalMaster::TerminalMasterClient(transport.async(), slot.handle);
		status = client.submit_write(request, nullptr, 0, &invocation, wire, wire_capacity);
		if (status != NA_STATUS_OK) {
			getAllocator().deallocate(wire, wire_capacity);
			return status_errno(status);
		}
		int error = wait_service_invocation(invocation);
		if (error != 0) {
			_na_handle_close(invocation);
			getAllocator().deallocate(wire, wire_capacity);
			return error;
		}
		naos::system::TerminalMaster::write_response response{};
		status = client.take_write(invocation, response, wire, wire_capacity, nullptr, 0, result);
		written = response.count;
	} else {
		naos::system::TerminalSlave::write_request request{};
		request.size = count;
		request.flags = nonblock ? 1 : 0;
		request.data = {static_cast<const std::uint8_t *>(buf), static_cast<std::uint32_t>(count)};
		auto client =
		    naos::system::TerminalSlave::TerminalSlaveClient(transport.async(), slot.handle);
		status = client.submit_write(request, nullptr, 0, &invocation, wire, wire_capacity);
		if (status != NA_STATUS_OK) {
			getAllocator().deallocate(wire, wire_capacity);
			return status_errno(status);
		}
		int error = wait_service_invocation(invocation);
		if (error != 0) {
			_na_handle_close(invocation);
			getAllocator().deallocate(wire, wire_capacity);
			return error;
		}
		naos::system::TerminalSlave::write_response response{};
		status = client.take_write(invocation, response, wire, wire_capacity, nullptr, 0, result);
		written = response.count;
	}
	_na_handle_close(invocation);
	if (status != NA_STATUS_OK) {
		getAllocator().deallocate(wire, wire_capacity);
		return status_errno(status);
	}
	if (result.execution_outcome != NA_EXECUTION_NONE || result.protocol_error != 0) {
		getAllocator().deallocate(wire, wire_capacity);
		return result_errno(result);
	}
	*bytes_written = static_cast<ssize_t>(written);
	getAllocator().deallocate(wire, wire_capacity);
	return 0;
}

void assign_termios(struct termios &target, const naos::system::TerminalMaster::Termios &value) {
	target = {};
	target.c_iflag = value.input_flags;
	target.c_oflag = value.output_flags;
	target.c_cflag = value.control_flags;
	target.c_lflag = value.local_flags;
	target.c_line = value.line;
	memcpy(target.c_cc, value.control_chars.data(), sizeof(target.c_cc));
	target.c_ibaud = value.input_baud;
	target.c_obaud = value.output_baud;
}

void assign_termios(struct termios &target, const naos::system::TerminalSlave::Termios &value) {
	target = {};
	target.c_iflag = value.input_flags;
	target.c_oflag = value.output_flags;
	target.c_cflag = value.control_flags;
	target.c_lflag = value.local_flags;
	target.c_line = value.line;
	memcpy(target.c_cc, value.control_chars.data(), sizeof(target.c_cc));
	target.c_ibaud = value.input_baud;
	target.c_obaud = value.output_baud;
}

naos::system::TerminalMaster::Termios wire_termios_master(const struct termios &value) {
	naos::system::TerminalMaster::Termios result{};
	result.input_flags = value.c_iflag;
	result.output_flags = value.c_oflag;
	result.control_flags = value.c_cflag;
	result.local_flags = value.c_lflag;
	result.line = value.c_line;
	memcpy(result.control_chars.data(), value.c_cc, sizeof(value.c_cc));
	result.input_baud = value.c_ibaud;
	result.output_baud = value.c_obaud;
	return result;
}

naos::system::TerminalSlave::Termios wire_termios_slave(const struct termios &value) {
	naos::system::TerminalSlave::Termios result{};
	result.input_flags = value.c_iflag;
	result.output_flags = value.c_oflag;
	result.control_flags = value.c_cflag;
	result.local_flags = value.c_lflag;
	result.line = value.c_line;
	memcpy(result.control_chars.data(), value.c_cc, sizeof(value.c_cc));
	result.input_baud = value.c_ibaud;
	result.output_baud = value.c_obaud;
	return result;
}

int terminal_ioctl(const fd_slot &slot, unsigned long request, void *argument, int *result) {
	const auto wire_capacity = static_cast<std::uint64_t>(NA_CHANNEL_MAX_MESSAGE_BYTES);
	auto *wire = static_cast<std::uint8_t *>(getAllocator().allocate(wire_capacity));
	if (wire == nullptr)
		return ENOMEM;
	auto transport = make_transport();
	int error = 0;
	bool reply_result = false;

	if (request == FIONREAD || request == TIOCINQ) {
		if (argument == nullptr) {
			getAllocator().deallocate(wire, wire_capacity);
			return EFAULT;
		}
		na_handle_t invocation = NA_HANDLE_INVALID;
		na_result_frame_t frame{};
		na_status_t status = NA_STATUS_OK;
		std::uint64_t count = 0;
		if (slot.master) {
			naos::system::TerminalMaster::get_input_count_request req{};
			auto client =
			    naos::system::TerminalMaster::TerminalMasterClient(transport.async(), slot.handle);
			status =
			    client.submit_get_input_count(req, nullptr, 0, &invocation, wire, wire_capacity);
			if (status == NA_STATUS_OK)
				error = wait_service_invocation(invocation);
			if (error == 0) {
				naos::system::TerminalMaster::get_input_count_response response{};
				status = client.take_get_input_count(
				    invocation, response, wire, wire_capacity, nullptr, 0, frame
				);
				if (status == NA_STATUS_OK && frame.execution_outcome == NA_EXECUTION_NONE
				    && frame.protocol_error == 0)
					count = response.count;
			}
		} else {
			naos::system::TerminalSlave::get_input_count_request req{};
			auto client =
			    naos::system::TerminalSlave::TerminalSlaveClient(transport.async(), slot.handle);
			status =
			    client.submit_get_input_count(req, nullptr, 0, &invocation, wire, wire_capacity);
			if (status == NA_STATUS_OK)
				error = wait_service_invocation(invocation);
			if (error == 0) {
				naos::system::TerminalSlave::get_input_count_response response{};
				status = client.take_get_input_count(
				    invocation, response, wire, wire_capacity, nullptr, 0, frame
				);
				if (status == NA_STATUS_OK && frame.execution_outcome == NA_EXECUTION_NONE
				    && frame.protocol_error == 0)
					count = response.count;
			}
		}
		_na_handle_close(invocation);
		if (error == 0 && status != NA_STATUS_OK)
			error = status_errno(status);
		if (error == 0 && result_errno(frame) != 0)
			error = result_errno(frame);
		if (error == 0) {
			if (count > static_cast<std::uint64_t>(INT_MAX))
				error = EOVERFLOW;
			else
				*static_cast<int *>(argument) = static_cast<int>(count);
		}
		getAllocator().deallocate(wire, wire_capacity);
		return error;
	} else if (request == TCGETS) {
		if (argument == nullptr) {
			getAllocator().deallocate(wire, wire_capacity);
			return EFAULT;
		}
		na_handle_t invocation = NA_HANDLE_INVALID;
		na_result_frame_t frame{};
		na_status_t status = NA_STATUS_OK;
		if (slot.master) {
			naos::system::TerminalMaster::get_attributes_request req{};
			auto client =
			    naos::system::TerminalMaster::TerminalMasterClient(transport.async(), slot.handle);
			status =
			    client.submit_get_attributes(req, nullptr, 0, &invocation, wire, wire_capacity);
			if (status == NA_STATUS_OK)
				error = wait_service_invocation(invocation);
			if (error == 0) {
				naos::system::TerminalMaster::get_attributes_response resp{};
				status = client.take_get_attributes(
				    invocation, resp, wire, wire_capacity, nullptr, 0, frame
				);
				if (status == NA_STATUS_OK && frame.execution_outcome == NA_EXECUTION_NONE
				    && frame.protocol_error == 0)
					assign_termios(*static_cast<struct termios *>(argument), resp.attributes);
			}
		} else {
			naos::system::TerminalSlave::get_attributes_request req{};
			auto client =
			    naos::system::TerminalSlave::TerminalSlaveClient(transport.async(), slot.handle);
			status =
			    client.submit_get_attributes(req, nullptr, 0, &invocation, wire, wire_capacity);
			if (status == NA_STATUS_OK)
				error = wait_service_invocation(invocation);
			if (error == 0) {
				naos::system::TerminalSlave::get_attributes_response resp{};
				status = client.take_get_attributes(
				    invocation, resp, wire, wire_capacity, nullptr, 0, frame
				);
				if (status == NA_STATUS_OK && frame.execution_outcome == NA_EXECUTION_NONE
				    && frame.protocol_error == 0)
					assign_termios(*static_cast<struct termios *>(argument), resp.attributes);
			}
		}
		_na_handle_close(invocation);
		if (error == 0 && status != NA_STATUS_OK)
			error = status_errno(status);
		if (error == 0 && frame.execution_outcome != NA_EXECUTION_NONE)
			error = result_errno(frame);
		reply_result = true;
	} else if (request == TCSETS || request == TCSETSW || request == TCSETSF) {
		if (argument == nullptr) {
			getAllocator().deallocate(wire, wire_capacity);
			return EFAULT;
		}
		na_handle_t invocation = NA_HANDLE_INVALID;
		na_result_frame_t frame{};
		na_status_t status = NA_STATUS_OK;
		if (slot.master) {
			naos::system::TerminalMaster::set_attributes_request req{};
			req.attributes = wire_termios_master(*static_cast<const struct termios *>(argument));
			req.action = request == TCSETS ? 0 : (request == TCSETSW ? 1 : 2);
			auto client =
			    naos::system::TerminalMaster::TerminalMasterClient(transport.async(), slot.handle);
			status =
			    client.submit_set_attributes(req, nullptr, 0, &invocation, wire, wire_capacity);
			if (status == NA_STATUS_OK)
				error = wait_service_invocation(invocation);
			if (error == 0) {
				naos::system::TerminalMaster::set_attributes_response resp{};
				status = client.take_set_attributes(
				    invocation, resp, wire, wire_capacity, nullptr, 0, frame
				);
			}
		} else {
			naos::system::TerminalSlave::set_attributes_request req{};
			req.attributes = wire_termios_slave(*static_cast<const struct termios *>(argument));
			req.action = request == TCSETS ? 0 : (request == TCSETSW ? 1 : 2);
			auto client =
			    naos::system::TerminalSlave::TerminalSlaveClient(transport.async(), slot.handle);
			status =
			    client.submit_set_attributes(req, nullptr, 0, &invocation, wire, wire_capacity);
			if (status == NA_STATUS_OK)
				error = wait_service_invocation(invocation);
			if (error == 0) {
				naos::system::TerminalSlave::set_attributes_response resp{};
				status = client.take_set_attributes(
				    invocation, resp, wire, wire_capacity, nullptr, 0, frame
				);
			}
		}
		_na_handle_close(invocation);
		if (error == 0 && status != NA_STATUS_OK)
			error = status_errno(status);
		if (error == 0 && frame.execution_outcome != NA_EXECUTION_NONE)
			error = result_errno(frame);
		reply_result = true;
	} else if (request == TCFLSH || request == TCXONC || request == TCSBRK || request == TCSBRKP) {
		if (argument == nullptr) {
			getAllocator().deallocate(wire, wire_capacity);
			return EFAULT;
		}
		const int value = *static_cast<int *>(argument);
		na_handle_t invocation = NA_HANDLE_INVALID;
		na_result_frame_t frame{};
		na_status_t status = NA_STATUS_OK;
		if (request == TCFLSH) {
			if (value < 0 || value > 2) {
				getAllocator().deallocate(wire, wire_capacity);
				return EINVAL;
			}
			if (slot.master) {
				naos::system::TerminalMaster::flush_request req{};
				req.queue = static_cast<std::uint64_t>(value);
				auto client = naos::system::TerminalMaster::TerminalMasterClient(
				    transport.async(), slot.handle
				);
				status = client.submit_flush(req, nullptr, 0, &invocation, wire, wire_capacity);
				if (status == NA_STATUS_OK)
					error = wait_service_invocation(invocation);
				if (error == 0) {
					naos::system::TerminalMaster::flush_response response{};
					status = client.take_flush(
					    invocation, response, wire, wire_capacity, nullptr, 0, frame
					);
				}
			} else {
				naos::system::TerminalSlave::flush_request req{};
				req.queue = static_cast<std::uint64_t>(value);
				auto client = naos::system::TerminalSlave::TerminalSlaveClient(
				    transport.async(), slot.handle
				);
				status = client.submit_flush(req, nullptr, 0, &invocation, wire, wire_capacity);
				if (status == NA_STATUS_OK)
					error = wait_service_invocation(invocation);
				if (error == 0) {
					naos::system::TerminalSlave::flush_response response{};
					status = client.take_flush(
					    invocation, response, wire, wire_capacity, nullptr, 0, frame
					);
				}
			}
		} else if (request == TCSBRK || request == TCSBRKP) {
			const auto duration_ms =
			    request == TCSBRK ? (value == 0 ? 250U : 0U) : static_cast<unsigned>(value) * 100U;
			if (slot.master) {
				naos::system::TerminalMaster::send_break_request req{};
				req.duration_ms = duration_ms;
				auto client = naos::system::TerminalMaster::TerminalMasterClient(
				    transport.async(), slot.handle
				);
				status =
				    client.submit_send_break(req, nullptr, 0, &invocation, wire, wire_capacity);
				if (status == NA_STATUS_OK)
					error = wait_service_invocation(invocation);
				if (error == 0) {
					naos::system::TerminalMaster::send_break_response response{};
					status = client.take_send_break(
					    invocation, response, wire, wire_capacity, nullptr, 0, frame
					);
				}
			} else {
				naos::system::TerminalSlave::send_break_request req{};
				req.duration_ms = duration_ms;
				auto client = naos::system::TerminalSlave::TerminalSlaveClient(
				    transport.async(), slot.handle
				);
				status =
				    client.submit_send_break(req, nullptr, 0, &invocation, wire, wire_capacity);
				if (status == NA_STATUS_OK)
					error = wait_service_invocation(invocation);
				if (error == 0) {
					naos::system::TerminalSlave::send_break_response response{};
					status = client.take_send_break(
					    invocation, response, wire, wire_capacity, nullptr, 0, frame
					);
				}
			}
		} else {
			std::uint64_t action = 0;
			switch (value) {
				case TCOOFF:
					action = 0;
					break;
				case TCOON:
					action = 1;
					break;
				case TCIOFF:
					action = 2;
					break;
				case TCION:
					action = 3;
					break;
				default:
					getAllocator().deallocate(wire, wire_capacity);
					return EINVAL;
			}
			if (slot.master) {
				naos::system::TerminalMaster::set_flow_request req{};
				req.action = action;
				auto client = naos::system::TerminalMaster::TerminalMasterClient(
				    transport.async(), slot.handle
				);
				status = client.submit_set_flow(req, nullptr, 0, &invocation, wire, wire_capacity);
				if (status == NA_STATUS_OK)
					error = wait_service_invocation(invocation);
				if (error == 0) {
					naos::system::TerminalMaster::set_flow_response response{};
					status = client.take_set_flow(
					    invocation, response, wire, wire_capacity, nullptr, 0, frame
					);
				}
			} else {
				naos::system::TerminalSlave::set_flow_request req{};
				req.action = action;
				auto client = naos::system::TerminalSlave::TerminalSlaveClient(
				    transport.async(), slot.handle
				);
				status = client.submit_set_flow(req, nullptr, 0, &invocation, wire, wire_capacity);
				if (status == NA_STATUS_OK)
					error = wait_service_invocation(invocation);
				if (error == 0) {
					naos::system::TerminalSlave::set_flow_response response{};
					status = client.take_set_flow(
					    invocation, response, wire, wire_capacity, nullptr, 0, frame
					);
				}
			}
		}
		if (invocation != NA_HANDLE_INVALID)
			_na_handle_close(invocation);
		if (error == 0 && status != NA_STATUS_OK)
			error = status_errno(status);
		if (error == 0 && frame.execution_outcome != NA_EXECUTION_NONE)
			error = result_errno(frame);
		reply_result = true;
	} else if (request == TIOCGWINSZ) {
		if (argument == nullptr) {
			getAllocator().deallocate(wire, wire_capacity);
			return EFAULT;
		}
		na_handle_t invocation = NA_HANDLE_INVALID;
		na_result_frame_t frame{};
		na_status_t status = NA_STATUS_OK;
		if (slot.master) {
			naos::system::TerminalMaster::get_winsize_request req{};
			auto client =
			    naos::system::TerminalMaster::TerminalMasterClient(transport.async(), slot.handle);
			status = client.submit_get_winsize(req, nullptr, 0, &invocation, wire, wire_capacity);
			if (status == NA_STATUS_OK)
				error = wait_service_invocation(invocation);
			if (error == 0) {
				naos::system::TerminalMaster::get_winsize_response resp{};
				status = client.take_get_winsize(
				    invocation, resp, wire, wire_capacity, nullptr, 0, frame
				);
				if (status == NA_STATUS_OK && frame.execution_outcome == NA_EXECUTION_NONE
				    && frame.protocol_error == 0) {
					auto *target = static_cast<struct winsize *>(argument);
					target->ws_row = resp.size.rows;
					target->ws_col = resp.size.columns;
					target->ws_xpixel = resp.size.x_pixels;
					target->ws_ypixel = resp.size.y_pixels;
				}
			}
		} else {
			naos::system::TerminalSlave::get_winsize_request req{};
			auto client =
			    naos::system::TerminalSlave::TerminalSlaveClient(transport.async(), slot.handle);
			status = client.submit_get_winsize(req, nullptr, 0, &invocation, wire, wire_capacity);
			if (status == NA_STATUS_OK)
				error = wait_service_invocation(invocation);
			if (error == 0) {
				naos::system::TerminalSlave::get_winsize_response resp{};
				status = client.take_get_winsize(
				    invocation, resp, wire, wire_capacity, nullptr, 0, frame
				);
				if (status == NA_STATUS_OK && frame.execution_outcome == NA_EXECUTION_NONE
				    && frame.protocol_error == 0) {
					auto *target = static_cast<struct winsize *>(argument);
					target->ws_row = resp.size.rows;
					target->ws_col = resp.size.columns;
					target->ws_xpixel = resp.size.x_pixels;
					target->ws_ypixel = resp.size.y_pixels;
				}
			}
		}
		_na_handle_close(invocation);
		if (error == 0 && status != NA_STATUS_OK)
			error = status_errno(status);
		if (error == 0 && frame.execution_outcome != NA_EXECUTION_NONE)
			error = result_errno(frame);
		reply_result = true;
	} else if (request == TIOCSWINSZ) {
		if (argument == nullptr) {
			getAllocator().deallocate(wire, wire_capacity);
			return EFAULT;
		}
		const auto *source = static_cast<const struct winsize *>(argument);
		na_handle_t invocation = NA_HANDLE_INVALID;
		na_result_frame_t frame{};
		na_status_t status = NA_STATUS_OK;
		if (slot.master) {
			naos::system::TerminalMaster::set_winsize_request req{};
			req.size.rows = source->ws_row;
			req.size.columns = source->ws_col;
			req.size.x_pixels = source->ws_xpixel;
			req.size.y_pixels = source->ws_ypixel;
			auto client =
			    naos::system::TerminalMaster::TerminalMasterClient(transport.async(), slot.handle);
			status = client.submit_set_winsize(req, nullptr, 0, &invocation, wire, wire_capacity);
			if (status == NA_STATUS_OK)
				error = wait_service_invocation(invocation);
			if (error == 0) {
				naos::system::TerminalMaster::set_winsize_response resp{};
				status = client.take_set_winsize(
				    invocation, resp, wire, wire_capacity, nullptr, 0, frame
				);
			}
		} else {
			naos::system::TerminalSlave::set_winsize_request req{};
			req.size.rows = source->ws_row;
			req.size.columns = source->ws_col;
			req.size.x_pixels = source->ws_xpixel;
			req.size.y_pixels = source->ws_ypixel;
			auto client =
			    naos::system::TerminalSlave::TerminalSlaveClient(transport.async(), slot.handle);
			status = client.submit_set_winsize(req, nullptr, 0, &invocation, wire, wire_capacity);
			if (status == NA_STATUS_OK)
				error = wait_service_invocation(invocation);
			if (error == 0) {
				naos::system::TerminalSlave::set_winsize_response resp{};
				status = client.take_set_winsize(
				    invocation, resp, wire, wire_capacity, nullptr, 0, frame
				);
			}
		}
		_na_handle_close(invocation);
		if (error == 0 && status != NA_STATUS_OK)
			error = status_errno(status);
		if (error == 0 && frame.execution_outcome != NA_EXECUTION_NONE)
			error = result_errno(frame);
		reply_result = true;
	} else if (request == TIOCGPTN && slot.master) {
		if (argument == nullptr) {
			getAllocator().deallocate(wire, wire_capacity);
			return EFAULT;
		}
		naos::system::TerminalMaster::get_number_request req{};
		na_handle_t invocation = NA_HANDLE_INVALID;
		na_result_frame_t frame{};
		auto client =
		    naos::system::TerminalMaster::TerminalMasterClient(transport.async(), slot.handle);
		auto status = client.submit_get_number(req, nullptr, 0, &invocation, wire, wire_capacity);
		if (status == NA_STATUS_OK)
			error = wait_service_invocation(invocation);
		if (error == 0) {
			naos::system::TerminalMaster::get_number_response resp{};
			status =
			    client.take_get_number(invocation, resp, wire, wire_capacity, nullptr, 0, frame);
			if (status == NA_STATUS_OK && frame.execution_outcome == NA_EXECUTION_NONE
			    && frame.protocol_error == 0)
				*static_cast<int *>(argument) = static_cast<int>(resp.number);
		}
		_na_handle_close(invocation);
		if (error == 0 && status != NA_STATUS_OK)
			error = status_errno(status);
		if (error == 0 && frame.execution_outcome != NA_EXECUTION_NONE)
			error = result_errno(frame);
		reply_result = true;
	} else if (request == TIOCSPTLCK && slot.master) {
		if (argument == nullptr) {
			getAllocator().deallocate(wire, wire_capacity);
			return EFAULT;
		}
		naos::system::TerminalMaster::unlock_request req{};
		req.locked = *static_cast<int *>(argument) != 0;
		na_handle_t invocation = NA_HANDLE_INVALID;
		na_result_frame_t frame{};
		auto client =
		    naos::system::TerminalMaster::TerminalMasterClient(transport.async(), slot.handle);
		auto status = client.submit_unlock(req, nullptr, 0, &invocation, wire, wire_capacity);
		if (status == NA_STATUS_OK)
			error = wait_service_invocation(invocation);
		if (error == 0) {
			naos::system::TerminalMaster::unlock_response resp{};
			status = client.take_unlock(invocation, resp, wire, wire_capacity, nullptr, 0, frame);
		}
		_na_handle_close(invocation);
		if (error == 0 && status != NA_STATUS_OK)
			error = status_errno(status);
		if (error == 0 && frame.execution_outcome != NA_EXECUTION_NONE)
			error = result_errno(frame);
		reply_result = true;
	} else if (request == TIOCSPTLGRANT && slot.master) {
		naos::system::TerminalMaster::grant_slave_request req{};
		na_handle_t invocation = NA_HANDLE_INVALID;
		na_result_frame_t frame{};
		auto client =
		    naos::system::TerminalMaster::TerminalMasterClient(transport.async(), slot.handle);
		auto status = client.submit_grant_slave(req, nullptr, 0, &invocation, wire, wire_capacity);
		if (status == NA_STATUS_OK)
			error = wait_service_invocation(invocation);
		if (error == 0) {
			naos::system::TerminalMaster::grant_slave_response resp{};
			status =
			    client.take_grant_slave(invocation, resp, wire, wire_capacity, nullptr, 0, frame);
		}
		if (invocation != NA_HANDLE_INVALID)
			_na_handle_close(invocation);
		if (error == 0 && status != NA_STATUS_OK)
			error = status_errno(status);
		if (error == 0 && frame.execution_outcome != NA_EXECUTION_NONE)
			error = result_errno(frame);
		reply_result = true;
	} else if (
	    request == TIOCGPGRP || request == TIOCSPGRP || request == TIOCSCTTY || request == TIOCGSID
	    || request == TIOCNOTTY
	) {
		if (slot.job_control == NA_HANDLE_INVALID) {
			getAllocator().deallocate(wire, wire_capacity);
			return ENOTTY;
		}
		if ((request == TIOCGPGRP || request == TIOCSPGRP || request == TIOCSCTTY
		     || request == TIOCGSID)
		    && argument == nullptr) {
			getAllocator().deallocate(wire, wire_capacity);
			return EFAULT;
		}
		auto client = naos::system::TerminalJobControl::TerminalJobControlClient(
		    transport.async(), slot.job_control
		);
		na_handle_t invocation = NA_HANDLE_INVALID;
		na_result_frame_t frame{};
		na_status_t status = NA_STATUS_OK;
		if (request == TIOCGPGRP) {
			naos::system::TerminalJobControl::get_pgrp_request req{};
			status = client.submit_get_pgrp(req, nullptr, 0, &invocation, wire, wire_capacity);
			if (status == NA_STATUS_OK)
				error = wait_service_invocation(invocation);
			if (error == 0) {
				naos::system::TerminalJobControl::get_pgrp_response resp{};
				status =
				    client.take_get_pgrp(invocation, resp, wire, wire_capacity, nullptr, 0, frame);
				if (status == NA_STATUS_OK && frame.execution_outcome == NA_EXECUTION_NONE
				    && frame.protocol_error == 0)
					*static_cast<int *>(argument) = static_cast<int>(resp.group);
			}
		} else if (request == TIOCSPGRP) {
			naos::system::TerminalJobControl::set_pgrp_request req{};
			req.group = *static_cast<int *>(argument);
			status = client.submit_set_pgrp(req, nullptr, 0, &invocation, wire, wire_capacity);
			if (status == NA_STATUS_OK)
				error = wait_service_invocation(invocation);
			if (error == 0) {
				naos::system::TerminalJobControl::set_pgrp_response resp{};
				status =
				    client.take_set_pgrp(invocation, resp, wire, wire_capacity, nullptr, 0, frame);
			}
		} else if (request == TIOCSCTTY) {
			naos::system::TerminalJobControl::attach_request req{};
			req.force = *static_cast<int *>(argument) != 0;
			status = client.submit_attach(req, nullptr, 0, &invocation, wire, wire_capacity);
			if (status == NA_STATUS_OK)
				error = wait_service_invocation(invocation);
			if (error == 0) {
				naos::system::TerminalJobControl::attach_response resp{};
				status =
				    client.take_attach(invocation, resp, wire, wire_capacity, nullptr, 0, frame);
			}
		} else if (request == TIOCGSID) {
			naos::system::TerminalJobControl::get_sid_request req{};
			status = client.submit_get_sid(req, nullptr, 0, &invocation, wire, wire_capacity);
			if (status == NA_STATUS_OK)
				error = wait_service_invocation(invocation);
			if (error == 0) {
				naos::system::TerminalJobControl::get_sid_response resp{};
				status =
				    client.take_get_sid(invocation, resp, wire, wire_capacity, nullptr, 0, frame);
				if (status == NA_STATUS_OK && frame.execution_outcome == NA_EXECUTION_NONE
				    && frame.protocol_error == 0)
					*static_cast<int *>(argument) = static_cast<int>(resp.session);
			}
		} else {
			naos::system::TerminalJobControl::detach_request req{};
			status = client.submit_detach(req, nullptr, 0, &invocation, wire, wire_capacity);
			if (status == NA_STATUS_OK)
				error = wait_service_invocation(invocation);
			if (error == 0) {
				naos::system::TerminalJobControl::detach_response resp{};
				status =
				    client.take_detach(invocation, resp, wire, wire_capacity, nullptr, 0, frame);
			}
		}
		_na_handle_close(invocation);
		if (error == 0 && status != NA_STATUS_OK)
			error = status_errno(status);
		if (error == 0 && result_errno(frame) != 0)
			error = result_errno(frame);
		reply_result = true;
	} else {
		getAllocator().deallocate(wire, wire_capacity);
		return ENOTTY;
	}

	getAllocator().deallocate(wire, wire_capacity);
	if (error == 0 && reply_result && result != nullptr)
		*result = 0;
	return error;
}

extern "C" int naos_service_register_handle(const char *uri, na_handle_t handle) {
	const int bootstrap_error = ensure_bootstrap();
	if (bootstrap_error != 0)
		return bootstrap_error;
	std::uint32_t uri_size = 0;
	int error = service_uri(uri, uri_size);
	if (error != 0)
		return error;
	if (handle == NA_HANDLE_INVALID)
		return EBADF;

	const auto wire_capacity = static_cast<std::uint64_t>(NA_CHANNEL_MAX_MESSAGE_BYTES);
	auto *wire = static_cast<std::uint8_t *>(getAllocator().allocate(wire_capacity));
	if (wire == nullptr)
		return ENOMEM;
	naos::system::ServiceDirectory::register_request request{};
	request.service.value = 0;
	request.uri = {uri, uri_size};
	na_resource_disposition_t disposition{};
	disposition.handle = handle;
	disposition.operation = NA_RESOURCE_MOVE;
	na_handle_t invocation = NA_HANDLE_INVALID;
	auto transport = make_transport();
	auto client = naos::system::ServiceDirectory::ServiceDirectoryClient(
	    transport.async(), service_directory
	);
	const auto submit_status =
	    client.submit_register(request, &disposition, 1, &invocation, wire, wire_capacity);
	if (submit_status != NA_STATUS_OK) {
		getAllocator().deallocate(wire, wire_capacity);
		return status_errno(submit_status);
	}
	error = wait_service_invocation(invocation);
	if (error != 0) {
		_na_handle_close(invocation);
		getAllocator().deallocate(wire, wire_capacity);
		return error;
	}
	naos::system::ServiceDirectory::register_response response{};
	na_handle_t response_resources[NA_CHANNEL_MAX_RESOURCES] = {};
	na_result_frame_t result{};
	const auto take_status = client.take_register(
	    invocation,
	    response,
	    wire,
	    wire_capacity,
	    response_resources,
	    NA_CHANNEL_MAX_RESOURCES,
	    result
	);
	_na_handle_close(invocation);
	getAllocator().deallocate(wire, wire_capacity);
	if (take_status != NA_STATUS_OK)
		return status_errno(take_status);
	return result_errno(result);
}

extern "C" int naos_service_register_fd(const char *uri, int fd) {
	const int bootstrap_error = ensure_bootstrap();
	if (bootstrap_error != 0)
		return bootstrap_error;
	const auto source = handle_for_fd(fd);
	if (source == NA_HANDLE_INVALID)
		return EBADF;
	na_handle_t duplicate = NA_HANDLE_INVALID;
	if (_na_handle_duplicate(source, 0, &duplicate) != NA_STATUS_OK)
		return EBADF;
	const int error = naos_service_register_handle(uri, duplicate);
	if (error != 0)
		_na_handle_close(duplicate);
	return error;
}

extern "C" int naos_service_resolve(const char *uri, na_handle_t *handle) {
	if (handle == nullptr)
		return EFAULT;
	*handle = NA_HANDLE_INVALID;
	const int bootstrap_error = ensure_bootstrap();
	if (bootstrap_error != 0)
		return bootstrap_error;
	std::uint32_t uri_size = 0;
	int error = service_uri(uri, uri_size);
	if (error != 0)
		return error;
	const auto wire_capacity = static_cast<std::uint64_t>(NA_CHANNEL_MAX_MESSAGE_BYTES);
	auto *wire = static_cast<std::uint8_t *>(getAllocator().allocate(wire_capacity));
	if (wire == nullptr)
		return ENOMEM;
	naos::system::ServiceDirectory::resolve_request request{};
	request.uri = {uri, uri_size};
	na_handle_t invocation = NA_HANDLE_INVALID;
	auto transport = make_transport();
	auto client = naos::system::ServiceDirectory::ServiceDirectoryClient(
	    transport.async(), service_directory
	);
	const auto submit_status =
	    client.submit_resolve(request, nullptr, 0, &invocation, wire, wire_capacity);
	if (submit_status != NA_STATUS_OK) {
		getAllocator().deallocate(wire, wire_capacity);
		return status_errno(submit_status);
	}
	error = wait_service_invocation(invocation);
	if (error != 0) {
		_na_handle_close(invocation);
		getAllocator().deallocate(wire, wire_capacity);
		return error;
	}
	naos::system::ServiceDirectory::resolve_response response{};
	na_handle_t response_resources[NA_CHANNEL_MAX_RESOURCES] = {};
	na_result_frame_t result{};
	const auto take_status = client.take_resolve(
	    invocation,
	    response,
	    wire,
	    wire_capacity,
	    response_resources,
	    NA_CHANNEL_MAX_RESOURCES,
	    result
	);
	_na_handle_close(invocation);
	getAllocator().deallocate(wire, wire_capacity);
	if (take_status != NA_STATUS_OK) {
		return status_errno(take_status);
	}
	error = result_errno(result);
	if (error != 0) {
		for (std::uint64_t i = 0; i < result.actual_resources; i++)
			_na_handle_close(response_resources[i]);
		return error;
	}
	if (result.actual_resources != 1 || response.service.value != 0) {
		for (std::uint64_t i = 0; i < result.actual_resources; i++)
			_na_handle_close(response_resources[i]);
		return EIO;
	}
	*handle = response_resources[0];
	return 0;
}

extern "C" int naos_service_listen(
    const char *uri, na_handle_t listener, na_handle_t descriptor, uint64_t max_pending
) {
	const int bootstrap_error = ensure_bootstrap();
	if (bootstrap_error != 0)
		return bootstrap_error;
	std::uint32_t uri_size = 0;
	int error = service_uri(uri, uri_size);
	if (error != 0)
		return error;
	if (listener == NA_HANDLE_INVALID || descriptor == NA_HANDLE_INVALID || max_pending == 0)
		return EINVAL;

	const auto wire_capacity = static_cast<std::uint64_t>(NA_CHANNEL_MAX_MESSAGE_BYTES);
	auto *wire = static_cast<std::uint8_t *>(getAllocator().allocate(wire_capacity));
	if (wire == nullptr)
		return ENOMEM;
	naos::system::ServiceDirectory::listen_request request{};
	request.max_pending = max_pending;
	request.listener.value = 0;
	request.descriptor.value = 1;
	request.uri = {uri, uri_size};
	na_resource_disposition_t dispositions[2]{};
	dispositions[0].handle = listener;
	dispositions[0].operation = NA_RESOURCE_MOVE;
	dispositions[0].rights = NA_RIGHT_TRANSFER;
	dispositions[1].handle = descriptor;
	dispositions[1].operation = NA_RESOURCE_MOVE;
	dispositions[1].rights = NA_RIGHT_TRANSFER;
	na_handle_t invocation = NA_HANDLE_INVALID;
	auto transport = make_transport();
	auto client = naos::system::ServiceDirectory::ServiceDirectoryClient(
	    transport.async(), service_directory
	);
	const auto submit_status =
	    client.submit_listen(request, dispositions, 2, &invocation, wire, wire_capacity);
	if (submit_status != NA_STATUS_OK) {
		getAllocator().deallocate(wire, wire_capacity);
		return status_errno(submit_status);
	}
	error = wait_service_invocation(invocation);
	if (error != 0) {
		_na_handle_close(invocation);
		getAllocator().deallocate(wire, wire_capacity);
		return error;
	}
	naos::system::ServiceDirectory::listen_response response{};
	na_handle_t response_resources[NA_CHANNEL_MAX_RESOURCES] = {};
	na_result_frame_t result{};
	const auto take_status = client.take_listen(
	    invocation,
	    response,
	    wire,
	    wire_capacity,
	    response_resources,
	    NA_CHANNEL_MAX_RESOURCES,
	    result
	);
	_na_handle_close(invocation);
	getAllocator().deallocate(wire, wire_capacity);
	if (take_status != NA_STATUS_OK)
		return status_errno(take_status);
	return result_errno(result);
}

extern "C" int naos_service_connect_versioned(
    const char *uri,
    const na_uuid_t *expected_uuid,
    uint64_t requested_rights,
    uint64_t requested_revision,
    uint64_t requested_features,
    na_handle_t *client
) {
	if (client == nullptr || expected_uuid == nullptr)
		return EFAULT;
	*client = NA_HANDLE_INVALID;
	const int bootstrap_error = ensure_bootstrap();
	if (bootstrap_error != 0)
		return bootstrap_error;
	std::uint32_t uri_size = 0;
	int error = service_uri(uri, uri_size);
	if (error != 0)
		return error;

	const auto wire_capacity = static_cast<std::uint64_t>(NA_CHANNEL_MAX_MESSAGE_BYTES);
	auto *wire = static_cast<std::uint8_t *>(getAllocator().allocate(wire_capacity));
	if (wire == nullptr)
		return ENOMEM;
	naos::system::ServiceDirectory::connect_request request{};
	memcpy(request.expected_uuid.data(), expected_uuid->bytes, sizeof(expected_uuid->bytes));
	request.requested_rights = requested_rights;
	request.uri = {uri, uri_size};
	request.requested_revision = requested_revision;
	request.requested_features = requested_features;
	na_handle_t invocation = NA_HANDLE_INVALID;
	auto transport = make_transport();
	auto service = naos::system::ServiceDirectory::ServiceDirectoryClient(
	    transport.async(), service_directory
	);
	const auto submit_status =
	    service.submit_connect(request, nullptr, 0, &invocation, wire, wire_capacity);
	if (submit_status != NA_STATUS_OK) {
		getAllocator().deallocate(wire, wire_capacity);
		return status_errno(submit_status);
	}
	error = wait_service_invocation(invocation);
	if (error != 0) {
		_na_handle_close(invocation);
		getAllocator().deallocate(wire, wire_capacity);
		return error;
	}
	naos::system::ServiceDirectory::connect_response response{};
	na_handle_t response_resources[NA_CHANNEL_MAX_RESOURCES] = {};
	na_result_frame_t result{};
	const auto take_status = service.take_connect(
	    invocation,
	    response,
	    wire,
	    wire_capacity,
	    response_resources,
	    NA_CHANNEL_MAX_RESOURCES,
	    result
	);
	_na_handle_close(invocation);
	getAllocator().deallocate(wire, wire_capacity);
	if (take_status != NA_STATUS_OK)
		return status_errno(take_status);
	error = result_errno(result);
	if (error != 0) {
		for (std::uint64_t i = 0; i < result.actual_resources; i++)
			_na_handle_close(response_resources[i]);
		return error;
	}
	if (result.actual_resources != 1 || response.client.value != 0) {
		for (std::uint64_t i = 0; i < result.actual_resources; i++)
			_na_handle_close(response_resources[i]);
		return EIO;
	}
	if ((requested_revision != 0 && response.revision != requested_revision)
	    || (response.features & requested_features) != requested_features) {
		_na_handle_close(response_resources[0]);
		return ENOTSUP;
	}
	*client = response_resources[0];
	return 0;
}

extern "C" int naos_service_connect(
    const char *uri, const na_uuid_t *expected_uuid, uint64_t requested_rights, na_handle_t *client
) {
	return naos_service_connect_versioned(uri, expected_uuid, requested_rights, 0, 0, client);
}

extern "C" int naos_service_unregister(const char *uri) {
	const int bootstrap_error = ensure_bootstrap();
	if (bootstrap_error != 0)
		return bootstrap_error;
	std::uint32_t uri_size = 0;
	int error = service_uri(uri, uri_size);
	if (error != 0)
		return error;
	const auto wire_capacity = static_cast<std::uint64_t>(NA_CHANNEL_MAX_MESSAGE_BYTES);
	auto *wire = static_cast<std::uint8_t *>(getAllocator().allocate(wire_capacity));
	if (wire == nullptr)
		return ENOMEM;
	naos::system::ServiceDirectory::unregister_request request{};
	request.uri = {uri, uri_size};
	na_handle_t invocation = NA_HANDLE_INVALID;
	auto transport = make_transport();
	auto client = naos::system::ServiceDirectory::ServiceDirectoryClient(
	    transport.async(), service_directory
	);
	const auto submit_status =
	    client.submit_unregister(request, nullptr, 0, &invocation, wire, wire_capacity);
	if (submit_status != NA_STATUS_OK) {
		getAllocator().deallocate(wire, wire_capacity);
		return status_errno(submit_status);
	}
	error = wait_service_invocation(invocation);
	if (error != 0) {
		_na_handle_close(invocation);
		getAllocator().deallocate(wire, wire_capacity);
		return error;
	}
	naos::system::ServiceDirectory::unregister_response response{};
	na_handle_t response_resources[NA_CHANNEL_MAX_RESOURCES] = {};
	na_result_frame_t result{};
	const auto take_status = client.take_unregister(
	    invocation,
	    response,
	    wire,
	    wire_capacity,
	    response_resources,
	    NA_CHANNEL_MAX_RESOURCES,
	    result
	);
	_na_handle_close(invocation);
	getAllocator().deallocate(wire, wire_capacity);
	if (take_status != NA_STATUS_OK)
		return status_errno(take_status);
	return result_errno(result);
}

extern "C" int naos_handle_close(na_handle_t handle) {
	return naos_syscall_error(_na_handle_close(handle));
}

int native_call(
    na_handle_t target,
    uint64_t method,
    const void *request,
    uint64_t request_bytes,
    call_result &result
) {
	result = {};
	if (request_bytes > NA_CHANNEL_MAX_MESSAGE_BYTES)
		return EOVERFLOW;

	result.bytes = static_cast<uint8_t *>(getAllocator().allocate(result_capacity));
	if (result.bytes == nullptr) {
		return ENOMEM;
	}
	na_submit_frame_t submit{};
	submit.struct_size = sizeof(submit);
	submit.method_id = method;
	submit.request = reinterpret_cast<uint64_t>(request);
	submit.request_bytes = request_bytes;
	submit.resources = 0;
	submit.resource_count = 0;
	result.frame = {};
	result.frame.struct_size = sizeof(result.frame);
	result.frame.bytes = reinterpret_cast<uint64_t>(result.bytes);
	result.frame.byte_capacity = result_capacity;
	result.frame.resources = reinterpret_cast<uint64_t>(result.resources);
	result.frame.resource_capacity = resource_capacity;
	na_handle_t invocation = NA_HANDLE_INVALID;
	auto status = _na_invoke_submit(target, &submit, &invocation);
	if (status != NA_STATUS_OK) {
		destroy_result(result);
		return status_errno(status);
	}
	const int wait_error = wait_service_invocation(invocation);
	if (wait_error != 0) {
		(void)_na_invocation_cancel(invocation);
		(void)_na_handle_close(invocation);
		destroy_result(result);
		return wait_error;
	}
	status = _na_invocation_take_result(invocation, &result.frame);
	(void)_na_handle_close(invocation);
	if (status != NA_STATUS_OK) {
		destroy_result(result);
		return status_errno(status);
	}
	result.byte_count = result.frame.actual_bytes;
	result.resource_count = result.frame.actual_resources;
	const int error = result_errno(result.frame);
	if (error != 0) {
		destroy_result(result);
		return error;
	}
	return 0;
}

void destroy_result(call_result &result) {
	const uint64_t count =
	    result.resource_count > resource_capacity ? resource_capacity : result.resource_count;
	for (uint64_t i = 0; i < count; i++) {
		if (result.resources[i] != NA_HANDLE_INVALID)
			_na_handle_close(result.resources[i]);
	}
	if (result.bytes != nullptr)
		getAllocator().deallocate(result.bytes, result_capacity);
	result = {};
}

na_handle_t directory_for_fd(int dirfd) {
	if (dirfd == AT_FDCWD)
		return current_directory;
	const auto handle = handle_for_fd(dirfd);
	if (handle == NA_HANDLE_INVALID)
		return NA_HANDLE_INVALID;
	na_handle_info_t info{};
	info.struct_size = sizeof(info);
	if (_na_handle_get_info(handle, &info) != NA_STATUS_OK || info.scope != NA_SCOPE_DIRECTORY)
		return NA_HANDLE_INVALID;
	return handle;
}

int open_directory_handle(
    na_handle_t directory, const char *path, uint64_t extra_flags, na_handle_t &handle
) {
	handle = NA_HANDLE_INVALID;
	if (directory == NA_HANDLE_INVALID || path == nullptr)
		return path == nullptr ? EFAULT : EBADF;
	const size_t path_length = strlen(path);
	if (path_length >= 4095)
		return ENAMETOOLONG;
	naos::system::Directory::open_request request{};
	request.mode = 1;
	request.flags = 16 | extra_flags;
	request.path = {
	    reinterpret_cast<const uint8_t *>(path), static_cast<uint32_t>(path_length + 1)
	};
	call_result result;
	const int error = encoded_native_call(
	    directory,
	    NA_METHOD_DIRECTORY_OPEN,
	    request,
	    naos::system::Directory::encode_open_request,
	    result
	);
	if (error != 0)
		return error;
	naos::system::Directory::open_response response{};
	if (!naos::system::Directory::decode_open_response(result.bytes, result.byte_count, response)
	    || response.object.value != 0 || result.resource_count != 1) {
		for (uint64_t i = 0; i < result.resource_count; i++)
			_na_handle_close(result.resources[i]);
		destroy_result(result);
		return EIO;
	}
	handle = result.resources[0];
	result.resources[0] = NA_HANDLE_INVALID;
	destroy_result(result);
	return 0;
}

int update_process_directory(na_handle_t directory, uint64_t method) {
	if (directory == NA_HANDLE_INVALID)
		return EBADF;
	call_result result;
	int error = 0;
	if (method == NA_METHOD_DIRECTORY_SET_CURRENT) {
		naos::system::Directory::set_current_request request{};
		error = encoded_native_call(
		    directory, method, request, naos::system::Directory::encode_set_current_request, result
		);
	} else {
		naos::system::Directory::set_root_request request{};
		error = encoded_native_call(
		    directory, method, request, naos::system::Directory::encode_set_root_request, result
		);
	}
	if (error != 0)
		return error;
	if (result.byte_count != 0 || result.resource_count != 0) {
		destroy_result(result);
		return EIO;
	}
	destroy_result(result);
	return 0;
}

int replace_current_directory(na_handle_t handle) {
	if (handle == NA_HANDLE_INVALID)
		return EBADF;
	lock_fds();
	const auto old = current_directory;
	current_directory = handle;
	unlock_fds();
	if (old != NA_HANDLE_INVALID)
		_na_handle_close(old);
	return 0;
}

int replace_root_directory(na_handle_t handle) {
	if (handle == NA_HANDLE_INVALID)
		return EBADF;
	na_handle_t root = NA_HANDLE_INVALID;
	const auto duplicate_status = _na_handle_duplicate(handle, 0, &root);
	if (duplicate_status != NA_STATUS_OK) {
		_na_handle_close(handle);
		return status_errno(duplicate_status);
	}
	lock_fds();
	const auto old_root = root_directory;
	const auto old_current = current_directory;
	root_directory = root;
	current_directory = handle;
	unlock_fds();
	if (old_root != NA_HANDLE_INVALID)
		_na_handle_close(old_root);
	if (old_current != NA_HANDLE_INVALID)
		_na_handle_close(old_current);
	return 0;
}

int ttyd_open_current_controlling(int flags, int *fd) {
	na_handle_t process = NA_HANDLE_INVALID;
	const auto process_status = _na_process_handle_open(0, &process);
	if (process_status != 0)
		return naos_syscall_error(process_status);
	naos::system::Process::get_controlling_terminal_request request{};
	call_result result{};
	const int error = encoded_native_call(
	    process,
	    NA_METHOD_PROCESS_GET_CONTROLLING_TERMINAL,
	    request,
	    naos::system::Process::encode_get_controlling_terminal_request,
	    result
	);
	(void)_na_handle_close(process);
	if (error != 0)
		return error;
	naos::system::Process::get_controlling_terminal_response response{};
	if (!naos::system::Process::decode_get_controlling_terminal_response(
	        result.bytes, result.byte_count, response
	    )
	    || result.resource_count != 0) {
		destroy_result(result);
		return EIO;
	}
	na_terminal_locator_t locator{};
	locator.terminal_id = response.terminal_id;
	locator.generation = response.generation;
	for (std::size_t i = 0; i < sizeof(locator.token); i++)
		locator.token[i] = response.token[i];
	destroy_result(result);
	return ttyd_open_controlling(locator, flags, fd);
}

int open_path_at(na_handle_t directory, const char *path, int flags, mode_t mode, int *fd) {
	if (path == nullptr)
		return EFAULT;
	const size_t path_length = strlen(path);
	if (path_length >= 4095)
		return ENAMETOOLONG;

	if (strcmp(path, "/dev/ptmx") == 0)
		return ttyd_create_pty(flags, fd);
	if (strcmp(path, "/dev/console") == 0 || strcmp(path, "/dev/tty0") == 0)
		return ttyd_open_console(flags, fd);
	if (strcmp(path, "/dev/tty") == 0) {
		return ttyd_open_current_controlling(flags, fd);
	}
	if (strncmp(path, "/dev/pts/", 9) == 0) {
		const char *cursor = path + 9;
		if (*cursor == 0)
			return ENOENT;
		std::uint32_t number = 0;
		for (; *cursor != 0; cursor++) {
			if (*cursor < '0' || *cursor > '9')
				return ENOENT;
			const auto digit = static_cast<std::uint32_t>(*cursor - '0');
			if (number > (UINT32_MAX - digit) / 10)
				return ENOENT;
			number = number * 10 + digit;
			if (number == 0)
				return ENOENT;
		}
		return ttyd_open_pty_slave(number, flags, fd);
	}

	uint64_t open_mode = 0;
	switch (flags & O_ACCMODE) {
		case O_WRONLY:
			open_mode = 2;
			break;
		case O_RDWR:
			open_mode = 1 | 2;
			break;
		default:
			open_mode = 1;
			break;
	}
	uint64_t attributes = 0;
	if ((flags & O_DIRECTORY) != 0)
		attributes |= 16;
	else if (
	    (flags & O_ACCMODE) != O_RDONLY || (flags & (O_CREAT | O_TRUNC | O_APPEND | O_EXCL)) != 0
	)
		attributes |= 32;
	if (flags & O_CREAT)
		attributes |= 1;
	if (flags & O_TRUNC)
		attributes |= 256;
	if (flags & O_APPEND)
		open_mode |= 8;
	if (flags & O_NONBLOCK)
		open_mode |= 16;
	if (flags & O_EXCL)
		open_mode |= 128;
	if (flags & O_APPEND)
		attributes |= 2048;
	if (flags & O_EXCL)
		attributes |= 4096;
	(void)mode;
	naos::system::Directory::open_request request{};
	request.mode = open_mode;
	request.flags = attributes;
	request.path = {
	    reinterpret_cast<const uint8_t *>(path), static_cast<uint32_t>(path_length + 1)
	};

	call_result result;
	const int error = encoded_native_call(
	    directory,
	    NA_METHOD_DIRECTORY_OPEN,
	    request,
	    naos::system::Directory::encode_open_request,
	    result
	);
	if (error != 0)
		return error;
	naos::system::Directory::open_response response{};
	if (!naos::system::Directory::decode_open_response(result.bytes, result.byte_count, response)
	    || response.object.value != 0 || result.resource_count != 1) {
		for (uint64_t i = 0; i < result.resource_count; i++)
			_na_handle_close(result.resources[i]);
		destroy_result(result);
		return EIO;
	}
	const auto handle = result.resources[0];
	result.resources[0] = NA_HANDLE_INVALID;
	destroy_result(result);
	const int new_fd = allocate_fd(handle, flags, (flags & O_CLOEXEC) != 0 ? FD_CLOEXEC : 0);
	if (new_fd < 0) {
		_na_handle_close(handle);
		return EMFILE;
	}
	*fd = new_fd;
	return 0;
}

int open_path(const char *path, int flags, mode_t mode, int *fd) {
	return open_path_at(current_directory, path, flags, mode, fd);
}

uint64_t count_startup_vector(char *const vector[]) {
	if (vector == nullptr)
		return 0;
	uint64_t count = 0;
	while (vector[count] != nullptr && count < 4096)
		count++;
	return count;
}

int start_process_capability(na_handle_t process) {
	if (process == NA_HANDLE_INVALID)
		return EINVAL;
	naos::system::Process::start_request request{};
	call_result result{};
	const int error = encoded_native_call(
	    process,
	    NA_METHOD_PROCESS_START,
	    request,
	    naos::system::Process::encode_start_request,
	    result
	);
	if (error != 0)
		return error;
	if (result.byte_count != 0 || result.resource_count != 0) {
		destroy_result(result);
		return EIO;
	}
	destroy_result(result);
	return 0;
}

int native_spawn_stdio_with_capabilities(
    pid_t *pid,
    const char *path,
    char *const argv[],
    char *const envp[],
    int stdin_fd,
    int stdout_fd,
    int stderr_fd,
	const na_bootstrap_capability_t *capabilities,
	uint32_t capability_count,
	uint64_t service_rights,
	na_handle_t *deferred_process
) {
	auto close_private_caps = [&] {
		const uint32_t count = capability_count > NA_BOOTSTRAP_MAX_CAPABILITIES
		                           ? NA_BOOTSTRAP_MAX_CAPABILITIES
		                           : capability_count;
		for (uint32_t i = 0; i < count; i++) {
			if (capabilities != nullptr && capabilities[i].handle != NA_HANDLE_INVALID)
				_na_handle_close(capabilities[i].handle);
		}
	};
	if (deferred_process != nullptr)
		*deferred_process = NA_HANDLE_INVALID;
	if (pid == nullptr || path == nullptr || capability_count > NA_BOOTSTRAP_MAX_CAPABILITIES ||
	    (capability_count != 0 && capabilities == nullptr)) {
		close_private_caps();
		return EFAULT;
	}
	for (uint32_t i = 0; i < capability_count; i++) {
		if (capabilities[i].kind == 0 || capabilities[i].handle == NA_HANDLE_INVALID) {
			close_private_caps();
			return EINVAL;
		}
		for (uint32_t j = 0; j < i; j++) {
			if (capabilities[j].kind == capabilities[i].kind || capabilities[j].handle == capabilities[i].handle) {
				close_private_caps();
				return EINVAL;
			}
		}
	}
	const int bootstrap_error = ensure_bootstrap();
	if (bootstrap_error != 0) {
		close_private_caps();
		return bootstrap_error;
	}

	int executable_fd = -1;
	int error = open_path(path, O_RDONLY, 0, &executable_fd);
	if (error != 0) {
		close_private_caps();
		return error;
	}
	const auto source = handle_for_fd(executable_fd);
	na_handle_t executable = NA_HANDLE_INVALID;
	const auto duplicate_status = _na_handle_duplicate(source, 0, &executable);
	const int close_error = close_fd(executable_fd);
	if (duplicate_status != NA_STATUS_OK) {
		close_private_caps();
		if (close_error != 0)
			return close_error;
		return status_errno(duplicate_status);
	}
	if (close_error != 0) {
		close_private_caps();
		_na_handle_close(executable);
		return close_error;
	}

	const na_handle_t stdio_handles[3] = {
	    handle_for_fd(stdin_fd),
	    handle_for_fd(stdout_fd),
	    handle_for_fd(stderr_fd),
	};
	if (stdio_handles[0] == NA_HANDLE_INVALID || stdio_handles[1] == NA_HANDLE_INVALID
	    || stdio_handles[2] == NA_HANDLE_INVALID) {
		close_private_caps();
		_na_handle_close(executable);
		return EBADF;
	}
	na_handle_t stdio_duplicates[3] = {NA_HANDLE_INVALID, NA_HANDLE_INVALID, NA_HANDLE_INVALID};
	uint32_t stdio_resource_indices[3] = {};
	uint32_t stdio_resource_count = NA_BOOTSTRAP_RESOURCE_STDIN;
	bool stdio_terminal[3] = {};
	bool stdio_master[3] = {};
	for (uint32_t i = 0; i < 3; i++) {
		stdio_terminal[i] = terminal_handle_scope(stdio_handles[i], stdio_master[i]);
		bool shared_terminal_binding = false;
		for (uint32_t previous = 0; previous < i; previous++) {
			if (stdio_terminal[i] && stdio_terminal[previous]
			    && stdio_handles[i] == stdio_handles[previous]) {
				stdio_resource_indices[i] = stdio_resource_indices[previous];
				shared_terminal_binding = true;
				break;
			}
		}
		if (shared_terminal_binding)
			continue;
		const int duplicate_error =
		    stdio_terminal[i]
		        ? terminal_clone_binding(
		              stdio_handles[i], stdio_master[i], stdio_duplicates[i], true
		          )
		        : status_errno(_na_handle_duplicate(stdio_handles[i], 0, &stdio_duplicates[i]));
		if (duplicate_error != 0) {
			close_private_caps();
			for (uint32_t j = 0; j < i; j++) {
				if (stdio_duplicates[j] != NA_HANDLE_INVALID)
					_na_handle_close(stdio_duplicates[j]);
			}
			_na_handle_close(executable);
			return duplicate_error;
		}
		stdio_resource_indices[i] = stdio_resource_count++;
	}
	auto close_stdio_duplicates = [&] {
		for (uint32_t i = 0; i < 3; i++) {
			if (stdio_duplicates[i] != NA_HANDLE_INVALID)
				_na_handle_close(stdio_duplicates[i]);
		}
	};

	na_handle_t parent_endpoint = NA_HANDLE_INVALID;
	na_handle_t child_endpoint = NA_HANDLE_INVALID;
	uint64_t status = _na_channel_create(nullptr, &parent_endpoint, &child_endpoint);
	if (status != NA_STATUS_OK) {
		close_private_caps();
		close_stdio_duplicates();
		_na_handle_close(executable);
		return status_errno(status);
	}

	na_handle_t process = NA_HANDLE_INVALID;
	uint64_t native_pid = 0;
	na_process_spawn_frame_t spawn{};
	spawn.struct_size = sizeof(spawn);
	if (deferred_process != nullptr)
		spawn.flags = NA_PROCESS_SPAWN_DEFERRED_START;
	spawn.executable = executable;
	spawn.bootstrap_endpoint = child_endpoint;
	spawn.path = reinterpret_cast<uint64_t>(path);
	spawn.argv = reinterpret_cast<uint64_t>(argv);
	spawn.envp = reinterpret_cast<uint64_t>(envp);
	spawn.process = reinterpret_cast<uint64_t>(&process);
	spawn.pid = reinterpret_cast<uint64_t>(&native_pid);
	const int64_t spawn_status = _na_process_spawn(&spawn);
	if (spawn_status != 0) {
		close_private_caps();
		close_stdio_duplicates();
		_na_handle_close(executable);
		_na_handle_close(child_endpoint);
		_na_handle_close(parent_endpoint);
		return naos_syscall_error(spawn_status);
	}

	// The registry capability is an independent bootstrap decision. Every
	// child receives a restricted view; a terminal service manager receives
	// only the system-namespace mutation right, never generic admin access.
	na_handle_t service_for_child = NA_HANDLE_INVALID;
	na_handle_t attenuated_service_source = NA_HANDLE_INVALID;
	if (_na_handle_duplicate(service_directory, 0, &attenuated_service_source) != NA_STATUS_OK) {
		close_private_caps();
		_na_handle_close(parent_endpoint);
		(void)start_process_capability(process);
		_na_handle_close(process);
		_na_handle_close(executable);
		close_stdio_duplicates();
		return EACCES;
	}
	na_handle_restriction_t restriction{};
	restriction.struct_size = sizeof(restriction);
	restriction.flags = NA_RESTRICTION_PROTOCOL_RIGHTS;
	restriction.protocol_rights = NA_PROTOCOL_RIGHT_INVOKE | service_rights;
	if (_na_handle_restrict(attenuated_service_source, &restriction, &service_for_child)
	    != NA_STATUS_OK) {
		close_private_caps();
		_na_handle_close(attenuated_service_source);
		_na_handle_close(parent_endpoint);
		(void)start_process_capability(process);
		_na_handle_close(process);
		_na_handle_close(executable);
		close_stdio_duplicates();
		return EACCES;
	}

	na_bootstrap_message_t message{};
	message.struct_size = sizeof(message);
	message.version = NA_BOOTSTRAP_MESSAGE_VERSION;
	uint32_t private_resource_count = stdio_resource_count;
	message.capability_count = capability_count;
	for (uint32_t i = 0; i < capability_count; i++) {
		message.capabilities[i].kind = capabilities[i].kind;
		message.capabilities[i].resource = private_resource_count++;
	}
	message.resource_count = private_resource_count;
	message.root_directory = NA_BOOTSTRAP_RESOURCE_ROOT_DIRECTORY;
	message.current_directory = NA_BOOTSTRAP_RESOURCE_CURRENT_DIRECTORY;
	message.service_directory = NA_BOOTSTRAP_RESOURCE_SERVICE_DIRECTORY;
	message.stdin_stream = stdio_resource_indices[0];
	message.stdout_stream = stdio_resource_indices[1];
	message.stderr_stream = stdio_resource_indices[2];
	message.argc = count_startup_vector(argv);
	message.envc = count_startup_vector(envp);
	na_resource_disposition_t dispositions[NA_BOOTSTRAP_RESOURCE_COUNT + NA_BOOTSTRAP_MAX_CAPABILITIES]{};
	na_handle_t resources[NA_BOOTSTRAP_RESOURCE_COUNT + NA_BOOTSTRAP_MAX_CAPABILITIES] = {
	    root_directory,
	    current_directory,
	    service_for_child,
	};
	for (uint32_t i = 0; i < 3; i++) {
		if (stdio_duplicates[i] != NA_HANDLE_INVALID)
			resources[stdio_resource_indices[i]] = stdio_duplicates[i];
	}
	for (uint32_t i = 0; i < capability_count; i++)
		resources[message.capabilities[i].resource] = capabilities[i].handle;
	for (uint32_t i = 0; i < message.resource_count; i++) {
		dispositions[i].handle = resources[i];
		dispositions[i].operation =
		    i < NA_BOOTSTRAP_RESOURCE_STDIN ? NA_RESOURCE_DUPLICATE : NA_RESOURCE_MOVE;
	}
	na_channel_send_frame send{};
	send.struct_size = sizeof(send);
	send.bytes = reinterpret_cast<uint64_t>(&message);
	send.byte_count = sizeof(message);
	send.resources = reinterpret_cast<uint64_t>(dispositions);
	send.resource_count = message.resource_count;
	status = _na_channel_send(parent_endpoint, &send);
	_na_handle_close(parent_endpoint);
	if (service_for_child != NA_HANDLE_INVALID)
		_na_handle_close(service_for_child);
	if (attenuated_service_source != NA_HANDLE_INVALID)
		_na_handle_close(attenuated_service_source);
	if (status != NA_STATUS_OK) {
		close_private_caps();
		close_stdio_duplicates();
		(void)start_process_capability(process);
		_na_handle_close(process);
		return status_errno(status);
	}
	if (deferred_process != nullptr)
		*deferred_process = process;
	else
		_na_handle_close(process);
	*pid = static_cast<pid_t>(native_pid);
	return 0;
}

extern "C" int naos_native_spawn_stdio(
    pid_t *pid,
    const char *path,
    char *const argv[],
    char *const envp[],
    int stdin_fd,
    int stdout_fd,
    int stderr_fd
) {
	return native_spawn_stdio_with_capabilities(
	    pid,
	    path,
	    argv,
	    envp,
	    stdin_fd,
	    stdout_fd,
	    stderr_fd,
	    nullptr,
	    0,
	    0,
	    nullptr
	);
}

extern "C" int naos_native_spawn_stdio_deferred(
    pid_t *pid,
    na_handle_t *process,
    const char *path,
    char *const argv[],
    char *const envp[],
    int stdin_fd,
    int stdout_fd,
    int stderr_fd
) {
	return native_spawn_stdio_with_capabilities(
	    pid,
	    path,
	    argv,
	    envp,
	    stdin_fd,
	    stdout_fd,
	    stderr_fd,
	    nullptr,
	    0,
	    0,
	    process
	);
}

extern "C" int naos_native_start_process(na_handle_t process) {
	return start_process_capability(process);
}

extern "C" int naos_native_spawn_with_terminal_factory(
    pid_t *pid, const char *path, char *const argv[], char *const envp[], na_handle_t factory_handle
) {
	const na_bootstrap_capability_t capability = {NA_BOOTSTRAP_CAPABILITY_TERMINAL_DRIVER_FACTORY, factory_handle};
	return native_spawn_stdio_with_capabilities(
	    pid,
	    path,
	    argv,
	    envp,
	    STDIN,
	    STDOUT,
	    STDERR,
	    &capability,
	    1,
	    0,
	    nullptr
	);
}

extern "C" int naos_native_spawn_with_terminal_factory_and_service_manager(
    pid_t *pid, const char *path, char *const argv[], char *const envp[], na_handle_t factory_handle
) {
	const na_bootstrap_capability_t capability = {NA_BOOTSTRAP_CAPABILITY_TERMINAL_DRIVER_FACTORY, factory_handle};
	return native_spawn_stdio_with_capabilities(
	    pid,
	    path,
	    argv,
	    envp,
	    STDIN,
	    STDOUT,
	    STDERR,
	    &capability,
	    1,
	    NA_SERVICE_DIRECTORY_RIGHT_SYSTEM_MANAGER,
	    nullptr
	);
}

extern "C" int naos_native_spawn_with_capabilities(
    pid_t *pid,
    const char *path,
    char *const argv[],
    char *const envp[],
    const na_bootstrap_capability_t *capabilities,
    uint32_t capability_count
) {
	return native_spawn_stdio_with_capabilities(
	    pid,
	    path,
	    argv,
	    envp,
	    STDIN,
	    STDOUT,
	    STDERR,
	    capabilities,
	    capability_count,
	    0,
	    nullptr
	);
}

extern "C" int
naos_native_spawn(pid_t *pid, const char *path, char *const argv[], char *const envp[]) {
	return naos_native_spawn_stdio(pid, path, argv, envp, STDIN, STDOUT, STDERR);
}

int directory_value_call(
    na_handle_t directory, uint64_t method, uint64_t value, const char *path, call_result &result
) {
	if (directory == NA_HANDLE_INVALID || path == nullptr)
		return path == nullptr ? EFAULT : EBADF;
	const size_t length = strlen(path);
	if (length >= 4095)
		return ENAMETOOLONG;
	if (method == NA_METHOD_DIRECTORY_ACCESS) {
		naos::system::Directory::access_request request{};
		request.mode = value;
		request.path = {reinterpret_cast<const uint8_t *>(path), static_cast<uint32_t>(length + 1)};
		return encoded_native_call(
		    directory, method, request, naos::system::Directory::encode_access_request, result
		);
	}
	naos::system::Directory::create_request request{};
	request.mode = value;
	request.flags = 1;
	request.path = {reinterpret_cast<const uint8_t *>(path), static_cast<uint32_t>(length + 1)};
	return encoded_native_call(
	    directory, method, request, naos::system::Directory::encode_create_request, result
	);
}

int directory_pair_call(
    na_handle_t directory,
    uint64_t method,
    const char *first,
    const char *second,
    call_result &result
) {
	if (directory == NA_HANDLE_INVALID || first == nullptr || second == nullptr)
		return first == nullptr || second == nullptr ? EFAULT : EBADF;
	const size_t first_length = strlen(first);
	const size_t second_length = strlen(second);
	if (first_length >= 4095 || second_length >= 4095
	    || first_length + second_length + 16 > NA_CHANNEL_MAX_MESSAGE_BYTES)
		return ENAMETOOLONG;
	if (method == NA_METHOD_DIRECTORY_RENAME) {
		naos::system::Directory::rename_request request{};
		request.first_size = first_length;
		request.second_size = second_length;
		request.first = {
		    reinterpret_cast<const uint8_t *>(first), static_cast<uint32_t>(first_length)
		};
		request.second = {
		    reinterpret_cast<const uint8_t *>(second), static_cast<uint32_t>(second_length)
		};
		return encoded_native_call(
		    directory, method, request, naos::system::Directory::encode_rename_request, result
		);
	}
	if (method == NA_METHOD_DIRECTORY_LINK) {
		naos::system::Directory::link_request request{};
		request.first_size = first_length;
		request.second_size = second_length;
		request.first = {
		    reinterpret_cast<const uint8_t *>(first), static_cast<uint32_t>(first_length)
		};
		request.second = {
		    reinterpret_cast<const uint8_t *>(second), static_cast<uint32_t>(second_length)
		};
		return encoded_native_call(
		    directory, method, request, naos::system::Directory::encode_link_request, result
		);
	}
	naos::system::Directory::symlink_request request{};
	request.first_size = first_length;
	request.second_size = second_length;
	request.first = {reinterpret_cast<const uint8_t *>(first), static_cast<uint32_t>(first_length)};
	request.second = {
	    reinterpret_cast<const uint8_t *>(second), static_cast<uint32_t>(second_length)
	};
	return encoded_native_call(
	    directory, method, request, naos::system::Directory::encode_symlink_request, result
	);
}

int directory_readlink_call(na_handle_t directory, const char *path, call_result &result) {
	if (directory == NA_HANDLE_INVALID || path == nullptr)
		return path == nullptr ? EFAULT : EBADF;
	const size_t length = strlen(path);
	if (length == 0 || length >= 4095)
		return ENAMETOOLONG;
	naos::system::Directory::readlink_request request{};
	request.size = length;
	request.path = {reinterpret_cast<const uint8_t *>(path), static_cast<uint32_t>(length)};
	return encoded_native_call(
	    directory,
	    NA_METHOD_DIRECTORY_READLINK,
	    request,
	    naos::system::Directory::encode_readlink_request,
	    result
	);
}

int set_file_flags(na_handle_t file, int flags) {
	naos::system::File::set_flags_request request{};
	uint64_t wire_flags = 0;
	if ((flags & O_NONBLOCK) != 0)
		wire_flags |= NA_IO_FLAG_NONBLOCK;
	if ((flags & O_APPEND) != 0)
		wire_flags |= NA_IO_FLAG_APPEND;
	request.flags = wire_flags;
	call_result result;
	const int error = encoded_native_call(
	    file,
	    NA_METHOD_FILE_SET_FLAGS,
	    request,
	    naos::system::File::encode_set_flags_request,
	    result
	);
	destroy_result(result);
	return error;
}

int file_value_call(
    na_handle_t file,
    uint64_t method,
    uint64_t first,
    uint64_t second,
    bool two_values,
    bool empty_request = false
) {
	(void)two_values;
	(void)empty_request;
	call_result result;
	int error = 0;
	if (method == NA_METHOD_FILE_TRUNCATE) {
		naos::system::File::truncate_request request{first};
		error = encoded_native_call(
		    file, method, request, naos::system::File::encode_truncate_request, result
		);
	} else if (method == NA_METHOD_FILE_ALLOCATE) {
		naos::system::File::allocate_request request{first, second};
		error = encoded_native_call(
		    file, method, request, naos::system::File::encode_allocate_request, result
		);
	} else {
		naos::system::File::sync_request request{};
		error = encoded_native_call(
		    file, method, request, naos::system::File::encode_sync_request, result
		);
	}
	destroy_result(result);
	return error;
}

int file_seek_call(na_handle_t file, off_t offset, int whence, off_t *new_offset) {
	if (file == NA_HANDLE_INVALID || new_offset == nullptr)
		return new_offset == nullptr ? EFAULT : EBADF;

	uint64_t native_whence = 0;
	switch (whence) {
		case SEEK_SET:
			native_whence = LSEEK_MODE_BEGIN;
			break;
		case SEEK_CUR:
			native_whence = LSEEK_MODE_CURRENT;
			break;
		case SEEK_END:
			native_whence = LSEEK_MODE_END;
			break;
		default:
			return EINVAL;
	}

	naos::system::File::seek_request request{};
	request.offset = offset;
	request.whence = native_whence;
	call_result result;
	const int error = encoded_native_call(
	    file, NA_METHOD_FILE_SEEK, request, naos::system::File::encode_seek_request, result
	);
	if (error != 0)
		return error;
	naos::system::File::seek_response response{};
	if (!naos::system::File::decode_seek_response(result.bytes, result.byte_count, response)) {
		destroy_result(result);
		return EIO;
	}
	*new_offset = static_cast<off_t>(response.offset);
	destroy_result(result);
	return 0;
}

int file_pread_call(na_handle_t file, void *buf, size_t n, off_t offset, ssize_t *bytes_read) {
	if (file == NA_HANDLE_INVALID)
		return EBADF;
	naos::system::File::pread_request request{};
	request.offset = offset;
	request.size = n;
	request.flags = 0;
	call_result result;
	const int error = encoded_native_call(
	    file, NA_METHOD_FILE_PREAD, request, naos::system::File::encode_pread_request, result
	);
	if (error != 0)
		return error;
	naos::system::File::pread_response response{};
	if (!naos::system::File::decode_pread_response(result.bytes, result.byte_count, response)
	    || response.data.size > n) {
		destroy_result(result);
		return EIO;
	}
	memcpy(buf, response.data.data, response.data.size);
	*bytes_read = static_cast<ssize_t>(response.data.size);
	destroy_result(result);
	return 0;
}

int file_pwrite_call(
    na_handle_t file, const void *buf, size_t n, off_t offset, ssize_t *bytes_written
) {
	if (file == NA_HANDLE_INVALID)
		return EBADF;
	if (n > NA_CHANNEL_MAX_MESSAGE_BYTES - 24)
		return EOVERFLOW;
	naos::system::File::pwrite_request request{};
	request.offset = offset;
	request.size = n;
	request.flags = 0;
	request.data = {static_cast<const uint8_t *>(buf), static_cast<uint32_t>(n)};
	call_result result;
	const int error = encoded_native_call(
	    file, NA_METHOD_FILE_PWRITE, request, naos::system::File::encode_pwrite_request, result
	);
	if (error != 0)
		return error;
	naos::system::File::pwrite_response response{};
	if (!naos::system::File::decode_pwrite_response(result.bytes, result.byte_count, response)
	    || response.count > n) {
		destroy_result(result);
		return EIO;
	}
	*bytes_written = static_cast<ssize_t>(response.count);
	destroy_result(result);
	return 0;
}

int file_read_call(na_handle_t file, void *buf, size_t n, ssize_t *bytes_read) {
	if (file == NA_HANDLE_INVALID)
		return EBADF;
	if (n > NA_CHANNEL_MAX_MESSAGE_BYTES - 16)
		return EOVERFLOW;
	naos::system::File::read_request request{};
	request.size = n;
	call_result result;
	const int error = encoded_native_call(
	    file, NA_METHOD_FILE_READ, request, naos::system::File::encode_read_request, result
	);
	if (error != 0)
		return error;
	naos::system::File::read_response response{};
	if (!naos::system::File::decode_read_response(result.bytes, result.byte_count, response)
	    || response.data.size > n) {
		destroy_result(result);
		return EIO;
	}
	memcpy(buf, response.data.data, response.data.size);
	*bytes_read = static_cast<ssize_t>(response.data.size);
	destroy_result(result);
	return 0;
}

int
file_write_call(na_handle_t file, const void *buf, size_t n, int flags, ssize_t *bytes_written) {
	if (file == NA_HANDLE_INVALID)
		return EBADF;
	if (n > NA_CHANNEL_MAX_MESSAGE_BYTES - 16)
		return EOVERFLOW;
	naos::system::File::write_request request{};
	request.size = n;
	if ((flags & O_NONBLOCK) != 0)
		request.flags |= NA_IO_FLAG_NONBLOCK;
	request.data = {static_cast<const uint8_t *>(buf), static_cast<uint32_t>(n)};
	call_result result;
	const int error = encoded_native_call(
	    file, NA_METHOD_FILE_WRITE, request, naos::system::File::encode_write_request, result
	);
	if (error != 0)
		return error;
	naos::system::File::write_response response{};
	if (!naos::system::File::decode_write_response(result.bytes, result.byte_count, response)
	    || response.count > n) {
		destroy_result(result);
		return EIO;
	}
	*bytes_written = static_cast<ssize_t>(response.count);
	destroy_result(result);
	return 0;
}

template <typename Layout>
int prepare_iovecs(const struct iovec *iovs, int iovc, Layout &layout, uint64_t &total) {
	if (iovc < 0 || iovc > static_cast<int>(layout.lengths.size()))
		return EINVAL;
	if (iovc != 0 && iovs == nullptr)
		return EFAULT;
	layout.segment_count = static_cast<uint64_t>(iovc);
	total = 0;
	for (int i = 0; i < iovc; i++) {
		if (iovs[i].iov_len != 0 && iovs[i].iov_base == nullptr)
			return EFAULT;
		if (iovs[i].iov_len > NA_CHANNEL_MAX_MESSAGE_BYTES
		    || total > NA_CHANNEL_MAX_MESSAGE_BYTES - iovs[i].iov_len)
			return EOVERFLOW;
		layout.lengths[static_cast<size_t>(i)] = iovs[i].iov_len;
		total += iovs[i].iov_len;
	}
	for (size_t i = static_cast<size_t>(iovc); i < layout.lengths.size(); i++)
		layout.lengths[i] = 0;
	return 0;
}

template <typename BoundedBytes>
int scatter_iovecs(const BoundedBytes &data, const struct iovec *iovs, int iovc, ssize_t *bytes) {
	if (bytes == nullptr || iovc < 0 || (iovc != 0 && iovs == nullptr))
		return EFAULT;
	if (data.size > NA_CHANNEL_MAX_MESSAGE_BYTES)
		return EIO;
	size_t capacity = 0;
	for (int i = 0; i < iovc; i++) {
		if (capacity > SIZE_MAX - iovs[i].iov_len)
			return EIO;
		capacity += iovs[i].iov_len;
	}
	if (data.size > capacity)
		return EIO;
	size_t remaining = data.size;
	const uint8_t *source = data.data;
	for (int i = 0; i < iovc && remaining != 0; i++) {
		const size_t amount = remaining < iovs[i].iov_len ? remaining : iovs[i].iov_len;
		if (amount != 0)
			memcpy(iovs[i].iov_base, source, amount);
		source += amount;
		remaining -= amount;
	}
	*bytes = static_cast<ssize_t>(data.size);
	return 0;
}

int file_readv_call(
    na_handle_t file,
    const struct iovec *iovs,
    int iovc,
    bool positioned,
    off_t offset,
    ssize_t *bytes_read
) {
	if (file == NA_HANDLE_INVALID)
		return EBADF;
	naos::system::File::IOVLayout layout{};
	uint64_t total = 0;
	int error = prepare_iovecs(iovs, iovc, layout, total);
	if (error != 0)
		return error;
	call_result result{};
	if (positioned) {
		naos::system::File::preadv_request request{};
		request.offset = offset;
		request.layout = layout;
		request.size = total;
		error = encoded_native_call(
		    file, NA_METHOD_FILE_PREADV, request, naos::system::File::encode_preadv_request, result
		);
		if (error != 0)
			return error;
		naos::system::File::preadv_response response{};
		if (!naos::system::File::decode_preadv_response(
		        result.bytes, result.byte_count, response
		    )) {
			destroy_result(result);
			return EIO;
		}
		error = scatter_iovecs(response.data, iovs, iovc, bytes_read);
	} else {
		naos::system::File::readv_request request{};
		request.layout = layout;
		request.size = total;
		error = encoded_native_call(
		    file, NA_METHOD_FILE_READV, request, naos::system::File::encode_readv_request, result
		);
		if (error != 0)
			return error;
		naos::system::File::readv_response response{};
		if (!naos::system::File::decode_readv_response(result.bytes, result.byte_count, response)) {
			destroy_result(result);
			return EIO;
		}
		error = scatter_iovecs(response.data, iovs, iovc, bytes_read);
	}
	destroy_result(result);
	return error;
}

int file_writev_call(
    na_handle_t file,
    const struct iovec *iovs,
    int iovc,
    bool positioned,
    off_t offset,
    int flags,
    ssize_t *bytes_written
) {
	if (file == NA_HANDLE_INVALID)
		return EBADF;
	naos::system::File::IOVLayout layout{};
	uint64_t total = 0;
	int error = prepare_iovecs(iovs, iovc, layout, total);
	if (error != 0)
		return error;
	uint8_t *packed = nullptr;
	if (total != 0) {
		packed = static_cast<uint8_t *>(getAllocator().allocate(total));
		if (packed == nullptr)
			return ENOMEM;
		size_t cursor = 0;
		for (int i = 0; i < iovc; i++) {
			if (iovs[i].iov_len != 0) {
				memcpy(packed + cursor, iovs[i].iov_base, iovs[i].iov_len);
				cursor += iovs[i].iov_len;
			}
		}
	}
	call_result result{};
	if (positioned) {
		naos::system::File::pwritev_request request{};
		request.offset = offset;
		request.layout = layout;
		request.size = total;
		request.flags = (flags & O_NONBLOCK) != 0 ? NA_IO_FLAG_NONBLOCK : 0;
		request.data = {packed, static_cast<uint32_t>(total)};
		error = encoded_native_call(
		    file,
		    NA_METHOD_FILE_PWRITEV,
		    request,
		    naos::system::File::encode_pwritev_request,
		    result
		);
		if (error == 0) {
			naos::system::File::pwritev_response response{};
			if (!naos::system::File::decode_pwritev_response(
			        result.bytes, result.byte_count, response
			    )
			    || response.count > total)
				error = EIO;
			else
				*bytes_written = static_cast<ssize_t>(response.count);
		}
	} else {
		naos::system::File::writev_request request{};
		request.layout = layout;
		request.size = total;
		request.flags = (flags & O_NONBLOCK) != 0 ? NA_IO_FLAG_NONBLOCK : 0;
		request.data = {packed, static_cast<uint32_t>(total)};
		error = encoded_native_call(
		    file, NA_METHOD_FILE_WRITEV, request, naos::system::File::encode_writev_request, result
		);
		if (error == 0) {
			naos::system::File::writev_response response{};
			if (!naos::system::File::decode_writev_response(
			        result.bytes, result.byte_count, response
			    )
			    || response.count > total)
				error = EIO;
			else
				*bytes_written = static_cast<ssize_t>(response.count);
		}
	}
	if (packed != nullptr)
		getAllocator().deallocate(packed, total);
	destroy_result(result);
	return error;
}

int stream_readv_call(
    na_handle_t stream, const struct iovec *iovs, int iovc, int flags, ssize_t *bytes_read
) {
	if (stream == NA_HANDLE_INVALID)
		return EBADF;
	naos::system::Stream::IOVLayout layout{};
	uint64_t total = 0;
	int error = prepare_iovecs(iovs, iovc, layout, total);
	if (error != 0)
		return error;
	naos::system::Stream::readv_request request{};
	request.layout = layout;
	request.size = total;
	request.flags = (flags & O_NONBLOCK) != 0 ? NA_IO_FLAG_NONBLOCK : 0;
	call_result result{};
	error = encoded_native_call(
	    stream, NA_METHOD_STREAM_READV, request, naos::system::Stream::encode_readv_request, result
	);
	if (error == 0) {
		naos::system::Stream::readv_response response{};
		if (!naos::system::Stream::decode_readv_response(result.bytes, result.byte_count, response))
			error = EIO;
		else
			error = scatter_iovecs(response.data, iovs, iovc, bytes_read);
	}
	destroy_result(result);
	return error;
}

int stream_writev_call(
    na_handle_t stream, const struct iovec *iovs, int iovc, int flags, ssize_t *bytes_written
) {
	if (stream == NA_HANDLE_INVALID)
		return EBADF;
	naos::system::Stream::IOVLayout layout{};
	uint64_t total = 0;
	int error = prepare_iovecs(iovs, iovc, layout, total);
	if (error != 0)
		return error;
	uint8_t *packed = nullptr;
	if (total != 0) {
		packed = static_cast<uint8_t *>(getAllocator().allocate(total));
		if (packed == nullptr)
			return ENOMEM;
		size_t cursor = 0;
		for (int i = 0; i < iovc; i++) {
			if (iovs[i].iov_len != 0) {
				memcpy(packed + cursor, iovs[i].iov_base, iovs[i].iov_len);
				cursor += iovs[i].iov_len;
			}
		}
	}
	naos::system::Stream::writev_request request{};
	request.layout = layout;
	request.size = total;
	request.flags = (flags & O_NONBLOCK) != 0 ? NA_IO_FLAG_NONBLOCK : 0;
	request.data = {packed, static_cast<uint32_t>(total)};
	call_result result{};
	error = encoded_native_call(
	    stream,
	    NA_METHOD_STREAM_WRITEV,
	    request,
	    naos::system::Stream::encode_writev_request,
	    result
	);
	if (error == 0) {
		naos::system::Stream::writev_response response{};
		if (!naos::system::Stream::decode_writev_response(result.bytes, result.byte_count, response)
		    || response.count > total)
			error = EIO;
		else
			*bytes_written = static_cast<ssize_t>(response.count);
	}
	if (packed != nullptr)
		getAllocator().deallocate(packed, total);
	destroy_result(result);
	return error;
}

} // namespace naos_native

extern "C" int
naos_native_preadv(int fd, const struct iovec *iovs, int iovc, off_t offset, ssize_t *bytes_read) {
	if (bytes_read == nullptr)
		return EFAULT;
	const auto slot = naos_native::slot_for_fd(fd);
	if (slot.handle == NA_HANDLE_INVALID)
		return EBADF;
	if (slot.kind != naos_native::descriptor_kind::file)
		return ESPIPE;
	return naos_native::file_readv_call(slot.handle, iovs, iovc, true, offset, bytes_read);
}

extern "C" int naos_native_pwritev(
    int fd, const struct iovec *iovs, int iovc, off_t offset, ssize_t *bytes_written
) {
	if (bytes_written == nullptr)
		return EFAULT;
	const auto slot = naos_native::slot_for_fd(fd);
	if (slot.handle == NA_HANDLE_INVALID)
		return EBADF;
	if (slot.kind != naos_native::descriptor_kind::file)
		return ESPIPE;
	return naos_native::file_writev_call(
	    slot.handle, iovs, iovc, true, offset, slot.flags, bytes_written
	);
}

void Sysdeps<LibcLog>::operator()(const char *message) { _s_log(message); }

[[noreturn]] void Sysdeps<LibcPanic>::operator()() {
	Sysdeps<LibcLog>::operator()("panic");
	while (true) {
		_s_exit(-1);
	}
}

[[noreturn]] void Sysdeps<Exit>::operator()(int status) { _s_exit(status); }
int Sysdeps<ClockGet>::operator()(int clock, time_t *secs, long *nanos) {
	na_time_clock_t c;
	if (int ret = _s_clock(clock, &c); ret != 0) {
		return naos_syscall_error(ret);
	}
	*secs = c.tv_sec;
	*nanos = c.tv_nsec;
	return 0;
}

int Sysdeps<TcbSet>::operator()(void *pointer) { return naos_syscall_error(_s_tcb_set(pointer)); }

pid_t Sysdeps<FutexTid>::operator()() { return 1; }
int Sysdeps<FutexWait>::operator()(int *pointer, int expected, const struct timespec *time) {
	na_time_clock_t c;
	if (time != nullptr) {
		c.tv_sec = time->tv_sec;
		c.tv_nsec = time->tv_nsec;
		return naos_syscall_error(_s_futex(pointer, FUTEX_WAIT, expected, &c));
	} else {
		return naos_syscall_error(_s_futex(pointer, FUTEX_WAIT, expected, nullptr));
	}
}
int Sysdeps<FutexWake>::operator()(int *pointer, bool all) {
	return naos_syscall_error(_s_futex(pointer, FUTEX_WAKE, all ? INT_MAX : 1, nullptr));
}

int Sysdeps<AnonAllocate>::operator()(size_t size, void **pointer) {
	na_memory_map_frame_t frame{};
	frame.struct_size = sizeof(frame);
	frame.flags = NA_MEMORY_MAP_READ | NA_MEMORY_MAP_WRITE;
	frame.object = NA_HANDLE_INVALID;
	frame.length = size;
	const auto status = _na_memory_map(&frame);
	if (status != NA_STATUS_OK)
		return naos_native::status_errno(status);
	*pointer = reinterpret_cast<void *>(frame.address);
	return 0;
}

int Sysdeps<AnonFree>::operator()(void *pointer, size_t size) {
	na_memory_unmap_frame_t frame{};
	frame.struct_size = sizeof(frame);
	frame.address = reinterpret_cast<uint64_t>(pointer);
	frame.length = size;
	return naos_native::status_errno(_na_memory_unmap(&frame));
}

int Sysdeps<Open>::operator()(const char *pathname, int flags, mode_t mode, int *fd) {
	return naos_native::open_path(pathname, flags, mode, fd);
}

int Sysdeps<Pipe>::operator()(int *fds, int flags) {
	if (fds == nullptr)
		return EFAULT;
	if ((flags & ~(O_CLOEXEC | O_NONBLOCK)) != 0)
		return EINVAL;

	na_pipe_create_frame_t frame{};
	const int error = naos_syscall_error(_na_pipe_create(&frame));
	if (error != 0)
		return error;

	const int status_flags = flags & O_NONBLOCK;
	const int descriptor_flags = (flags & O_CLOEXEC) != 0 ? FD_CLOEXEC : 0;
	const int read_fd =
	    naos_native::allocate_fd(frame.read_end, O_RDONLY | status_flags, descriptor_flags);
	if (read_fd < 0) {
		_na_handle_close(frame.read_end);
		_na_handle_close(frame.write_end);
		return EMFILE;
	}
	const int write_fd =
	    naos_native::allocate_fd(frame.write_end, O_WRONLY | status_flags, descriptor_flags);
	if (write_fd < 0) {
		naos_native::close_fd(read_fd);
		_na_handle_close(frame.write_end);
		return EMFILE;
	}

	fds[0] = read_fd;
	fds[1] = write_fd;
	return 0;
}

int Sysdeps<Read>::operator()(int fd, void *buf, size_t count, ssize_t *bytes_read) {
	const auto slot = naos_native::slot_for_fd(fd);
	if (slot.handle == NA_HANDLE_INVALID)
		return EBADF;
	if (bytes_read == nullptr)
		return EFAULT;
	if ((slot.flags & O_ACCMODE) == O_WRONLY)
		return EBADF;
	if (count == 0) {
		*bytes_read = 0;
		return 0;
	}
	if (buf == nullptr)
		return EFAULT;
	int error;
	if (slot.kind == naos_native::descriptor_kind::terminal)
		return naos_native::terminal_read(slot, buf, count, bytes_read);
	const auto handle = slot.handle;
	if (slot.kind == naos_native::descriptor_kind::file)
		return naos_native::file_read_call(handle, buf, count, bytes_read);
	naos::system::Stream::read_request request{};
	request.size = count;
	if ((slot.flags & O_NONBLOCK) != 0)
		request.flags = RWFLAGS_NO_BLOCK;
	naos_native::call_result result;
	error = naos_native::encoded_native_call(
	    handle, NA_METHOD_STREAM_READ, request, naos::system::Stream::encode_read_request, result
	);
	if (error != 0)
		return error;
	naos::system::Stream::read_response response{};
	if (!naos::system::Stream::decode_read_response(result.bytes, result.byte_count, response)
	    || response.data.size > count) {
		naos_native::destroy_result(result);
		return EIO;
	}
	memcpy(buf, response.data.data, response.data.size);
	*bytes_read = static_cast<ssize_t>(response.data.size);
	naos_native::destroy_result(result);
	return 0;
}

int Sysdeps<Readv>::operator()(int fd, const struct iovec *iovs, int iovc, ssize_t *bytes_read) {
	if (bytes_read == nullptr)
		return EFAULT;
	if (iovc < 0)
		return EINVAL;
	if (iovc != 0 && iovs == nullptr)
		return EFAULT;
	*bytes_read = 0;
	const auto slot = naos_native::slot_for_fd(fd);
	if (slot.handle == NA_HANDLE_INVALID)
		return EBADF;
	if ((slot.flags & O_ACCMODE) == O_WRONLY)
		return EBADF;
	if (slot.kind == naos_native::descriptor_kind::terminal) {
		for (int i = 0; i < iovc; i++) {
			if (iovs[i].iov_len != 0 && iovs[i].iov_base == nullptr)
				return EFAULT;
			ssize_t current = 0;
			int error =
			    naos_native::terminal_read(slot, iovs[i].iov_base, iovs[i].iov_len, &current);
			if (error != 0)
				return error;
			*bytes_read += current;
			if (static_cast<size_t>(current) < iovs[i].iov_len)
				break;
		}
		return 0;
	}
	if (slot.kind == naos_native::descriptor_kind::file)
		return naos_native::file_readv_call(slot.handle, iovs, iovc, false, 0, bytes_read);
	return naos_native::stream_readv_call(slot.handle, iovs, iovc, slot.flags, bytes_read);
}

int Sysdeps<Write>::operator()(int fd, const void *buf, size_t count, ssize_t *bytes_written) {
	const auto slot = naos_native::slot_for_fd(fd);
	if (slot.handle == NA_HANDLE_INVALID)
		return EBADF;
	if (bytes_written == nullptr)
		return EFAULT;
	if ((slot.flags & O_ACCMODE) == O_RDONLY)
		return EBADF;
	if (count == 0) {
		*bytes_written = 0;
		return 0;
	}
	if (buf == nullptr)
		return EFAULT;
	int error;
	if (slot.kind == naos_native::descriptor_kind::terminal)
		return naos_native::terminal_write(slot, buf, count, bytes_written);
	const auto handle = slot.handle;
	if (slot.kind == naos_native::descriptor_kind::file)
		return naos_native::file_write_call(handle, buf, count, slot.flags, bytes_written);
	if (count > NA_CHANNEL_MAX_MESSAGE_BYTES - 16)
		return EOVERFLOW;
	naos::system::Stream::write_request request{};
	request.size = count;
	uint64_t flags = 0;
	if ((slot.flags & O_NONBLOCK) != 0)
		flags |= RWFLAGS_NO_BLOCK;
	request.flags = flags;
	request.data = {static_cast<const uint8_t *>(buf), static_cast<uint32_t>(count)};
	naos_native::call_result result;
	error = naos_native::encoded_native_call(
	    handle, NA_METHOD_STREAM_WRITE, request, naos::system::Stream::encode_write_request, result
	);
	if (error != 0)
		return error;
	naos::system::Stream::write_response response{};
	if (!naos::system::Stream::decode_write_response(result.bytes, result.byte_count, response)) {
		naos_native::destroy_result(result);
		return EIO;
	}
	*bytes_written = static_cast<ssize_t>(response.count);
	naos_native::destroy_result(result);
	return 0;
}

int
Sysdeps<Writev>::operator()(int fd, const struct iovec *iovs, int iovc, ssize_t *bytes_written) {
	if (bytes_written == nullptr)
		return EFAULT;
	if (iovc < 0)
		return EINVAL;
	if (iovc != 0 && iovs == nullptr)
		return EFAULT;
	*bytes_written = 0;
	const auto slot = naos_native::slot_for_fd(fd);
	if (slot.handle == NA_HANDLE_INVALID)
		return EBADF;
	if ((slot.flags & O_ACCMODE) == O_RDONLY)
		return EBADF;
	if (slot.kind == naos_native::descriptor_kind::terminal) {
		for (int i = 0; i < iovc; i++) {
			if (iovs[i].iov_len != 0 && iovs[i].iov_base == nullptr)
				return EFAULT;
			ssize_t current = 0;
			int error =
			    naos_native::terminal_write(slot, iovs[i].iov_base, iovs[i].iov_len, &current);
			if (error != 0)
				return error;
			*bytes_written += current;
			if (static_cast<size_t>(current) < iovs[i].iov_len)
				break;
		}
		return 0;
	}
	if (slot.kind == naos_native::descriptor_kind::file)
		return naos_native::file_writev_call(
		    slot.handle, iovs, iovc, false, 0, slot.flags, bytes_written
		);
	return naos_native::stream_writev_call(slot.handle, iovs, iovc, slot.flags, bytes_written);
}

int Sysdeps<Seek>::operator()(int fd, off_t offset, int whence, off_t *new_offset) {
	const auto slot = naos_native::slot_for_fd(fd);
	if (slot.handle == NA_HANDLE_INVALID)
		return EBADF;
	if (slot.kind != naos_native::descriptor_kind::file)
		return ESPIPE;
	return naos_native::file_seek_call(slot.handle, offset, whence, new_offset);
}

int Sysdeps<Pread>::operator()(int fd, void *buf, size_t n, off_t off, ssize_t *bytes_read) {
	const auto slot = naos_native::slot_for_fd(fd);
	if (slot.handle == NA_HANDLE_INVALID)
		return EBADF;
	if (slot.kind != naos_native::descriptor_kind::file)
		return ESPIPE;
	if (bytes_read == nullptr)
		return EFAULT;
	if ((slot.flags & O_ACCMODE) == O_WRONLY)
		return EBADF;
	if (n == 0) {
		*bytes_read = 0;
		return 0;
	}
	if (buf == nullptr)
		return EFAULT;
	return naos_native::file_pread_call(slot.handle, buf, n, off, bytes_read);
}

int
Sysdeps<Pwrite>::operator()(int fd, const void *buf, size_t n, off_t off, ssize_t *bytes_written) {
	const auto slot = naos_native::slot_for_fd(fd);
	if (slot.handle == NA_HANDLE_INVALID)
		return EBADF;
	if (slot.kind != naos_native::descriptor_kind::file)
		return ESPIPE;
	if (bytes_written == nullptr)
		return EFAULT;
	if ((slot.flags & O_ACCMODE) == O_RDONLY)
		return EBADF;
	if (n == 0) {
		*bytes_written = 0;
		return 0;
	}
	if (buf == nullptr)
		return EFAULT;
	return naos_native::file_pwrite_call(slot.handle, buf, n, off, bytes_written);
}

int Sysdeps<Close>::operator()(int fd) { return naos_native::close_fd(fd); }

int Sysdeps<Isatty>::operator()(int fd) {
	const auto slot = naos_native::slot_for_fd(fd);
	if (slot.handle == NA_HANDLE_INVALID)
		return EBADF;
	if (slot.terminal)
		return 0;
	return ENOTTY;
}

int Sysdeps<Ioctl>::operator()(int fd, unsigned long request, void *argument, int *result) {
	int error = 0;
	const auto slot = naos_native::slot_for_fd(fd);
	if (slot.handle == NA_HANDLE_INVALID)
		return EBADF;
	const auto stream = slot.handle;

	// These requests change POSIX descriptor-local policy. Terminal endpoints
	// are typed capabilities rather than File objects, so only regular files
	// receive a File.set_flags RPC.
	if (request == FIONBIO) {
		if (argument == nullptr)
			return EFAULT;
		int flags = naos_native::status_flags_for_fd(fd);
		if (*static_cast<int *>(argument) != 0)
			flags |= O_NONBLOCK;
		else
			flags &= ~O_NONBLOCK;
		if (!slot.terminal) {
			error = naos_native::set_file_flags(stream, flags);
			if (error != 0)
				return error;
		} else {
			error = naos_native::terminal_set_status_flags(slot, flags);
			if (error != 0)
				return error;
		}
		error = naos_native::update_status_flags(fd, flags);
		if (error == 0 && result != nullptr)
			*result = 0;
		return error;
	}
	if (request == FIOCLEX || request == FIONCLEX) {
		const int flags = naos_native::descriptor_flags_for_fd(fd);
		if (flags < 0)
			return EBADF;
		error = naos_native::update_descriptor_flags(
		    fd, request == FIOCLEX ? flags | FD_CLOEXEC : flags & ~FD_CLOEXEC
		);
		if (error == 0 && result != nullptr)
			*result = 0;
		return error;
	}

	if (slot.terminal) {
		const bool set_tostop = (request == TCSETS || request == TCSETSW || request == TCSETSF)
		                        && argument != nullptr;
		const bool tostop =
		    set_tostop && (static_cast<const struct termios *>(argument)->c_lflag & TOSTOP) != 0;
		const int ioctl_error = naos_native::terminal_ioctl(slot, request, argument, result);
		if (ioctl_error != 0)
			return ioctl_error;
		if (set_tostop) {
			naos_native::lock_fds();
			if (fd >= 0 && fd < naos_native::max_fds && naos_native::fd_slots[fd].terminal) {
				const auto handle = naos_native::fd_slots[fd].handle;
				for (int candidate = 0; candidate < naos_native::max_fds; candidate++) {
					if (naos_native::fd_slots[candidate].terminal
					    && naos_native::fd_slots[candidate].handle == handle)
						naos_native::fd_slots[candidate].tostop = tostop;
				}
			}
			naos_native::unlock_fds();
		}
		return 0;
	}

	if (request == FBIOGET_FSCREENINFO || request == FBIOGET_VSCREENINFO) {
		if (argument == nullptr)
			return EFAULT;
		naos::system::File::device_control_request encoded_request{};
		encoded_request.request = request;
		encoded_request.argument_size = 0;
		naos_native::call_result call;
		error = naos_native::encoded_native_call(
		    stream,
		    NA_METHOD_FILE_DEVICE_CONTROL,
		    encoded_request,
		    naos::system::File::encode_device_control_request,
		    call
		);
		if (error != 0)
			return error;
		naos::system::File::device_control_response response{};
		if (!naos::system::File::decode_device_control_response(
		        call.bytes, call.byte_count, response
		    )) {
			naos_native::destroy_result(call);
			return EIO;
		}
		const auto expected = request == FBIOGET_FSCREENINFO ? sizeof(fb_fix_screeninfo) : sizeof(fb_var_screeninfo);
		if (response.result.size < expected) {
			naos_native::destroy_result(call);
			return EIO;
		}
		memcpy(argument, response.result.data, expected);
		naos_native::destroy_result(call);
		if (result != nullptr)
			*result = 0;
		return 0;
	}

	// Kernel no longer owns POSIX terminal state. Non-terminal streams do not
	// implement the legacy TtyControl ioctls.
	return ENOTTY;
}

int Sysdeps<Tcgetattr>::operator()(int fd, struct termios *attr) {
	int result = 0;
	return sysdep<Ioctl>(fd, TCGETS, attr, &result);
}

int Sysdeps<Tcsetattr>::operator()(int fd, int optional_action, const struct termios *attr) {
	int request = 0;
	switch (optional_action) {
		case TCSANOW:
			request = TCSETS;
			break;
		case TCSADRAIN:
			request = TCSETSW;
			break;
		case TCSAFLUSH:
			request = TCSETSF;
			break;
		default:
			return EINVAL;
	}

	int result = 0;
	return sysdep<Ioctl>(fd, request, const_cast<struct termios *>(attr), &result);
}

int Sysdeps<Tcgetwinsize>::operator()(int fd, struct winsize *winsz) {
	int result = 0;
	return sysdep<Ioctl>(fd, TIOCGWINSZ, winsz, &result);
}

int Sysdeps<Tcsetwinsize>::operator()(int fd, const struct winsize *winsz) {
	int result = 0;
	return sysdep<Ioctl>(fd, TIOCSWINSZ, const_cast<struct winsize *>(winsz), &result);
}

int Sysdeps<Ptsname>::operator()(int fd, char *buffer, size_t length) {
	int index = 0;
	int result = 0;
	if (int error = sysdep<Ioctl>(fd, TIOCGPTN, &index, &result); error != 0) {
		return error;
	}

	const int required = snprintf(buffer, length, "/dev/pts/%d", index);
	if (required < 0 || static_cast<size_t>(required) >= length) {
		return ERANGE;
	}
	return 0;
}

int Sysdeps<Unlockpt>::operator()(int fd) {
	int unlock = 0;
	int result = 0;
	return sysdep<Ioctl>(fd, TIOCSPTLCK, &unlock, &result);
}

namespace {

int open_process_capability(pid_t pid, na_handle_t &handle) {
	handle = NA_HANDLE_INVALID;
	const int64_t status =
	    _na_process_handle_open(pid == 0 ? 0 : static_cast<int64_t>(pid), &handle);
	return status == 0 ? 0 : naos_syscall_error(status);
}

} // namespace

int Sysdeps<SetSid>::operator()(pid_t *sid) {
	na_handle_t process = NA_HANDLE_INVALID;
	if (int error = open_process_capability(0, process); error != 0)
		return error;
	naos::system::Process::set_session_request request{};
	naos_native::call_result result;
	const int error = naos_native::encoded_native_call(
	    process,
	    NA_METHOD_PROCESS_SET_SESSION,
	    request,
	    naos::system::Process::encode_set_session_request,
	    result
	);
	_na_handle_close(process);
	if (error != 0)
		return error;
	naos::system::Process::set_session_response response{};
	if (!naos::system::Process::decode_set_session_response(
	        result.bytes, result.byte_count, response
	    )
	    || result.resource_count != 0) {
		naos_native::destroy_result(result);
		return EIO;
	}
	*sid = static_cast<pid_t>(response.session);
	naos_native::destroy_result(result);
	return 0;
}

int Sysdeps<GetPgid>::operator()(pid_t pid, pid_t *pgid) {
	na_handle_t process = NA_HANDLE_INVALID;
	if (int error = open_process_capability(pid, process); error != 0)
		return error;
	naos::system::Process::get_process_group_request request{};
	naos_native::call_result result;
	const int error = naos_native::encoded_native_call(
	    process,
	    NA_METHOD_PROCESS_GET_PROCESS_GROUP,
	    request,
	    naos::system::Process::encode_get_process_group_request,
	    result
	);
	_na_handle_close(process);
	if (error != 0)
		return error;
	naos::system::Process::get_process_group_response response{};
	if (!naos::system::Process::decode_get_process_group_response(
	        result.bytes, result.byte_count, response
	    )
	    || result.resource_count != 0) {
		naos_native::destroy_result(result);
		return EIO;
	}
	*pgid = static_cast<pid_t>(response.process_group);
	naos_native::destroy_result(result);
	return 0;
}

int Sysdeps<SetPgid>::operator()(pid_t pid, pid_t pgid) {
	na_handle_t process = NA_HANDLE_INVALID;
	if (int error = open_process_capability(pid, process); error != 0)
		return error;
	naos::system::Process::set_process_group_request request{};
	request.process_group = pgid;
	naos_native::call_result result;
	const int error = naos_native::encoded_native_call(
	    process,
	    NA_METHOD_PROCESS_SET_PROCESS_GROUP,
	    request,
	    naos::system::Process::encode_set_process_group_request,
	    result
	);
	_na_handle_close(process);
	if (error != 0)
		return error;
	if (result.byte_count != 0 || result.resource_count != 0) {
		naos_native::destroy_result(result);
		return EIO;
	}
	naos_native::destroy_result(result);
	return 0;
}

int Sysdeps<GetSid>::operator()(pid_t pid, pid_t *sid) {
	na_handle_t process = NA_HANDLE_INVALID;
	if (int error = open_process_capability(pid, process); error != 0)
		return error;
	naos::system::Process::get_session_request request{};
	naos_native::call_result result;
	const int error = naos_native::encoded_native_call(
	    process,
	    NA_METHOD_PROCESS_GET_SESSION,
	    request,
	    naos::system::Process::encode_get_session_request,
	    result
	);
	_na_handle_close(process);
	if (error != 0)
		return error;
	naos::system::Process::get_session_response response{};
	if (!naos::system::Process::decode_get_session_response(
	        result.bytes, result.byte_count, response
	    )
	    || result.resource_count != 0) {
		naos_native::destroy_result(result);
		return EIO;
	}
	*sid = static_cast<pid_t>(response.session);
	naos_native::destroy_result(result);
	return 0;
}

namespace {

constexpr uint64_t terminal_readable_bit = 0x001;
constexpr uint64_t terminal_writable_bit = 0x004;
constexpr uint64_t terminal_error_bit = 0x008;
constexpr uint64_t terminal_hangup_bit = 0x010;

struct terminal_poll_entry {
	int fd = -1;
	bool master = false;
	na_handle_t invocation = NA_HANDLE_INVALID;
	uint8_t *wire = nullptr;
	uint32_t events = 0;
};

uint32_t terminal_poll_revents(uint64_t ready_mask, uint64_t hangup_mask, uint32_t events) {
	uint32_t revents = 0;
	if ((events & (POLLIN | POLLPRI)) != 0 && (ready_mask & terminal_readable_bit) != 0)
		revents |= POLLIN;
	if ((events & POLLOUT) != 0 && (ready_mask & terminal_writable_bit) != 0)
		revents |= POLLOUT;
	if ((ready_mask & terminal_hangup_bit) != 0 || (hangup_mask & terminal_hangup_bit) != 0)
		revents |= POLLHUP;
	if ((ready_mask & terminal_error_bit) != 0)
		revents |= POLLERR;
	return revents;
}

int terminal_submit_watch(
    const naos_native::fd_slot &slot,
    uint64_t mask,
    uint64_t generation,
    na_handle_t &invocation,
    uint8_t *wire
) {
	auto transport = naos_native::make_transport();
	na_status_t status = NA_STATUS_OK;
	if (slot.master) {
		naos::system::TerminalMaster::watch_request request{};
		request.mask = mask;
		request.observed_generation = generation;
		auto client =
		    naos::system::TerminalMaster::TerminalMasterClient(transport.async(), slot.handle);
		status = client.submit_watch(request, nullptr, 0, &invocation, wire, 256);
	} else {
		naos::system::TerminalSlave::watch_request request{};
		request.mask = mask;
		request.observed_generation = generation;
		auto client =
		    naos::system::TerminalSlave::TerminalSlaveClient(transport.async(), slot.handle);
		status = client.submit_watch(request, nullptr, 0, &invocation, wire, 256);
	}
	return status == NA_STATUS_OK ? 0 : naos_native::status_errno(status);
}

int terminal_query(
    const naos_native::fd_slot &slot,
    uint64_t mask,
    uint32_t events,
    uint32_t &revents,
    uint64_t &generation,
    const struct timespec *deadline
) {
	revents = 0;
	generation = 0;
	std::uint8_t wire[256] = {};
	na_handle_t invocation = NA_HANDLE_INVALID;
	na_result_frame_t result{};
	auto transport = naos_native::make_transport();
	na_status_t status = NA_STATUS_OK;
	if (slot.master) {
		naos::system::TerminalMaster::query_request request{};
		request.mask = mask;
		auto client =
		    naos::system::TerminalMaster::TerminalMasterClient(transport.async(), slot.handle);
		status = client.submit_query(request, nullptr, 0, &invocation, wire, sizeof(wire));
		const int wait_error =
		    status == NA_STATUS_OK ? naos_native::wait_service_invocation(invocation, deadline) : 0;
		if (wait_error != 0) {
			(void)_na_invocation_cancel(invocation);
			(void)_na_handle_close(invocation);
			return wait_error;
		}
		if (status == NA_STATUS_OK) {
			naos::system::TerminalMaster::query_response response{};
			status =
			    client.take_query(invocation, response, wire, sizeof(wire), nullptr, 0, result);
			if (status == NA_STATUS_OK && naos::result_errno(result) == 0) {
				revents = terminal_poll_revents(
				    response.readiness.ready_mask, response.readiness.hangup_mask, events
				);
				generation = response.readiness.generation;
			}
		}
	} else {
		naos::system::TerminalSlave::query_request request{};
		request.mask = mask;
		auto client =
		    naos::system::TerminalSlave::TerminalSlaveClient(transport.async(), slot.handle);
		status = client.submit_query(request, nullptr, 0, &invocation, wire, sizeof(wire));
		const int wait_error =
		    status == NA_STATUS_OK ? naos_native::wait_service_invocation(invocation, deadline) : 0;
		if (wait_error != 0) {
			(void)_na_invocation_cancel(invocation);
			(void)_na_handle_close(invocation);
			return wait_error;
		}
		if (status == NA_STATUS_OK) {
			naos::system::TerminalSlave::query_response response{};
			status =
			    client.take_query(invocation, response, wire, sizeof(wire), nullptr, 0, result);
			if (status == NA_STATUS_OK && naos::result_errno(result) == 0) {
				revents = terminal_poll_revents(
				    response.readiness.ready_mask, response.readiness.hangup_mask, events
				);
				generation = response.readiness.generation;
			}
		}
	}
	if (invocation != NA_HANDLE_INVALID)
		(void)_na_handle_close(invocation);
	if (status != NA_STATUS_OK)
		return naos_native::status_errno(status);
	return naos::result_errno(result);
}

int terminal_take_watch(
    const naos_native::fd_slot &slot,
    na_handle_t invocation,
    uint8_t *wire,
    uint32_t events,
    uint32_t &revents
) {
	revents = 0;
	auto transport = naos_native::make_transport();
	na_result_frame_t result{};
	na_status_t status = NA_STATUS_OK;
	if (slot.master) {
		naos::system::TerminalMaster::watch_response response{};
		auto client =
		    naos::system::TerminalMaster::TerminalMasterClient(transport.async(), slot.handle);
		status = client.take_watch(invocation, response, wire, 256, nullptr, 0, result);
		if (status == NA_STATUS_OK && result.execution_outcome == NA_EXECUTION_NONE
		    && result.protocol_error == 0)
			revents = terminal_poll_revents(
			    response.readiness.ready_mask, response.readiness.hangup_mask, events
			);
	} else {
		naos::system::TerminalSlave::watch_response response{};
		auto client =
		    naos::system::TerminalSlave::TerminalSlaveClient(transport.async(), slot.handle);
		status = client.take_watch(invocation, response, wire, 256, nullptr, 0, result);
		if (status == NA_STATUS_OK && result.execution_outcome == NA_EXECUTION_NONE
		    && result.protocol_error == 0)
			revents = terminal_poll_revents(
			    response.readiness.ready_mask, response.readiness.hangup_mask, events
			);
	}
	if (status != NA_STATUS_OK)
		return naos_native::status_errno(status);
	return naos::result_errno(result);
}

void terminal_cancel_and_close(terminal_poll_entry &entry) {
	if (entry.invocation != NA_HANDLE_INVALID) {
		(void)_na_invocation_cancel(entry.invocation);
		(void)_na_handle_close(entry.invocation);
		entry.invocation = NA_HANDLE_INVALID;
	}
	if (entry.wire != nullptr) {
		getAllocator().deallocate(entry.wire, 256);
		entry.wire = nullptr;
	}
}

} // namespace

int Sysdeps<Poll>::operator()(struct pollfd *fds, nfds_t count, int timeout, int *num_events) {
	if (fds == nullptr && count != 0) {
		*num_events = 0;
		return EFAULT;
	}
	if (count > 1024)
		return EINVAL;
	const int requested_timeout = timeout;
	int64_t deadline_us = 0;
	if (requested_timeout > 0) {
		na_time_clock_t now{};
		if (_s_clock(1, &now) != 0) {
			*num_events = 0;
			return EIO;
		}
		deadline_us = now.tv_sec * 1000000 + now.tv_nsec / 1000
		              + static_cast<int64_t>(requested_timeout) * 1000;
	}

retry_terminal_watch:
	terminal_poll_entry *terminal_entries = nullptr;
	if (count != 0) {
		terminal_entries = static_cast<terminal_poll_entry *>(
		    getAllocator().allocate(sizeof(terminal_poll_entry) * static_cast<std::size_t>(count))
		);
		if (terminal_entries == nullptr)
			return ENOMEM;
		memset(terminal_entries, 0, sizeof(terminal_poll_entry) * static_cast<std::size_t>(count));
	}
	na_wait_item_t wait_items[1024] = {};
	uint64_t wait_count = 0;
	int ready = 0;
	struct timespec query_deadline{};
	const struct timespec *query_deadline_ptr = nullptr;
	if (requested_timeout == 0) {
		query_deadline_ptr = &query_deadline;
	} else if (requested_timeout > 0 && deadline_us > 0) {
		query_deadline.tv_sec = static_cast<time_t>(deadline_us / 1000000);
		query_deadline.tv_nsec = static_cast<long>((deadline_us % 1000000) * 1000);
		query_deadline_ptr = &query_deadline;
	} else if (requested_timeout > 0) {
		query_deadline_ptr = &query_deadline;
	}
	for (nfds_t i = 0; i < count; i++) {
		fds[i].revents = 0;
		terminal_entries[i] = {};
		const auto slot = naos_native::slot_for_fd(fds[i].fd);
		if (slot.handle == NA_HANDLE_INVALID) {
			fds[i].revents = POLLNVAL;
			ready++;
			continue;
		}
		if (!slot.terminal) {
			na_handle_info_t info{};
			info.struct_size = sizeof(info);
			const auto status = _na_handle_get_info(slot.handle, &info);
			if (status != NA_STATUS_OK) {
				fds[i].revents = POLLNVAL;
				ready++;
				continue;
			}
			na_signal_t signals = NA_SIGNAL_PEER_CLOSED;
			if ((fds[i].events & (POLLIN | POLLPRI)) != 0)
				signals |= NA_SIGNAL_READABLE;
			if ((fds[i].events & POLLOUT) != 0)
				signals |= NA_SIGNAL_WRITABLE;
			wait_items[wait_count++] = {slot.handle, signals, info.signals};
			if ((info.signals & signals) != 0) {
				if ((info.signals & NA_SIGNAL_READABLE) != 0
				    && (fds[i].events & (POLLIN | POLLPRI)) != 0)
					fds[i].revents |= POLLIN;
				if ((info.signals & NA_SIGNAL_WRITABLE) != 0 && (fds[i].events & POLLOUT) != 0)
					fds[i].revents |= POLLOUT;
				if ((info.signals & NA_SIGNAL_PEER_CLOSED) != 0)
					fds[i].revents |= POLLHUP;
				if (fds[i].revents != 0)
					ready++;
			}
			continue;
		}

		uint64_t mask = 0;
		if ((fds[i].events & (POLLIN | POLLPRI)) != 0)
			mask |= terminal_readable_bit;
		if ((fds[i].events & POLLOUT) != 0)
			mask |= terminal_writable_bit;
		uint32_t initial_revents = 0;
		uint64_t generation = 0;
		const int query_error =
		    terminal_query(slot, mask, fds[i].events, initial_revents, generation, query_deadline_ptr);
		if (query_error == ETIMEDOUT) {
			// The terminal service did not answer within the poll deadline.
			// Report no readiness for this descriptor instead of blocking
			// past the caller's timeout; the descriptor remains valid.
			continue;
		}
		if (query_error != 0) {
			fds[i].revents = POLLNVAL;
			ready++;
			continue;
		}
		if (initial_revents != 0) {
			fds[i].revents = initial_revents;
			ready++;
			continue;
		}
		terminal_entries[i].fd = fds[i].fd;
		terminal_entries[i].master = slot.master;
		terminal_entries[i].events = fds[i].events;
		auto *wire = static_cast<uint8_t *>(getAllocator().allocate(256));
		if (wire == nullptr) {
			fds[i].revents = POLLNVAL;
			ready++;
			continue;
		}
		terminal_entries[i].wire = wire;
		const int watch_error =
		    terminal_submit_watch(slot, mask, generation, terminal_entries[i].invocation, wire);
		if (watch_error != 0) {
			getAllocator().deallocate(wire, 256);
			terminal_entries[i].wire = nullptr;
			fds[i].revents = POLLNVAL;
			ready++;
			continue;
		}
		wait_items[wait_count++] = {
		    terminal_entries[i].invocation, NA_SIGNAL_COMPLETED | NA_SIGNAL_PEER_CLOSED, 0
		};
	}

	bool retry_terminal_watch = false;
	if (ready == 0 && (wait_count != 0 || timeout != 0)) {
		if (timeout < 0) {
			if (wait_count != 0) {
				const auto status = _na_handle_wait_many(wait_items, wait_count, nullptr);
				if (status != NA_STATUS_OK && status != NA_STATUS_WAIT_TIMED_OUT) {
					for (nfds_t i = 0; i < count; i++)
						terminal_cancel_and_close(terminal_entries[i]);
					getAllocator().deallocate(
					    terminal_entries,
					    sizeof(terminal_poll_entry) * static_cast<std::size_t>(count)
					);
					*num_events = 0;
					return naos_native::status_errno(status);
				}
			} else {
				while (true) {
					na_time_clock_t delay{};
					delay.tv_sec = 1;
					const int sleep_error = _s_sleep(&delay);
					if (sleep_error != 0) {
						for (nfds_t i = 0; i < count; i++)
							terminal_cancel_and_close(terminal_entries[i]);
						if (terminal_entries != nullptr)
							getAllocator().deallocate(
							    terminal_entries,
							    sizeof(terminal_poll_entry) * static_cast<std::size_t>(count)
							);
						*num_events = 0;
						return naos_syscall_error(sleep_error);
					}
				}
			}
		} else {
			na_time_clock_t now{};
			if (_s_clock(1, &now) != 0) {
				for (nfds_t i = 0; i < count; i++)
					terminal_cancel_and_close(terminal_entries[i]);
				if (terminal_entries != nullptr)
					getAllocator().deallocate(
					    terminal_entries,
					    sizeof(terminal_poll_entry) * static_cast<std::size_t>(count)
					);
				*num_events = 0;
				return EIO;
			}
			const int64_t now_us = now.tv_sec * 1000000 + now.tv_nsec / 1000;
			const int64_t remaining_us = deadline_us - now_us;
			if (remaining_us > 0) {
				na_time_clock_t remaining{};
				remaining.tv_sec = static_cast<time_t>(remaining_us / 1000000);
				remaining.tv_nsec = static_cast<int64_t>((remaining_us % 1000000) * 1000);
				if (wait_count != 0) {
					struct timespec deadline{};
					deadline.tv_sec = static_cast<time_t>(deadline_us / 1000000);
					deadline.tv_nsec = static_cast<long>((deadline_us % 1000000) * 1000);
					const auto status = _na_handle_wait_many(wait_items, wait_count, &deadline);
					if (status != NA_STATUS_OK && status != NA_STATUS_WAIT_TIMED_OUT) {
						for (nfds_t i = 0; i < count; i++)
							terminal_cancel_and_close(terminal_entries[i]);
						getAllocator().deallocate(
						    terminal_entries,
						    sizeof(terminal_poll_entry) * static_cast<std::size_t>(count)
						);
						*num_events = 0;
						return naos_native::status_errno(status);
					}
				} else {
					const int sleep_error = _s_sleep(&remaining);
					if (sleep_error != 0) {
						for (nfds_t i = 0; i < count; i++)
							terminal_cancel_and_close(terminal_entries[i]);
						if (terminal_entries != nullptr)
							getAllocator().deallocate(
							    terminal_entries,
							    sizeof(terminal_poll_entry) * static_cast<std::size_t>(count)
							);
						*num_events = 0;
						return naos_syscall_error(sleep_error);
					}
				}
			}
		}

		ready = 0;
		for (nfds_t i = 0; i < count; i++) {
			if (fds[i].revents & POLLNVAL)
				continue;
			const auto slot = naos_native::slot_for_fd(fds[i].fd);
			if (slot.handle == NA_HANDLE_INVALID) {
				fds[i].revents = POLLNVAL;
				ready++;
				continue;
			}
			if (slot.terminal) {
				auto &entry = terminal_entries[i];
				if (entry.invocation == NA_HANDLE_INVALID)
					continue;
				na_handle_info_t invocation_info{};
				invocation_info.struct_size = sizeof(invocation_info);
				if (_na_handle_get_info(entry.invocation, &invocation_info) != NA_STATUS_OK
				    || (invocation_info.signals & (NA_SIGNAL_COMPLETED | NA_SIGNAL_PEER_CLOSED))
				           == 0) {
					terminal_cancel_and_close(entry);
					continue;
				}
				uint32_t revents = 0;
				const int take_error =
				    terminal_take_watch(slot, entry.invocation, entry.wire, entry.events, revents);
				if (take_error != 0) {
					fds[i].revents = POLLNVAL;
					ready++;
				} else if (revents != 0) {
					fds[i].revents = revents;
					ready++;
				} else
					retry_terminal_watch = true;
				terminal_cancel_and_close(entry);
				continue;
			}
			na_handle_info_t info{};
			info.struct_size = sizeof(info);
			if (_na_handle_get_info(slot.handle, &info) != NA_STATUS_OK) {
				fds[i].revents = POLLNVAL;
				ready++;
				continue;
			}
			if ((info.signals & NA_SIGNAL_READABLE) != 0
			    && (fds[i].events & (POLLIN | POLLPRI)) != 0)
				fds[i].revents |= POLLIN;
			if ((info.signals & NA_SIGNAL_WRITABLE) != 0 && (fds[i].events & POLLOUT) != 0)
				fds[i].revents |= POLLOUT;
			if ((info.signals & NA_SIGNAL_PEER_CLOSED) != 0)
				fds[i].revents |= POLLHUP;
			if (fds[i].revents != 0)
				ready++;
		}
	}

	for (nfds_t i = 0; i < count; i++) {
		terminal_cancel_and_close(terminal_entries[i]);
	}
	if (terminal_entries != nullptr)
		getAllocator().deallocate(
		    terminal_entries, sizeof(terminal_poll_entry) * static_cast<std::size_t>(count)
		);
	if (ready == 0 && retry_terminal_watch) {
		if (requested_timeout < 0)
			goto retry_terminal_watch;
		if (requested_timeout > 0) {
			na_time_clock_t now{};
			if (_s_clock(1, &now) != 0) {
				*num_events = 0;
				return EIO;
			}
			const int64_t remaining_us = deadline_us - (now.tv_sec * 1000000 + now.tv_nsec / 1000);
			if (remaining_us > 0) {
				timeout = static_cast<int>((remaining_us + 999) / 1000);
				goto retry_terminal_watch;
			}
		}
	}
	*num_events = ready;
	return 0;
}

// mlibc assumes that anonymous memory returned by sys_vm_map() is zeroed by the kernel / whatever
// is behind the sysdeps
int Sysdeps<VmMap>::operator()(
    void *hint, size_t size, int prot, int flags, int fd, off_t offset, void **window
) {
	if (offset < 0)
		return EINVAL;
	uint32_t mmap_flags = 0;
	if (prot & PROT_READ) {
		mmap_flags |= NA_MEMORY_MAP_READ;
	}
	if (prot & PROT_WRITE) {
		mmap_flags |= NA_MEMORY_MAP_WRITE;
	}
	if (prot & PROT_EXEC) {
		mmap_flags |= NA_MEMORY_MAP_EXEC;
	}
	if (flags & MAP_SHARED) {
		mmap_flags |= NA_MEMORY_MAP_SHARED;
	}
	na_memory_map_frame_t frame{};
	frame.struct_size = sizeof(frame);
	frame.flags = mmap_flags;
	frame.hint = reinterpret_cast<uint64_t>(hint);
	frame.object = NA_HANDLE_INVALID;
	if (!(flags & MAP_ANONYMOUS)) {
		frame.object = naos_native::handle_for_fd(fd);
		if (frame.object == NA_HANDLE_INVALID)
			return EBADF;
	}
	frame.offset = offset;
	frame.length = size;
	const auto status = _na_memory_map(&frame);
	if (status != NA_STATUS_OK)
		return naos_native::status_errno(status);
	*window = reinterpret_cast<void *>(frame.address);
	return 0;
}
int Sysdeps<VmUnmap>::operator()(void *pointer, size_t size) {
	na_memory_unmap_frame_t frame{};
	frame.struct_size = sizeof(frame);
	frame.address = reinterpret_cast<uint64_t>(pointer);
	frame.length = size;
	return naos_native::status_errno(_na_memory_unmap(&frame));
}

void Sysdeps<Yield>::operator()() { _s_yield(); }

int Sysdeps<Sleep>::operator()(time_t *secs, long *nanos) {
	na_time_clock_t c;
	memset(&c, 0, sizeof(c));
	if (secs != nullptr) {
		c.tv_sec = *secs;
	}
	if (nanos != nullptr) {
		c.tv_nsec = *nanos;
	}
	return naos_syscall_error(_s_sleep(&c));
}

int Sysdeps<Fork>::operator()(pid_t *child) {
	int ret = _s_fork();
	*child = ret;
	if (ret < 0) {
		return naos_syscall_error(ret);
	}
	if (ret == 0)
		naos_native::reset_after_fork();
	return 0;
}

int Sysdeps<PrepareStack>::operator()(
    void **stack,
    void *entry,
    void *user_arg,
    void *tcb,
    size_t *stack_size,
    size_t *guard_size,
    void **stack_base
) {
	(void)stack_size;
	(void)guard_size;

	auto context =
	    static_cast<NaosThreadContext *>(getAllocator().allocate(sizeof(NaosThreadContext)));
	if (!context)
		return ENOMEM;

	context->entry = entry;
	context->user_arg = user_arg;
	context->tcb = tcb;
	*stack = context;
	*stack_base = nullptr;
	*stack_size = 0;
	*guard_size = 0;
	return 0;
}

[[noreturn]] void Sysdeps<ThreadExit>::operator()() {
	_s_exit_thread(0);
	__builtin_unreachable();
}

int Sysdeps<Clone>::operator()(void *tcb, pid_t *pid_out, void *stack) {
	int ret = _s_clone(reinterpret_cast<void *>(__mlibc_naos_thread_entry), stack, tcb);
	if (ret < 0)
		return naos_syscall_error(ret);

	*pid_out = ret;
	return 0;
}

int Sysdeps<Execve>::operator()(const char *path, char *const argv[], char *const envp[]) {
	int executable_fd = -1;
	int error = naos_native::open_path(path, O_RDONLY, 0, &executable_fd);
	if (error != 0)
		return error;

	const auto source = naos_native::handle_for_fd(executable_fd);
	na_handle_t executable = NA_HANDLE_INVALID;
	const auto duplicate_status = _na_handle_duplicate(source, 0, &executable);
	const int close_error = naos_native::close_fd(executable_fd);
	if (duplicate_status != NA_STATUS_OK) {
		if (close_error != 0)
			return close_error;
		return naos_native::status_errno(duplicate_status);
	}
	if (close_error != 0) {
		_na_handle_close(executable);
		return close_error;
	}

	na_process_exec_frame_t frame{};
	frame.struct_size = sizeof(frame);
	frame.executable = executable;
	frame.path = reinterpret_cast<uint64_t>(path);
	frame.argv = reinterpret_cast<uint64_t>(argv);
	frame.envp = reinterpret_cast<uint64_t>(envp);
	naos_native::close_cloexec();
	const int64_t status = _na_process_exec(&frame);
	_na_handle_close(executable);
	return naos_syscall_error(status);
}

int
Sysdeps<Waitpid>::operator()(pid_t pid, int *status, int flags, struct rusage *ru, pid_t *ret_pid) {
	(void)ru;
	na_handle_t process = NA_HANDLE_INVALID;
	const int64_t open_status =
	    _na_process_handle_open(pid > 0 ? static_cast<int64_t>(pid) : 0, &process);
	if (open_status != 0)
		return naos_syscall_error(open_status);

	naos_native::call_result result;
	int error = 0;
	if (pid > 0) {
		naos::system::Process::wait_request request{};
		request.flags = flags;
		error = naos_native::encoded_native_call(
		    process,
		    NA_METHOD_PROCESS_WAIT,
		    request,
		    naos::system::Process::encode_wait_request,
		    result
		);
	} else {
		naos::system::Process::wait_children_request request{};
		request.pid = pid;
		request.flags = flags;
		error = naos_native::encoded_native_call(
		    process,
		    NA_METHOD_PROCESS_WAIT_CHILDREN,
		    request,
		    naos::system::Process::encode_wait_children_request,
		    result
		);
	}
	_na_handle_close(process);
	if (error != 0)
		return error;
	naos::system::Process::wait_response response{};
	if (!naos::system::Process::decode_wait_response(result.bytes, result.byte_count, response)
	    || result.resource_count != 0) {
		naos_native::destroy_result(result);
		return EIO;
	}
	if (status)
		*status = static_cast<int>(response.status);
	if (ret_pid)
		*ret_pid = static_cast<pid_t>(response.pid);
	naos_native::destroy_result(result);
	return 0;
}

int Sysdeps<Access>::operator()(const char *path, int mode) {
	return sysdep<Faccessat>(AT_FDCWD, path, mode, 0);
}

int Sysdeps<GetCwd>::operator()(char *buffer, size_t size) {
	if (buffer == nullptr || size == 0)
		return EINVAL;
	naos_native::call_result result;
	naos::system::Directory::path_request request{};
	const int error = naos_native::encoded_native_call(
	    naos_native::current_directory,
	    NA_METHOD_DIRECTORY_PATH,
	    request,
	    naos::system::Directory::encode_path_request,
	    result
	);
	if (error != 0)
		return error;
	naos::system::Directory::path_response response{};
	if (!naos::system::Directory::decode_path_response(result.bytes, result.byte_count, response)
	    || response.path.size + 1 > size) {
		naos_native::destroy_result(result);
		return result.byte_count == 0 ? EIO : ERANGE;
	}
	memcpy(buffer, response.path.data, response.path.size);
	buffer[response.path.size] = 0;
	naos_native::destroy_result(result);
	return 0;
}

int Sysdeps<Chdir>::operator()(const char *path) {
	int error;
	na_handle_t directory = NA_HANDLE_INVALID;
	error = naos_native::open_directory_handle(naos_native::current_directory, path, 0, directory);
	if (error != 0)
		return error;
	error = naos_native::update_process_directory(directory, NA_METHOD_DIRECTORY_SET_CURRENT);
	if (error != 0) {
		_na_handle_close(directory);
		return error;
	}
	return naos_native::replace_current_directory(directory);
}

int Sysdeps<Fchdir>::operator()(int fd) {
	int error;
	const auto source = naos_native::directory_for_fd(fd);
	if (source == NA_HANDLE_INVALID)
		return EBADF;
	na_handle_t directory = NA_HANDLE_INVALID;
	const auto status = _na_handle_duplicate(source, 0, &directory);
	if (status != NA_STATUS_OK)
		return naos_native::status_errno(status);
	error = naos_native::update_process_directory(directory, NA_METHOD_DIRECTORY_SET_CURRENT);
	if (error != 0) {
		_na_handle_close(directory);
		return error;
	}
	return naos_native::replace_current_directory(directory);
}

int Sysdeps<Chroot>::operator()(const char *path) {
	int error;
	na_handle_t directory = NA_HANDLE_INVALID;
	error = naos_native::open_directory_handle(
	    naos_native::current_directory, path, NA_DIRECTORY_OPEN_FLAG_CHROOT, directory
	);
	if (error != 0)
		return error;
	error = naos_native::update_process_directory(directory, NA_METHOD_DIRECTORY_SET_ROOT);
	if (error != 0) {
		_na_handle_close(directory);
		return error;
	}
	return naos_native::replace_root_directory(directory);
}

int Sysdeps<OpenDir>::operator()(const char *path, int *handle) {
	return naos_native::open_path(path, O_RDONLY | O_DIRECTORY, 0, handle);
}

int Sysdeps<Openat>::operator()(int dirfd, const char *path, int flags, mode_t mode, int *fd) {
	const auto directory = naos_native::directory_for_fd(dirfd);
	if (directory == NA_HANDLE_INVALID)
		return EBADF;
	return naos_native::open_path_at(directory, path, flags, mode, fd);
}

int
Sysdeps<ReadEntries>::operator()(int handle, void *buffer, size_t max_size, size_t *bytes_read) {
	if (buffer == nullptr || max_size < sizeof(dirent) || bytes_read == nullptr)
		return EINVAL;
	auto directory = naos_native::handle_for_fd(handle);
	if (directory == NA_HANDLE_INVALID)
		return EBADF;
	naos::system::Directory::list_request request{};
	dirent *output = static_cast<dirent *>(buffer);
	const uint64_t offset = static_cast<uint64_t>(output->d_off);
	request.offset = offset;
	request.requested_bytes = NA_CHANNEL_MAX_MESSAGE_BYTES;
	naos_native::call_result result;
	int error = naos_native::encoded_native_call(
	    directory,
	    NA_METHOD_DIRECTORY_LIST,
	    request,
	    naos::system::Directory::encode_list_request,
	    result
	);
	if (error != 0)
		return error;
	naos::system::Directory::list_response response{};
	if (!naos::system::Directory::decode_list_response(result.bytes, result.byte_count, response)) {
		naos_native::destroy_result(result);
		return EIO;
	}
	const uint64_t count = response.count;
	if (count == 0) {
		*bytes_read = 0;
		naos_native::destroy_result(result);
		return 0;
	}
	if (response.records.size < 16) {
		naos_native::destroy_result(result);
		return EIO;
	}
	const uint64_t inode = naos_native::get_u64(response.records.data);
	const uint32_t type = naos_native::get_u32(response.records.data + 8);
	const uint32_t name_bytes = naos_native::get_u32(response.records.data + 12);
	if (name_bytes == 0 || name_bytes > sizeof(output->d_name)
	    || 16 + name_bytes > response.records.size) {
		naos_native::destroy_result(result);
		return EIO;
	}
	memset(output, 0, sizeof(*output));
	output->d_ino = inode;
	output->d_off = static_cast<off_t>(offset + 1);
	output->d_reclen = sizeof(dirent);
	switch (type) {
		case 1:
			output->d_type = DT_DIR;
			break;
		case 2:
			output->d_type = DT_LNK;
			break;
		case 5:
			output->d_type = DT_FIFO;
			break;
		case 4:
			output->d_type = DT_CHR;
			break;
		default:
			output->d_type = DT_REG;
			break;
	}
	memcpy(output->d_name, response.records.data + 16, name_bytes);
	*bytes_read = sizeof(dirent);
	naos_native::destroy_result(result);
	return 0;
}

int Sysdeps<Rmdir>::operator()(const char *path) {
	if (path == nullptr)
		return EFAULT;
	int error;
	const size_t length = strlen(path);
	if (length >= 4095)
		return ENAMETOOLONG;
	naos::system::Directory::remove_request request{};
	request.mode = 0;
	request.flags = 1;
	request.path = {reinterpret_cast<const uint8_t *>(path), static_cast<uint32_t>(length + 1)};
	naos_native::call_result result;
	error = naos_native::encoded_native_call(
	    naos_native::current_directory,
	    NA_METHOD_DIRECTORY_REMOVE,
	    request,
	    naos::system::Directory::encode_remove_request,
	    result
	);
	naos_native::destroy_result(result);
	return error;
}

int Sysdeps<Mkdir>::operator()(const char *path, mode_t mode) {
	if (path == nullptr)
		return EFAULT;
	int error;
	const size_t length = strlen(path);
	if (length >= 4095)
		return ENAMETOOLONG;
	naos::system::Directory::create_request request{};
	request.mode = mode;
	request.flags = 1;
	request.path = {reinterpret_cast<const uint8_t *>(path), static_cast<uint32_t>(length + 1)};
	naos_native::call_result result;
	error = naos_native::encoded_native_call(
	    naos_native::current_directory,
	    NA_METHOD_DIRECTORY_CREATE,
	    request,
	    naos::system::Directory::encode_create_request,
	    result
	);
	naos_native::destroy_result(result);
	return error;
}

int Sysdeps<Unlinkat>::operator()(int fd, const char *path, int flags) {
	if (path == nullptr)
		return EFAULT;
	int error;
	const size_t length = strlen(path);
	if (length >= 4095)
		return ENAMETOOLONG;
	const auto directory = naos_native::directory_for_fd(fd);
	if (directory == NA_HANDLE_INVALID)
		return EBADF;
	naos::system::Directory::remove_request request{};
	request.mode = 0;
	request.flags = (flags & AT_REMOVEDIR) != 0 ? 1 : 0;
	request.path = {reinterpret_cast<const uint8_t *>(path), static_cast<uint32_t>(length + 1)};
	naos_native::call_result result;
	error = naos_native::encoded_native_call(
	    directory,
	    NA_METHOD_DIRECTORY_REMOVE,
	    request,
	    naos::system::Directory::encode_remove_request,
	    result
	);
	naos_native::destroy_result(result);
	return error;
}

int Sysdeps<Faccessat>::operator()(int dirfd, const char *pathname, int mode, int flags) {
	if ((flags & ~(AT_EACCESS | AT_SYMLINK_NOFOLLOW)) != 0)
		return EINVAL;
	int error;
	const auto directory = naos_native::directory_for_fd(dirfd);
	if (directory == NA_HANDLE_INVALID)
		return EBADF;
	naos_native::call_result result;
	error = naos_native::directory_value_call(
	    directory, NA_METHOD_DIRECTORY_ACCESS, static_cast<uint64_t>(mode), pathname, result
	);
	naos_native::destroy_result(result);
	return error;
}

int Sysdeps<Mkdirat>::operator()(int dirfd, const char *path, mode_t mode) {
	const auto directory = naos_native::directory_for_fd(dirfd);
	if (directory == NA_HANDLE_INVALID)
		return EBADF;
	naos_native::call_result result;
	const int error = naos_native::directory_value_call(
	    directory, NA_METHOD_DIRECTORY_CREATE, mode | 1, path, result
	);
	naos_native::destroy_result(result);
	return error;
}

int
Sysdeps<Readlink>::operator()(const char *path, void *buffer, size_t max_size, ssize_t *length) {
	return sysdep<Readlinkat>(AT_FDCWD, path, buffer, max_size, length);
}

int Sysdeps<Readlinkat>::operator()(
    int dirfd, const char *path, void *buffer, size_t max_size, ssize_t *length
) {
	if (buffer == nullptr || length == nullptr)
		return EFAULT;
	const auto directory = naos_native::directory_for_fd(dirfd);
	if (directory == NA_HANDLE_INVALID)
		return EBADF;
	naos_native::call_result result;
	const int error = naos_native::directory_readlink_call(directory, path, result);
	if (error != 0)
		return error;
	naos::system::Directory::readlink_response response{};
	if (!naos::system::Directory::decode_readlink_response(
	        result.bytes, result.byte_count, response
	    )
	    || response.target.size > max_size) {
		naos_native::destroy_result(result);
		return result.byte_count == 0 ? EIO : EOVERFLOW;
	}
	memcpy(buffer, response.target.data, response.target.size);
	*length = static_cast<ssize_t>(response.target.size);
	naos_native::destroy_result(result);
	return 0;
}

int Sysdeps<Renameat>::operator()(
    int olddirfd, const char *old_path, int newdirfd, const char *new_path
) {
	int error;
	const auto old_directory = naos_native::directory_for_fd(olddirfd);
	const auto new_directory = naos_native::directory_for_fd(newdirfd);
	if (old_directory == NA_HANDLE_INVALID || new_directory == NA_HANDLE_INVALID)
		return EBADF;
	if (old_directory != new_directory)
		return EXDEV;
	naos_native::call_result result;
	error = naos_native::directory_pair_call(
	    old_directory, NA_METHOD_DIRECTORY_RENAME, old_path, new_path, result
	);
	naos_native::destroy_result(result);
	return error;
}

int Sysdeps<Rename>::operator()(const char *path, const char *new_path) {
	return sysdep<Renameat>(AT_FDCWD, path, AT_FDCWD, new_path);
}

int Sysdeps<Link>::operator()(const char *old_path, const char *new_path) {
	return sysdep<Linkat>(AT_FDCWD, old_path, AT_FDCWD, new_path, 0);
}

int Sysdeps<Linkat>::operator()(
    int olddirfd, const char *old_path, int newdirfd, const char *new_path, int flags
) {
	if ((flags & ~AT_SYMLINK_FOLLOW) != 0)
		return EINVAL;
	int error;
	const auto old_directory = naos_native::directory_for_fd(olddirfd);
	const auto new_directory = naos_native::directory_for_fd(newdirfd);
	if (old_directory == NA_HANDLE_INVALID || new_directory == NA_HANDLE_INVALID)
		return EBADF;
	if (old_directory != new_directory)
		return EXDEV;
	naos_native::call_result result;
	error = naos_native::directory_pair_call(
	    old_directory, NA_METHOD_DIRECTORY_LINK, old_path, new_path, result
	);
	naos_native::destroy_result(result);
	return error;
}

int Sysdeps<Symlink>::operator()(const char *target_path, const char *link_path) {
	return sysdep<Symlinkat>(target_path, AT_FDCWD, link_path);
}

int Sysdeps<Symlinkat>::operator()(const char *target_path, int dirfd, const char *link_path) {
	const auto directory = naos_native::directory_for_fd(dirfd);
	if (directory == NA_HANDLE_INVALID)
		return EBADF;
	naos_native::call_result result;
	const int error = naos_native::directory_pair_call(
	    directory, NA_METHOD_DIRECTORY_SYMLINK, target_path, link_path, result
	);
	naos_native::destroy_result(result);
	return error;
}

int Sysdeps<Truncate>::operator()(const char *path, off_t length) {
	int fd = -1;
	int error = naos_native::open_path(path, O_WRONLY, 0, &fd);
	if (error != 0)
		return error;
	error = sysdep<Ftruncate>(fd, static_cast<size_t>(length));
	const int close_error = naos_native::close_fd(fd);
	return error != 0 ? error : close_error;
}

int Sysdeps<Ftruncate>::operator()(int fd, size_t size) {
	const auto file = naos_native::handle_for_fd(fd);
	if (file == NA_HANDLE_INVALID)
		return EBADF;
	return naos_native::file_value_call(file, NA_METHOD_FILE_TRUNCATE, size, 0, false);
}

int Sysdeps<Fallocate>::operator()(int fd, off_t offset, size_t size) {
	const auto file = naos_native::handle_for_fd(fd);
	if (file == NA_HANDLE_INVALID)
		return EBADF;
	return naos_native::file_value_call(
	    file, NA_METHOD_FILE_ALLOCATE, static_cast<uint64_t>(offset), size, true
	);
}

int Sysdeps<Fsync>::operator()(int fd) {
	const auto file = naos_native::handle_for_fd(fd);
	if (file == NA_HANDLE_INVALID)
		return EBADF;
	return naos_native::file_value_call(file, NA_METHOD_FILE_SYNC, 0, 0, false, true);
}

int Sysdeps<Fdatasync>::operator()(int fd) { return sysdep<Fsync>(fd); }

int Sysdeps<Fcntl>::operator()(int fd, int request, va_list args, int *result) {
	if (result == nullptr)
		return EFAULT;
	int error = 0;
	switch (request) {
		case F_DUPFD:
		case F_DUPFD_CLOEXEC: {
			const int minimum = va_arg(args, int);
			const int new_fd = naos_native::duplicate_fd_min(
			    fd, minimum, request == F_DUPFD_CLOEXEC ? FD_CLOEXEC : 0
			);
			if (new_fd < 0)
				return -new_fd;
			*result = new_fd;
			return 0;
		}
		case F_GETFD: {
			const int flags = naos_native::descriptor_flags_for_fd(fd);
			if (flags < 0)
				return EBADF;
			*result = flags;
			return 0;
		}
		case F_SETFD:
			if (const int e = naos_native::update_descriptor_flags(fd, va_arg(args, int)); e != 0)
				return e;
			*result = 0;
			return 0;
		case F_GETFL: {
			const auto handle = naos_native::handle_for_fd(fd);
			if (handle == NA_HANDLE_INVALID)
				return EBADF;
			*result = naos_native::status_flags_for_fd(fd);
			return 0;
		}
		case F_SETFL: {
			const auto slot = naos_native::slot_for_fd(fd);
			if (slot.handle == NA_HANDLE_INVALID)
				return EBADF;
			const int flags = va_arg(args, int);
			if (slot.terminal) {
				if (const int e = naos_native::terminal_set_status_flags(slot, flags); e != 0)
					return e;
				if (const int e = naos_native::update_status_flags(fd, flags); e != 0)
					return e;
				*result = 0;
				return 0;
			}
			const auto handle = slot.handle;
			error = naos_native::set_file_flags(handle, flags);
			if (error != 0)
				return error;
			if (const int e = naos_native::update_status_flags(fd, flags); e != 0)
				return e;
			*result = 0;
			return 0;
		}
		default:
			return ENOTSUP;
	}
}

int Sysdeps<Stat>::operator()(
    fsfd_target fsfdt, int fd, const char *path, int flags, struct stat *statbuf
) {
	if (statbuf == nullptr)
		return EFAULT;
	int temporary_fd = -1;
	if (fsfdt != fsfd_target::fd) {
		int error = naos_native::open_path(path, O_RDONLY, 0, &temporary_fd);
		if (error != 0)
			return error;
		fd = temporary_fd;
	}
	const auto target = naos_native::handle_for_fd(fd);
	if (target == NA_HANDLE_INVALID) {
		if (temporary_fd >= 0)
			naos_native::close_fd(temporary_fd);
		return EBADF;
	}
	na_handle_info_t info{};
	info.struct_size = sizeof(info);
	uint64_t status = _na_handle_get_info(target, &info);
	if (status != NA_STATUS_OK) {
		if (temporary_fd >= 0)
			naos_native::close_fd(temporary_fd);
		return naos_native::status_errno(status);
	}
	const uint64_t method =
	    info.scope == NA_SCOPE_DIRECTORY ? NA_METHOD_DIRECTORY_STAT : NA_METHOD_FILE_STAT;
	naos_native::call_result result;
	int error = 0;
	if (info.scope == NA_SCOPE_DIRECTORY) {
		naos::system::Directory::stat_request request{};
		error = naos_native::encoded_native_call(
		    target, method, request, naos::system::Directory::encode_stat_request, result
		);
	} else {
		naos::system::File::stat_request request{};
		error = naos_native::encoded_native_call(
		    target, method, request, naos::system::File::encode_stat_request, result
		);
	}
	if (error == 0) {
		const bool decoded =
		    info.scope == NA_SCOPE_DIRECTORY
		        ? naos_native::decode_directory_stat(result.bytes, result.byte_count, *statbuf)
		        : naos_native::decode_stat(result.bytes, result.byte_count, *statbuf);
		if (!decoded)
			error = EIO;
	}
	naos_native::destroy_result(result);
	if (temporary_fd >= 0)
		naos_native::close_fd(temporary_fd);
	return error;
}

int Sysdeps<Dup>::operator()(int fd, int flags, int *newfd) {
	const int nfd =
	    naos_native::duplicate_fd(fd, -1, (flags & F_DUPFD_CLOEXEC) != 0 ? FD_CLOEXEC : 0);
	if (nfd < 0)
		return -nfd;
	*newfd = nfd;
	return 0;
}

int Sysdeps<Dup2>::operator()(int fd, int flags, int newfd) {
	const int result =
	    naos_native::duplicate_fd(fd, newfd, (flags & F_DUPFD_CLOEXEC) != 0 ? FD_CLOEXEC : 0);
	return result < 0 ? -result : 0;
}

int Sysdeps<Sigprocmask>::operator()(int how, const sigset_t *set, sigset_t *retrieve) {
	uint64_t valid = 0;
	uint64_t block = set ? static_cast<uint64_t>(*set) : 0;
	uint64_t ignore = 0;
	int ret = _s_sigmask(how, &valid, &block, &ignore);
	if (ret == 0 && retrieve)
		*retrieve = static_cast<sigset_t>(block);
	return naos_syscall_error(ret);
}

int
Sysdeps<Sigaction>::operator()(int signum, const struct sigaction *act, struct sigaction *oldact) {
	if (signum <= 0 || signum >= NSIG || signum >= 64 || signum == SIGKILL || signum == SIGSTOP)
		return EINVAL;

	if (oldact)
		*oldact = naos_signal_actions[signum];
	if (!act)
		return 0;

	const uint64_t bit = 1ULL << signum;
	na_signal_mask_t valid = 0;
	na_signal_mask_t block = 0;
	na_signal_mask_t ignore = 0;
	if (int e = _s_sigmask(SIGOPT_GET, &valid, &block, &ignore); e != 0)
		return naos_syscall_error(e);

	if (act->sa_handler == SIG_DFL) {
		valid &= ~bit;
		ignore &= ~bit;
	} else {
		valid |= bit;
		if (act->sa_handler == SIG_IGN)
			ignore |= bit;
		else
			ignore &= ~bit;
	}
	if (int e = _s_sigmask(SIGOPT_SET, &valid, &block, &ignore); e != 0)
		return naos_syscall_error(e);

	naos_signal_actions[signum] = *act;
	return 0;
}

// NaOS currently has one uid/gid namespace and starts every user process as
// root. Keep these sysdeps explicit so mlibc does not abort in get*id().
uid_t Sysdeps<GetUid>::operator()() { return 0; }
uid_t Sysdeps<GetEuid>::operator()() { return 0; }
gid_t Sysdeps<GetGid>::operator()() { return 0; }
gid_t Sysdeps<GetEgid>::operator()() { return 0; }
pid_t Sysdeps<GetPpid>::operator()() { return 0; }

int Sysdeps<Kill>::operator()(int pid, int sig) {
	na_signal_target_t target{};
	if (pid > 0) {
		target.id = pid;
		target.flags = SIGTGT_PROC;
	} else if (pid == 0) {
		target.id = 0;
		target.flags = SIGTGT_GROUP;
	} else if (pid < -1) {
		target.id = -static_cast<int64_t>(pid);
		target.flags = SIGTGT_GROUP;
	} else {
		// Sending to every process is not implemented by the NaOS kernel.
		return ENOTSUP;
	}
	return naos_syscall_error(_s_sigsend(&target, sig, nullptr));
}

pid_t Sysdeps<GetPid>::operator()() { return _s_current_pid(); }

// The NaOS mlibc profile does not enable the optional glibc surface, but
// BusyBox and a few POSIX consumers still use the standard variadic ioctl
// entry point. Keep that ABI shim here and route it through the typed TTY
// adapter above; no legacy kernel ioctl syscall is involved.
extern "C" int ioctl(int fd, unsigned long request, ...) {
	va_list args;
	va_start(args, request);
	// Linux-compatible TTY requests with scalar arguments pass those values
	// through varargs, while mlibc's typed sysdep receives a pointer to a
	// stable argument object. Materialize the scalar for the duration of the
	// call and avoid reading a missing vararg for no-argument requests.
	int scalar_argument = 0;
	const bool no_argument = request == TIOCNOTTY || request == FIOCLEX || request == FIONCLEX;
	const bool scalar_request = request == TIOCSCTTY || request == TCSBRK || request == TCXONC
	                            || request == TCFLSH || request == TCSBRKP;
	void *argument = nullptr;
	if (scalar_request) {
		scalar_argument = static_cast<int>(va_arg(args, uintptr_t));
		argument = &scalar_argument;
	} else if (!no_argument) {
		argument = va_arg(args, void *);
	}
	va_end(args);

	int result = 0;
	if (int error = sysdep<Ioctl>(fd, request, argument, &result); error != 0) {
		errno = error;
		return -1;
	}
	return result;
}

} // namespace mlibc

extern "C" [[noreturn]] void __mlibc_naos_thread_entry(void *raw_context) {
	auto context = static_cast<NaosThreadContext *>(raw_context);
	auto entry = context->entry;
	auto user_arg = context->user_arg;
	auto tcb = static_cast<Tcb *>(context->tcb);
	getAllocator().deallocate(context, sizeof(NaosThreadContext));

	mlibc::sysdep<::TcbSet>(tcb);
	while (!__atomic_load_n(&tcb->tid, __ATOMIC_RELAXED))
		mlibc::sysdep<::FutexWait>(&tcb->tid, 0, nullptr);

	__atomic_fetch_or(&tcb->cancelBits, 1, __ATOMIC_RELAXED);
	tcb->invokeThreadFunc(entry, user_arg);
	mlibc::thread_exit(tcb->returnValue);
}
