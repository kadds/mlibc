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
#include <naos/generated/system/Directory.hpp>
#include <naos/generated/system/File.hpp>
#include <naos/generated/system/Process.hpp>
#include <naos/generated/system/ServiceDirectory_client.hpp>
#include <naos/generated/system/Stream.hpp>
#include <naos/generated/system/TtyControl.hpp>
#include <naos/generated/system_uapi.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <naos/service_directory.hpp>

#define SYS_CALL(index, ret, name, ...)                                                            \
	extern "C" ret name(__VA_ARGS__);                                                              \
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

struct time_clock {
	int64_t tv_sec;
	int64_t tv_nsec;
};

SYS_CALL(0, void, _s_none, void)
SYS_CALL(1, void, _s_log, const char *message)
SYS_CALL(2, int, _s_clock, int clock_index, time_clock *clock);

// Native object-call ABI. These wrappers intentionally expose the kernel's
// status return directly; the adapter below maps it to POSIX errno values.
SYS_CALL(17, uint64_t, _na_handle_close, na_handle_t handle)
SYS_CALL(18, uint64_t, _na_channel_create, const na_channel_options_t *options, na_handle_t *left, na_handle_t *right)
SYS_CALL(19, uint64_t, _na_channel_send, na_handle_t endpoint, const na_channel_send_frame_t *frame)
SYS_CALL(20, uint64_t, _na_channel_receive, na_handle_t endpoint, na_channel_receive_frame_t *frame)
SYS_CALL(
    22, uint64_t, _na_handle_wait_many, na_wait_item_t *items, uint64_t count, const struct timespec *deadline
)
SYS_CALL(
    23,
    uint64_t,
    _na_handle_duplicate,
    na_handle_t source,
    na_meta_rights_t rights,
    na_handle_t *result
)
SYS_CALL(
    24,
    uint64_t,
    _na_handle_restrict,
    na_handle_t source,
    const na_handle_restriction_t *restriction,
    na_handle_t *result
)
SYS_CALL(25, uint64_t, _na_handle_get_info, na_handle_t handle, na_handle_info_t *result)
SYS_CALL(
    26,
    uint64_t,
    _na_protocol_descriptor_create,
    const na_protocol_descriptor_t *input,
    na_handle_t *result
)
SYS_CALL(
    27,
    uint64_t,
    _na_protocol_endpoint_create,
    na_handle_t descriptor,
    const na_protocol_endpoint_options_t *options,
    na_handle_t *client,
    na_handle_t *server
)
SYS_CALL(
    28,
    uint64_t,
    _na_invoke_submit,
    na_handle_t target,
    const na_submit_frame_t *frame,
    na_handle_t *invocation
)
SYS_CALL(29, uint64_t, _na_invoke_oneway, na_handle_t target, const na_submit_frame_t *frame)
SYS_CALL(31, uint64_t, _na_invocation_take_result, na_handle_t invocation, na_result_frame_t *frame)
SYS_CALL(32, uint64_t, _na_responder_reply, na_handle_t responder, const na_reply_frame_t *frame)
SYS_CALL(33, uint64_t, _na_responder_fail, na_handle_t responder, const na_fail_frame_t *frame)
SYS_CALL(34, uint64_t, _na_bootstrap, na_bootstrap_frame_t *frame)
SYS_CALL(38, int64_t, _na_process_exec, const na_process_exec_frame_t *frame)
SYS_CALL(39, int64_t, _na_process_handle_open, int64_t pid, na_handle_t *result)
SYS_CALL(40, int64_t, _na_process_spawn, const na_process_spawn_frame_t *frame)
SYS_CALL(41, int64_t, _na_pipe_create, na_pipe_create_frame_t *frame)
SYS_CALL(35, uint64_t, _na_tty_control_acquire, na_handle_t stream, na_handle_t *result)
SYS_CALL(36, uint64_t, _na_memory_map, na_memory_map_frame_t *frame)
SYS_CALL(37, uint64_t, _na_memory_unmap, na_memory_unmap_frame_t *frame)

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

SYS_CALL(3, int, _s_futex, int *ptr, int op, int val, const time_clock *timeout);
SYS_CALL(4, [[noreturn]] void, _s_exit, int64_t ret)
SYS_CALL(5, [[noreturn]] void, _s_exit_thread, int64_t ret)
SYS_CALL(6, int, _s_sleep, const time_clock *time)
SYS_CALL(7, int64_t, _s_current_pid)
SYS_CALL(8, int64_t, _s_current_tid)
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

struct sig_info_t {
	int64_t error;
	int64_t code;
	int64_t status;
	int64_t pid;
	int64_t tid;
};

struct sigtarget_t {
	int64_t id;
	int64_t flags;
};

#define SIGTGT_PROC 1
#define SIGTGT_GROUP 2
typedef uint64_t sig_mask_t;

static inline void sig_mask_init(sig_mask_t &mask) { mask = 0; }

static inline void sig_mask_set(sig_mask_t &mask, int idx) { mask |= (1ul << idx); }

static inline void sig_mask_clear(sig_mask_t &mask, int idx) { mask &= ~(1ul << idx); }

static inline bool sig_mask_get(sig_mask_t mask, int idx) { return mask & (1ul << idx); }

SYS_CALL(9, int, _s_sigsend, sigtarget_t *target, int signum, sig_info_t *info)
SYS_CALL(10, int, _s_sigmask, int opt, sig_mask_t *valid, sig_mask_t *block, sig_mask_t *ignore)
SYS_CALL(11, int, _s_tcb_set, void *p);
SYS_CALL(12, int, _s_fork);
SYS_CALL(13, int, _s_clone, void *entry, void *arg, void *tcb);
SYS_CALL(14, int, _s_yield);

SYS_CALL(15, bool, _s_brk, uint64_t ptr)
SYS_CALL(16, uint64_t, _s_sbrk, int64_t offset)

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

struct fd_slot {
	na_handle_t handle = NA_HANDLE_INVALID;
	int flags = 0;
	int fd_flags = 0;
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

bool decode_termios(const uint8_t *bytes, uint64_t size, struct termios &value) {
	naos::system::TtyControl::get_attributes_response response{};
	if (!naos::system::TtyControl::decode_get_attributes_response(bytes, size, response))
		return false;
	value = {};
	value.c_iflag = response.attributes.input_flags;
	value.c_oflag = response.attributes.output_flags;
	value.c_cflag = response.attributes.control_flags;
	value.c_lflag = response.attributes.local_flags;
	value.c_line = response.attributes.line;
	memcpy(value.c_cc, response.attributes.control_chars.data(), sizeof(value.c_cc));
	value.c_ibaud = response.attributes.input_baud;
	value.c_obaud = response.attributes.output_baud;
	return true;
}

naos::system::TtyControl::Termios wire_termios(const struct termios &value) {
	naos::system::TtyControl::Termios result{};
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

bool decode_winsize(const uint8_t *bytes, uint64_t size, struct winsize &value) {
	naos::system::TtyControl::get_winsize_response response{};
	if (!naos::system::TtyControl::decode_get_winsize_response(bytes, size, response))
		return false;
	value.ws_row = response.size.rows;
	value.ws_col = response.size.columns;
	value.ws_xpixel = response.size.x_pixels;
	value.ws_ypixel = response.size.y_pixels;
	return true;
}

naos::system::TtyControl::Winsize wire_winsize(const struct winsize &value) {
	naos::system::TtyControl::Winsize result{};
	result.rows = value.ws_row;
	result.columns = value.ws_col;
	result.x_pixels = value.ws_xpixel;
	result.y_pixels = value.ws_ypixel;
	return result;
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
bool bootstrapped = false;
volatile uint32_t fd_lock = 0;

int ensure_bootstrap();

void lock_fds() {
	while (__atomic_exchange_n(&fd_lock, 1, __ATOMIC_ACQUIRE))
		__asm__ volatile("pause");
}

void unlock_fds() { __atomic_store_n(&fd_lock, 0, __ATOMIC_RELEASE); }

void reset_after_fork() {
	fd_slot snapshot[max_fds] = {};
	na_handle_t snapshot_root = NA_HANDLE_INVALID;
	na_handle_t snapshot_current = NA_HANDLE_INVALID;
	na_handle_t snapshot_service = NA_HANDLE_INVALID;
	lock_fds();
	for (int fd = 0; fd < max_fds; fd++)
		snapshot[fd] = fd_slots[fd];
	snapshot_root = root_directory;
	snapshot_current = current_directory;
	snapshot_service = service_directory;
	unlock_fds();

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
			valid_fd_slots[fd] = inspect(snapshot[fd].handle, info);
		}
	}
	const bool bootstrap_valid =
		is_directory(snapshot_root) && is_directory(snapshot_current)
	    && is_service_directory(snapshot_service) && valid_fd_slots[STDIN] && valid_fd_slots[STDOUT]
	    && valid_fd_slots[STDERR] && is_stream(snapshot[STDIN].handle)
	    && is_stream(snapshot[STDOUT].handle) && is_stream(snapshot[STDERR].handle);

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
}

void close_cloexec() {
	na_handle_t handles[max_fds] = {};
	uint64_t handle_count = 0;
	lock_fds();
	for (int fd = 0; fd < max_fds; fd++) {
		if (fd_slots[fd].handle != NA_HANDLE_INVALID && (fd_slots[fd].fd_flags & FD_CLOEXEC) != 0) {
			handles[handle_count++] = fd_slots[fd].handle;
			fd_slots[fd] = {};
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

int result_errno(const na_result_frame_t &frame) {
	if (frame.protocol_error < 0)
		return static_cast<int>(-frame.protocol_error);
	if (frame.execution_outcome == NA_EXECUTION_NONE)
		return 0;
	switch (frame.outcome_reason) {
		case NA_OUTCOME_REASON_CANCEL_REQUESTED:
			return ECANCELED;
		case NA_OUTCOME_REASON_OPERATION_DEADLINE:
			return ETIMEDOUT;
		case NA_OUTCOME_REASON_PEER_CLOSED:
			return EPIPE;
		default:
			return EIO;
	}
}

int ensure_bootstrap() {
	if (bootstrapped)
		return 0;
	na_bootstrap_frame_t frame{};
	frame.struct_size = sizeof(frame);
	const auto status = _na_bootstrap(&frame);
	if (status != NA_STATUS_OK)
		return status_errno(status);
	if (frame.root_directory == NA_HANDLE_INVALID || frame.current_directory == NA_HANDLE_INVALID
	    || frame.service_directory == NA_HANDLE_INVALID || frame.stdin_stream == NA_HANDLE_INVALID
	    || frame.stdout_stream == NA_HANDLE_INVALID || frame.stderr_stream == NA_HANDLE_INVALID)
		return EIO;

	lock_fds();
	fd_slots[STDIN].handle = frame.stdin_stream;
	fd_slots[STDOUT].handle = frame.stdout_stream;
	fd_slots[STDERR].handle = frame.stderr_stream;
	fd_slots[STDIN].flags = O_RDONLY;
	fd_slots[STDOUT].flags = O_WRONLY;
	fd_slots[STDERR].flags = O_WRONLY;
	root_directory = frame.root_directory;
	current_directory = frame.current_directory;
	service_directory = frame.service_directory;
	bootstrapped = true;
	unlock_fds();
	return 0;
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
	const auto flags = fd_slots[fd].flags;
	unlock_fds();
	return flags;
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
	fd_slots[fd].flags =
	    (fd_slots[fd].flags & ~(O_APPEND | O_NONBLOCK)) | (flags & (O_APPEND | O_NONBLOCK));
	unlock_fds();
	return 0;
}

int allocate_fd(na_handle_t handle, int flags, int fd_flags = 0) {
	if (handle == NA_HANDLE_INVALID)
		return -1;
	lock_fds();
	for (int fd = 3; fd < max_fds; fd++) {
		if (fd_slots[fd].handle == NA_HANDLE_INVALID) {
			fd_slots[fd] = {handle, flags, fd_flags};
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
	fd_slots[fd] = {};
	unlock_fds();
	return status_errno(_na_handle_close(handle));
}

int duplicate_fd(int fd, int requested_fd, int requested_fd_flags = 0) {
	lock_fds();
	if (!valid_fd(fd)) {
		unlock_fds();
		return -EBADF;
	}
	const auto source = fd_slots[fd].handle;
	const int source_flags = fd_slots[fd].flags;
	unlock_fds();

	na_handle_t duplicate = NA_HANDLE_INVALID;
	const auto status = _na_handle_duplicate(source, 0, &duplicate);
	if (status != NA_STATUS_OK)
		return -status_errno(status);

	if (requested_fd >= 0) {
		if (requested_fd >= max_fds || requested_fd == fd) {
			_na_handle_close(duplicate);
			return requested_fd == fd ? requested_fd : -EBADF;
		}
		lock_fds();
		const auto old = fd_slots[requested_fd].handle;
		fd_slots[requested_fd] = {duplicate, source_flags, requested_fd_flags};
		unlock_fds();
		if (old != NA_HANDLE_INVALID)
			_na_handle_close(old);
		return requested_fd;
	}

	const int new_fd = allocate_fd(duplicate, source_flags, requested_fd_flags);
	if (new_fd < 0) {
		_na_handle_close(duplicate);
		return -EMFILE;
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
	unlock_fds();

	na_handle_t duplicate = NA_HANDLE_INVALID;
	const auto status = _na_handle_duplicate(source, 0, &duplicate);
	if (status != NA_STATUS_OK)
		return -status_errno(status);
	lock_fds();
	int new_fd = -1;
	for (int candidate = minimum < 3 ? 3 : minimum; candidate < max_fds; candidate++) {
		if (fd_slots[candidate].handle == NA_HANDLE_INVALID) {
			fd_slots[candidate] = {duplicate, source_flags, new_fd_flags};
			new_fd = candidate;
			break;
		}
	}
	unlock_fds();
	if (new_fd < 0) {
		_na_handle_close(duplicate);
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
	api.handle_close = [](void *, na_handle_t handle) { return static_cast<na_status_t>(_na_handle_close(handle)); };
	api.handle_get_info = [](void *, na_handle_t handle, na_handle_info_t *info) {
		return static_cast<na_status_t>(_na_handle_get_info(handle, info));
	};
	api.invoke_submit = [](void *, na_handle_t target, const na_submit_frame_t *frame, na_handle_t *invocation) {
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

int wait_service_invocation(na_handle_t invocation) {
	na_wait_item_t wait_item{invocation, NA_SIGNAL_COMPLETED | NA_SIGNAL_PEER_CLOSED, 0};
	return naos_syscall_error(_na_handle_wait_many(&wait_item, 1, nullptr));
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
	auto client = naos::system::ServiceDirectory::ServiceDirectoryClient(transport.async(), service_directory);
	const auto submit_status = client.submit_register(request, &disposition, 1, &invocation, wire, wire_capacity);
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
	const auto take_status = client.take_register(invocation, response, wire, wire_capacity, response_resources,
	                                              NA_CHANNEL_MAX_RESOURCES, result);
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
	auto client = naos::system::ServiceDirectory::ServiceDirectoryClient(transport.async(), service_directory);
	const auto submit_status = client.submit_resolve(request, nullptr, 0, &invocation, wire, wire_capacity);
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
	const auto take_status = client.take_resolve(invocation, response, wire, wire_capacity, response_resources,
	                                              NA_CHANNEL_MAX_RESOURCES, result);
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
	if (result.actual_resources != 1 || response.service.value != 0) {
		for (std::uint64_t i = 0; i < result.actual_resources; i++)
			_na_handle_close(response_resources[i]);
		return EIO;
	}
	*handle = response_resources[0];
	return 0;
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
	auto client = naos::system::ServiceDirectory::ServiceDirectoryClient(transport.async(), service_directory);
	const auto submit_status = client.submit_unregister(request, nullptr, 0, &invocation, wire, wire_capacity);
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
	const auto take_status = client.take_unregister(invocation, response, wire, wire_capacity, response_resources,
	                                                 NA_CHANNEL_MAX_RESOURCES, result);
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

	auto adapter = make_transport();
	const auto client = adapter.async();
	na_handle_t invocation = NA_HANDLE_INVALID;
	uint64_t status = client.submit(client.context, target, method, static_cast<const uint8_t *>(request), request_bytes,
	                                nullptr, 0, 0, &invocation);
	if (status != NA_STATUS_OK) {
		return status_errno(status);
	}

	na_wait_item_t wait_item{invocation, NA_SIGNAL_COMPLETED | NA_SIGNAL_PEER_CLOSED, 0};
	status = _na_handle_wait_many(&wait_item, 1, nullptr);
	if (status != NA_STATUS_OK) {
		_na_handle_close(invocation);
		return status_errno(status);
	}

	result.bytes = static_cast<uint8_t *>(getAllocator().allocate(result_capacity));
	if (result.bytes == nullptr) {
		_na_handle_close(invocation);
		return ENOMEM;
	}
	result.frame = {};
	result.frame.struct_size = sizeof(result.frame);
	result.frame.bytes = reinterpret_cast<uint64_t>(result.bytes);
	result.frame.byte_capacity = result_capacity;
	result.frame.resources = reinterpret_cast<uint64_t>(result.resources);
	result.frame.resource_capacity = resource_capacity;
	status = client.take_result(client.context, invocation, &result.frame);
	_na_handle_close(invocation);
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

int open_path_at(na_handle_t directory, const char *path, int flags, mode_t mode, int *fd) {
	if (path == nullptr)
		return EFAULT;
	const size_t path_length = strlen(path);
	if (path_length >= 4095)
		return ENAMETOOLONG;

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

extern "C" int naos_native_spawn(pid_t *pid, const char *path, char *const argv[], char *const envp[]) {
	if (pid == nullptr || path == nullptr)
		return EFAULT;
	const int bootstrap_error = ensure_bootstrap();
	if (bootstrap_error != 0)
		return bootstrap_error;

	int executable_fd = -1;
	int error = open_path(path, O_RDONLY, 0, &executable_fd);
	if (error != 0)
		return error;
	const auto source = handle_for_fd(executable_fd);
	na_handle_t executable = NA_HANDLE_INVALID;
	const auto duplicate_status = _na_handle_duplicate(source, 0, &executable);
	const int close_error = close_fd(executable_fd);
	if (duplicate_status != NA_STATUS_OK) {
		if (close_error != 0)
			return close_error;
		return status_errno(duplicate_status);
	}
	if (close_error != 0) {
		_na_handle_close(executable);
		return close_error;
	}

	na_handle_t parent_endpoint = NA_HANDLE_INVALID;
	na_handle_t child_endpoint = NA_HANDLE_INVALID;
	uint64_t status = _na_channel_create(nullptr, &parent_endpoint, &child_endpoint);
	if (status != NA_STATUS_OK) {
		_na_handle_close(executable);
		return status_errno(status);
	}

	na_handle_t process = NA_HANDLE_INVALID;
	uint64_t native_pid = 0;
	na_process_spawn_frame_t spawn{};
	spawn.struct_size = sizeof(spawn);
	spawn.executable = executable;
	spawn.bootstrap_endpoint = child_endpoint;
	spawn.path = reinterpret_cast<uint64_t>(path);
	spawn.argv = reinterpret_cast<uint64_t>(argv);
	spawn.envp = reinterpret_cast<uint64_t>(envp);
	spawn.process = reinterpret_cast<uint64_t>(&process);
	spawn.pid = reinterpret_cast<uint64_t>(&native_pid);
	const int64_t spawn_status = _na_process_spawn(&spawn);
	if (spawn_status != 0) {
		_na_handle_close(executable);
		_na_handle_close(child_endpoint);
		_na_handle_close(parent_endpoint);
		return naos_syscall_error(spawn_status);
	}

	na_bootstrap_message_t message{};
	message.struct_size = sizeof(message);
	message.version = NA_BOOTSTRAP_MESSAGE_VERSION;
	message.resource_count = NA_BOOTSTRAP_RESOURCE_COUNT;
	message.root_directory = NA_BOOTSTRAP_RESOURCE_ROOT_DIRECTORY;
	message.current_directory = NA_BOOTSTRAP_RESOURCE_CURRENT_DIRECTORY;
	message.service_directory = NA_BOOTSTRAP_RESOURCE_SERVICE_DIRECTORY;
	message.stdin_stream = NA_BOOTSTRAP_RESOURCE_STDIN;
	message.stdout_stream = NA_BOOTSTRAP_RESOURCE_STDOUT;
	message.stderr_stream = NA_BOOTSTRAP_RESOURCE_STDERR;
	message.argc = count_startup_vector(argv);
	message.envc = count_startup_vector(envp);
	na_resource_disposition_t dispositions[NA_BOOTSTRAP_RESOURCE_COUNT]{};
	const na_handle_t resources[NA_BOOTSTRAP_RESOURCE_COUNT] = {
		root_directory,
		current_directory,
		service_directory,
		handle_for_fd(STDIN),
		handle_for_fd(STDOUT),
		handle_for_fd(STDERR),
	};
	for (uint32_t i = 0; i < NA_BOOTSTRAP_RESOURCE_COUNT; i++) {
		dispositions[i].handle = resources[i];
		dispositions[i].operation = NA_RESOURCE_DUPLICATE;
	}
	na_channel_send_frame send{};
	send.struct_size = sizeof(send);
	send.bytes = reinterpret_cast<uint64_t>(&message);
	send.byte_count = sizeof(message);
	send.resources = reinterpret_cast<uint64_t>(dispositions);
	send.resource_count = NA_BOOTSTRAP_RESOURCE_COUNT;
	status = _na_channel_send(parent_endpoint, &send);
	_na_handle_close(parent_endpoint);
	_na_handle_close(process);
	if (status != NA_STATUS_OK)
		return status_errno(status);
	*pid = static_cast<pid_t>(native_pid);
	return 0;
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

} // namespace naos_native

void Sysdeps<LibcLog>::operator()(const char *message) { _s_log(message); }

[[noreturn]] void Sysdeps<LibcPanic>::operator()() {
	Sysdeps<LibcLog>::operator()("panic");
	while (true) {
		_s_exit(-1);
	}
}

[[noreturn]] void Sysdeps<Exit>::operator()(int status) { _s_exit(status); }
int Sysdeps<ClockGet>::operator()(int clock, time_t *secs, long *nanos) {
	time_clock c;
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
	time_clock c;
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
	const int read_fd = naos_native::allocate_fd(frame.read_end, O_RDONLY | status_flags, descriptor_flags);
	if (read_fd < 0) {
		_na_handle_close(frame.read_end);
		_na_handle_close(frame.write_end);
		return EMFILE;
	}
	const int write_fd = naos_native::allocate_fd(frame.write_end, O_WRONLY | status_flags, descriptor_flags);
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
	int error;
	const auto handle = naos_native::handle_for_fd(fd);
	if (handle == NA_HANDLE_INVALID)
		return EBADF;
	naos::system::Stream::read_request request{};
	request.size = count;
	if ((naos_native::status_flags_for_fd(fd) & O_NONBLOCK) != 0)
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

int Sysdeps<Write>::operator()(int fd, const void *buf, size_t count, ssize_t *bytes_written) {
	int error;
	const auto handle = naos_native::handle_for_fd(fd);
	if (handle == NA_HANDLE_INVALID)
		return EBADF;
	if (count > NA_CHANNEL_MAX_MESSAGE_BYTES - 16)
		return EOVERFLOW;
	naos::system::Stream::write_request request{};
	request.size = count;
	uint64_t flags = 0;
	if ((naos_native::status_flags_for_fd(fd) & O_NONBLOCK) != 0)
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

int Sysdeps<Seek>::operator()(int fd, off_t offset, int whence, off_t *new_offset) {
	int error;
	const auto handle = naos_native::handle_for_fd(fd);
	if (handle == NA_HANDLE_INVALID)
		return EBADF;
	na_handle_info_t info{};
	info.struct_size = sizeof(info);
	const auto info_status = _na_handle_get_info(handle, &info);
	if (info_status != NA_STATUS_OK)
		return naos_native::status_errno(info_status);
	if (memcmp(info.protocol_uuid.bytes, naos::system::Stream::protocol_uuid.bytes, sizeof(info.protocol_uuid.bytes)) == 0)
		return ESPIPE;
	if (memcmp(info.protocol_uuid.bytes, naos::system::File::protocol_uuid.bytes, sizeof(info.protocol_uuid.bytes)) != 0)
		return ESPIPE;
	naos::system::File::seek_request request{};
	request.offset = offset;
	request.whence = whence;
	naos_native::call_result result;
	error = naos_native::encoded_native_call(
	    handle, NA_METHOD_FILE_SEEK, request, naos::system::File::encode_seek_request, result
	);
	if (error != 0)
		return error;
	naos::system::File::seek_response response{};
	if (!naos::system::File::decode_seek_response(result.bytes, result.byte_count, response)) {
		naos_native::destroy_result(result);
		return EIO;
	}
	*new_offset = static_cast<off_t>(response.offset);
	naos_native::destroy_result(result);
	return 0;
}

int Sysdeps<Pread>::operator()(int fd, void *buf, size_t n, off_t off, ssize_t *bytes_read) {
	int error;
	const auto handle = naos_native::handle_for_fd(fd);
	if (handle == NA_HANDLE_INVALID)
		return EBADF;
	naos::system::File::pread_request request{};
	request.offset = off;
	request.size = n;
	request.flags = 0;
	naos_native::call_result result;
	error = naos_native::encoded_native_call(
	    handle, NA_METHOD_FILE_PREAD, request, naos::system::File::encode_pread_request, result
	);
	if (error != 0)
		return error;
	naos::system::File::pread_response response{};
	if (!naos::system::File::decode_pread_response(result.bytes, result.byte_count, response)
	    || response.data.size > n) {
		naos_native::destroy_result(result);
		return EIO;
	}
	memcpy(buf, response.data.data, response.data.size);
	*bytes_read = static_cast<ssize_t>(response.data.size);
	naos_native::destroy_result(result);
	return 0;
}

int
Sysdeps<Pwrite>::operator()(int fd, const void *buf, size_t n, off_t off, ssize_t *bytes_written) {
	int error;
	const auto handle = naos_native::handle_for_fd(fd);
	if (handle == NA_HANDLE_INVALID)
		return EBADF;
	if (n > NA_CHANNEL_MAX_MESSAGE_BYTES - 24)
		return EOVERFLOW;
	naos::system::File::pwrite_request request{};
	request.offset = off;
	request.size = n;
	request.flags = 0;
	request.data = {static_cast<const uint8_t *>(buf), static_cast<uint32_t>(n)};
	naos_native::call_result result;
	error = naos_native::encoded_native_call(
	    handle, NA_METHOD_FILE_PWRITE, request, naos::system::File::encode_pwrite_request, result
	);
	if (error != 0)
		return error;
	naos::system::File::pwrite_response response{};
	if (!naos::system::File::decode_pwrite_response(result.bytes, result.byte_count, response)) {
		naos_native::destroy_result(result);
		return EIO;
	}
	*bytes_written = static_cast<ssize_t>(response.count);
	naos_native::destroy_result(result);
	return 0;
}

int Sysdeps<Close>::operator()(int fd) { return naos_native::close_fd(fd); }

int Sysdeps<Isatty>::operator()(int fd) {
	const auto stream = naos_native::handle_for_fd(fd);
	if (stream == NA_HANDLE_INVALID)
		return EBADF;
	na_handle_t control = NA_HANDLE_INVALID;
	const auto status = _na_tty_control_acquire(stream, &control);
	if (status != NA_STATUS_OK)
		return status == NA_STATUS_WRONG_BINDING || status == NA_STATUS_WRONG_SCOPE
		           ? ENOTTY
		           : naos_native::status_errno(status);
	_na_handle_close(control);
	return 0;
}

int Sysdeps<Ioctl>::operator()(int fd, unsigned long request, void *argument, int *result) {
	int error = 0;
	const auto stream = naos_native::handle_for_fd(fd);
	if (stream == NA_HANDLE_INVALID)
		return EBADF;

	// These requests change POSIX descriptor-local policy and do not require
	// a TTY capability. Keep that policy in mlibc's fd table while forwarding
	// the corresponding open-file flags to the native File object.
	if (request == FIONBIO) {
		if (argument == nullptr)
			return EFAULT;
		int flags = naos_native::status_flags_for_fd(fd);
		if (*static_cast<int *>(argument) != 0)
			flags |= O_NONBLOCK;
		else
			flags &= ~O_NONBLOCK;
		error = naos_native::set_file_flags(stream, flags);
		if (error != 0)
			return error;
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

	na_handle_t control = NA_HANDLE_INVALID;
	auto status = _na_tty_control_acquire(stream, &control);
	if (status != NA_STATUS_OK)
		return status == NA_STATUS_WRONG_BINDING || status == NA_STATUS_WRONG_SCOPE
		           ? ENOTTY
		           : naos_native::status_errno(status);

	uint64_t method = 0;
	bool copy_result = false;
	bool scalar_result = false;
	size_t result_size = 0;
	switch (request) {
		case TCGETS:
			method = NA_METHOD_TTY_GET_ATTRIBUTES;
			copy_result = true;
			result_size = sizeof(struct termios);
			break;
		case TCSETS:
		case TCSETSW:
		case TCSETSF:
			if (argument == nullptr) {
				_na_handle_close(control);
				return EFAULT;
			}
			method = NA_METHOD_TTY_SET_ATTRIBUTES;
			break;
		case TIOCGWINSZ:
			method = NA_METHOD_TTY_GET_WINSIZE;
			copy_result = true;
			result_size = sizeof(struct winsize);
			break;
		case TIOCSCTTY:
			method = NA_METHOD_TTY_ATTACH;
			break;
		case TIOCGPGRP:
			method = NA_METHOD_TTY_GET_PGRP;
			copy_result = true;
			scalar_result = true;
			result_size = sizeof(int);
			break;
		case TIOCSPGRP:
			if (argument == nullptr) {
				_na_handle_close(control);
				return EFAULT;
			}
			method = NA_METHOD_TTY_SET_PGRP;
			break;
		case TIOCGSID:
			method = NA_METHOD_TTY_GET_SID;
			copy_result = true;
			scalar_result = true;
			result_size = sizeof(int);
			break;
		case TIOCNOTTY:
			method = NA_METHOD_TTY_DETACH;
			break;
		case FIONREAD:
			method = NA_METHOD_TTY_GET_INPUT;
			copy_result = true;
			scalar_result = true;
			result_size = sizeof(int);
			break;
		case TIOCSWINSZ:
			if (argument == nullptr) {
				_na_handle_close(control);
				return EFAULT;
			}
			method = NA_METHOD_TTY_SET_WINSIZE;
			break;
		case TCFLSH:
			method = NA_METHOD_TTY_FLUSH;
			break;
		case TIOCGPTN:
			method = NA_METHOD_PTY_GET_NUMBER;
			copy_result = true;
			scalar_result = true;
			result_size = sizeof(int);
			break;
		case TIOCSPTLCK:
			if (argument == nullptr) {
				_na_handle_close(control);
				return EFAULT;
			}
			method = NA_METHOD_PTY_UNLOCK;
			break;
		default:
			_na_handle_close(control);
			return ENOTTY;
	}

	if (copy_result && argument == nullptr) {
		_na_handle_close(control);
		return EFAULT;
	}
	naos_native::call_result call;
	if (request == TCGETS) {
		naos::system::TtyControl::get_attributes_request encoded_request{};
		error = naos_native::encoded_native_call(
		    control,
		    method,
		    encoded_request,
		    naos::system::TtyControl::encode_get_attributes_request,
		    call
		);
	} else if (request == TIOCGWINSZ) {
		naos::system::TtyControl::get_winsize_request encoded_request{};
		error = naos_native::encoded_native_call(
		    control,
		    method,
		    encoded_request,
		    naos::system::TtyControl::encode_get_winsize_request,
		    call
		);
	} else if (request == TIOCGPGRP) {
		naos::system::TtyControl::get_pgrp_request encoded_request{};
		error = naos_native::encoded_native_call(
		    control,
		    method,
		    encoded_request,
		    naos::system::TtyControl::encode_get_pgrp_request,
		    call
		);
	} else if (request == TIOCGSID) {
		naos::system::TtyControl::get_sid_request encoded_request{};
		error = naos_native::encoded_native_call(
		    control, method, encoded_request, naos::system::TtyControl::encode_get_sid_request, call
		);
	} else if (request == FIONREAD) {
		naos::system::TtyControl::get_input_request encoded_request{};
		error = naos_native::encoded_native_call(
		    control,
		    method,
		    encoded_request,
		    naos::system::TtyControl::encode_get_input_request,
		    call
		);
	} else if (request == TIOCGPTN) {
		naos::system::TtyControl::get_number_request encoded_request{};
		error = naos_native::encoded_native_call(
		    control,
		    method,
		    encoded_request,
		    naos::system::TtyControl::encode_get_number_request,
		    call
		);
	} else if (request == TIOCSCTTY) {
		naos::system::TtyControl::attach_request encoded_request{};
		encoded_request.controlling = argument == nullptr ? 0 : *static_cast<int *>(argument);
		error = naos_native::encoded_native_call(
		    control, method, encoded_request, naos::system::TtyControl::encode_attach_request, call
		);
	} else if (request == TIOCSPGRP) {
		naos::system::TtyControl::set_pgrp_request encoded_request{};
		encoded_request.group = *static_cast<int *>(argument);
		error = naos_native::encoded_native_call(
		    control,
		    method,
		    encoded_request,
		    naos::system::TtyControl::encode_set_pgrp_request,
		    call
		);
	} else if (request == TCSETS || request == TCSETSW || request == TCSETSF) {
		naos::system::TtyControl::set_attributes_request encoded_request{};
		encoded_request.attributes =
		    naos_native::wire_termios(*static_cast<const struct termios *>(argument));
		error = naos_native::encoded_native_call(
		    control,
		    method,
		    encoded_request,
		    naos::system::TtyControl::encode_set_attributes_request,
		    call
		);
	} else if (request == TIOCSWINSZ) {
		naos::system::TtyControl::set_winsize_request encoded_request{};
		encoded_request.size =
		    naos_native::wire_winsize(*static_cast<const struct winsize *>(argument));
		error = naos_native::encoded_native_call(
		    control,
		    method,
		    encoded_request,
		    naos::system::TtyControl::encode_set_winsize_request,
		    call
		);
	} else if (request == TCFLSH) {
		naos::system::TtyControl::flush_request encoded_request{};
		encoded_request.queue = argument == nullptr ? 0 : *static_cast<int *>(argument);
		error = naos_native::encoded_native_call(
		    control, method, encoded_request, naos::system::TtyControl::encode_flush_request, call
		);
	} else if (request == TIOCSPTLCK) {
		naos::system::TtyControl::unlock_request encoded_request{};
		encoded_request.locked = *static_cast<int *>(argument);
		error = naos_native::encoded_native_call(
		    control, method, encoded_request, naos::system::TtyControl::encode_unlock_request, call
		);
	} else if (request == TIOCNOTTY) {
		naos::system::TtyControl::detach_request encoded_request{};
		error = naos_native::encoded_native_call(
		    control, method, encoded_request, naos::system::TtyControl::encode_detach_request, call
		);
	} else {
		error = EINVAL;
	}
	_na_handle_close(control);
	if (error != 0) {
		return error;
	}
	if (copy_result) {
		if (call.byte_count < (scalar_result ? sizeof(uint64_t) : result_size)) {
			naos_native::destroy_result(call);
			return EFAULT;
		}
		bool decoded = false;
		if (request == TCGETS)
			decoded = naos_native::decode_termios(
			    call.bytes, call.byte_count, *static_cast<struct termios *>(argument)
			);
		else if (request == TIOCGWINSZ)
			decoded = naos_native::decode_winsize(
			    call.bytes, call.byte_count, *static_cast<struct winsize *>(argument)
			);
		else if (request == TIOCGPGRP) {
			naos::system::TtyControl::get_pgrp_response response{};
			decoded = naos::system::TtyControl::decode_get_pgrp_response(
			    call.bytes, call.byte_count, response
			);
			if (decoded)
				*static_cast<int *>(argument) = static_cast<int>(response.group);
		} else if (request == TIOCGSID) {
			naos::system::TtyControl::get_sid_response response{};
			decoded = naos::system::TtyControl::decode_get_sid_response(
			    call.bytes, call.byte_count, response
			);
			if (decoded)
				*static_cast<int *>(argument) = static_cast<int>(response.session);
		} else if (request == FIONREAD) {
			naos::system::TtyControl::get_input_response response{};
			decoded = naos::system::TtyControl::decode_get_input_response(
			    call.bytes, call.byte_count, response
			);
			if (decoded)
				*static_cast<int *>(argument) = static_cast<int>(response.count);
		} else if (request == TIOCGPTN) {
			naos::system::TtyControl::get_number_response response{};
			decoded = naos::system::TtyControl::decode_get_number_response(
			    call.bytes, call.byte_count, response
			);
			if (decoded)
				*static_cast<int *>(argument) = static_cast<int>(response.number);
		} else {
			memcpy(argument, call.bytes, result_size);
			decoded = true;
		}
		if (!decoded) {
			naos_native::destroy_result(call);
			return EIO;
		}
	}
	if (request == TCSETSF) {
		naos::system::TtyControl::flush_request flush_request{};
		naos_native::call_result flush_result;
		na_handle_t flush_control = NA_HANDLE_INVALID;
		const auto flush_status = _na_tty_control_acquire(stream, &flush_control);
		if (flush_status != NA_STATUS_OK)
			error = naos_native::status_errno(flush_status);
		else
			error = naos_native::encoded_native_call(
			    flush_control,
			    NA_METHOD_TTY_FLUSH,
			    flush_request,
			    naos::system::TtyControl::encode_flush_request,
			    flush_result
			);
		if (flush_control != NA_HANDLE_INVALID)
			_na_handle_close(flush_control);
		if (error == 0)
			naos_native::destroy_result(flush_result);
	}
	if (result != nullptr)
		*result = 0;
	naos_native::destroy_result(call);
	return error;
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
	const int64_t status = _na_process_handle_open(pid == 0 ? 0 : static_cast<int64_t>(pid), &handle);
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
		process, NA_METHOD_PROCESS_SET_SESSION, request, naos::system::Process::encode_set_session_request, result
	);
	_na_handle_close(process);
	if (error != 0)
		return error;
	naos::system::Process::set_session_response response{};
	if (!naos::system::Process::decode_set_session_response(result.bytes, result.byte_count, response) ||
		result.resource_count != 0) {
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
		process, NA_METHOD_PROCESS_GET_PROCESS_GROUP, request,
		naos::system::Process::encode_get_process_group_request, result
	);
	_na_handle_close(process);
	if (error != 0)
		return error;
	naos::system::Process::get_process_group_response response{};
	if (!naos::system::Process::decode_get_process_group_response(result.bytes, result.byte_count, response) ||
		result.resource_count != 0) {
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
		process, NA_METHOD_PROCESS_SET_PROCESS_GROUP, request,
		naos::system::Process::encode_set_process_group_request, result
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
		process, NA_METHOD_PROCESS_GET_SESSION, request, naos::system::Process::encode_get_session_request, result
	);
	_na_handle_close(process);
	if (error != 0)
		return error;
	naos::system::Process::get_session_response response{};
	if (!naos::system::Process::decode_get_session_response(result.bytes, result.byte_count, response) ||
		result.resource_count != 0) {
		naos_native::destroy_result(result);
		return EIO;
	}
	*sid = static_cast<pid_t>(response.session);
	naos_native::destroy_result(result);
	return 0;
}

int Sysdeps<Poll>::operator()(struct pollfd *fds, nfds_t count, int timeout, int *num_events) {
	if (fds == nullptr && count != 0) {
		*num_events = 0;
		return EFAULT;
	}
	if (count > 1024)
		return EINVAL;

	na_wait_item_t wait_items[1024] = {};
	uint64_t wait_count = 0;
	int ready = 0;
	for (nfds_t i = 0; i < count; i++) {
		fds[i].revents = 0;
		const auto handle = naos_native::handle_for_fd(fds[i].fd);
		if (handle == NA_HANDLE_INVALID) {
			fds[i].revents = POLLNVAL;
			ready++;
			continue;
		}
		na_handle_info_t info{};
		info.struct_size = sizeof(info);
		const auto status = _na_handle_get_info(handle, &info);
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
		wait_items[wait_count++] = {handle, signals, info.signals};
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
	}

	if (ready == 0 && timeout != 0) {
		if (timeout < 0) {
			if (wait_count != 0) {
				const auto status = _na_handle_wait_many(wait_items, wait_count, nullptr);
				if (status != NA_STATUS_OK && status != NA_STATUS_WAIT_TIMED_OUT)
					return naos_native::status_errno(status);
			} else {
				while (true) {
					time_clock delay{};
					delay.tv_sec = 1;
					const int sleep_error = _s_sleep(&delay);
					if (sleep_error != 0)
						return naos_syscall_error(sleep_error);
				}
			}
		} else {
			time_clock delay{};
			delay.tv_sec = timeout / 1000;
			delay.tv_nsec = static_cast<int64_t>(timeout % 1000) * 1000000;
			const int sleep_error = _s_sleep(&delay);
			if (sleep_error != 0)
				return naos_syscall_error(sleep_error);
		}

		ready = 0;
		for (nfds_t i = 0; i < count; i++) {
			if (fds[i].revents & POLLNVAL)
				continue;
			const auto handle = naos_native::handle_for_fd(fds[i].fd);
			if (handle == NA_HANDLE_INVALID) {
				fds[i].revents = POLLNVAL;
				ready++;
				continue;
			}
			na_handle_info_t info{};
			info.struct_size = sizeof(info);
			if (_na_handle_get_info(handle, &info) != NA_STATUS_OK) {
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
	time_clock c;
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
			return naos_native::update_descriptor_flags(fd, va_arg(args, int));
		case F_GETFL: {
			const auto handle = naos_native::handle_for_fd(fd);
			if (handle == NA_HANDLE_INVALID)
				return EBADF;
			*result = naos_native::status_flags_for_fd(fd);
			return 0;
		}
		case F_SETFL: {
			const auto handle = naos_native::handle_for_fd(fd);
			if (handle == NA_HANDLE_INVALID)
				return EBADF;
			const int flags = va_arg(args, int);
			error = naos_native::set_file_flags(handle, flags);
			if (error != 0)
				return error;
			return naos_native::update_status_flags(fd, flags);
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
	sig_mask_t valid = 0;
	sig_mask_t block = 0;
	sig_mask_t ignore = 0;
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
	sigtarget_t target{};
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
