#include "sysdeps/linux/include/abi-bits/seek-whence.h"
#include <abi-bits/seek-whence.h>
#include <abi-bits/stat.h>
#include <abi-bits/vm-flags.h>
#include <bits/ensure.h>
#include <bits/off_t.h>
#include <bits/ssize_t.h>
#include <cstddef>
#include <cstdint>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/debug.hpp>
#include <mlibc/fsfd_target.hpp>

#define SYS_CALL(index, ret, name, ...)                                                                                \
    extern "C" ret name(__VA_ARGS__);                                                                                  \
    __asm__(".globl " #name " \n\t "                                                                                   \
            ".type	" #name ",	@function \n\t" #name ": \n\t"                                                         \
            "movq $" #index ", %rax \n\t"                                                                              \
            "pushq %r10 \n\t"                                                                                          \
            "pushq %r11 \n\t"                                                                                          \
            "pushq %r12 \n\t"                                                                                          \
            "movq %rcx, %r12 \n\t"                                                                                     \
            "movq %rsp, %r10 \n\t"                                                                                     \
            "syscall \n\t"                                                                                             \
            "popq %r12 \n\t"                                                                                           \
            "popq %r11 \n\t"                                                                                           \
            "popq %r10 \n\t"                                                                                           \
            "retq");

struct time_clock
{
    int64_t tv_sec;
    int64_t tv_nsec;
};

SYS_CALL(0, void, _s_none, void)
SYS_CALL(1, void, _s_log, const char *message)
SYS_CALL(2, int, _s_clock, int clock_index, time_clock *clock);

#define OPEN_MODE_READ 1
#define OPEN_MODE_WRITE 2
#define OPEN_MODE_BIN 4
#define OPEN_MODE_APPEND 8

#define STDIN 0
#define STDOUT 1
#define STDERR 2
typedef int fd_t;

#define OPEN_ATTR_AUTO_CREATE_FILE 1
#define RWFLAGS_NO_BLOCK 1
#define RWFLAGS_OVERRIDE 2

SYS_CALL(3, fd_t, _s_open, const char *path, uint64_t mode, uint64_t attr)
SYS_CALL(4, int64_t, _s_read, fd_t fd, void *buffer, uint64_t max_len, uint64_t flags)
SYS_CALL(5, int64_t, _s_write, fd_t fd, const void *buffer, uint64_t len, uint64_t flags)
SYS_CALL(6, int64_t, _s_pread, fd_t fd, uint64_t offset, char *buffer, uint64_t max_len, uint64_t flags)
SYS_CALL(7, int64_t, _s_pwrite, fd_t fd, uint64_t offset, const char *buffer, uint64_t len, uint64_t flags)
SYS_CALL(8, int64_t, _s_lseek, fd_t fd, int64_t offset, int mode)
SYS_CALL(9, int, _s_close, fd_t fd);
SYS_CALL(10, int, _s_dup, fd_t fd);
SYS_CALL(11, int, _s_dup2, fd_t fd, fd_t newfd);
SYS_CALL(12, int, _s_istty, fd_t fd);
SYS_CALL(13, int, _s_stat, fd_t fd);
SYS_CALL(14, int64_t, _s_fcntl, fd_t fd, unsigned int operator_type, unsigned int target, unsigned int attr,
         void *value, uint64_t size)

SYS_CALL(15, int, _s_fsync, fd_t fd);
SYS_CALL(16, int, _s_ftruncate, fd_t fd);
SYS_CALL(17, int, _s_fallocate, fd_t fd);

#define LSEEK_MODE_CURRENT 0
#define LSEEK_MODE_BEGIN 1
#define LSEEK_MODE_END 2

// SYS_CALL(10, int64_t, _s_get_pipe, fd_t *fd1, fd_t *fd2)
// SYS_CALL(11, int, _s_create_fifo, const char *path, uint64_t mode)

struct list_directory_cursor
{
    uint32_t size;
    int64_t cursor;
};

struct list_directory_result
{
    list_directory_cursor cursor;
    uint32_t num_files;
    char *files_buffer;
    uint32_t bytes;
    char *buffer;
};

SYS_CALL(18, int, _s_open_dir, const char *path);
SYS_CALL(19, int, _s_list_dir, fd_t fd, list_directory_result *result);
SYS_CALL(20, int, _s_access, const char *path, int64_t mode);

SYS_CALL(22, int, _s_unlink, const char *target)
SYS_CALL(23, int, _s_mkdir, const char *path)
SYS_CALL(24, int, _s_rmdir, const char *path)
SYS_CALL(25, int, _s_rename, const char *src, const char *target);
SYS_CALL(26, int, _s_create, const char *filepath)
SYS_CALL(27, int, _s_link, const char *src, const char *target)
SYS_CALL(28, int, _s_symbolink, const char *src, const char *target, uint64_t flags);
SYS_CALL(29, int, _s_mount, const char *dev, const char *mount_point, const char *fs_type, uint64_t flags,
         const char *data, uint64_t size)
SYS_CALL(30, int, _s_umount, const char *mount_point)

#define FUTEX_WAIT 1
#define FUTEX_WAKE 2

SYS_CALL(31, int, _s_futex, int *ptr, int op, int val, const time_clock *timeout);
SYS_CALL(32, [[noreturn]] void, _s_exit, int64_t ret)
SYS_CALL(33, [[noreturn]] void, _s_exit_thread, int64_t ret)
SYS_CALL(34, int, _s_sleep, const time_clock *time)
SYS_CALL(35, int64_t, _s_current_pid)
SYS_CALL(36, int64_t, _s_current_tid)
SYS_CALL(37, int64_t, _s_create_process, const char *filename, char *const args[], uint64_t flags)
SYS_CALL(38, int64_t, _s_create_thread, void *entry, uint64_t arg, uint64_t flags)
SYS_CALL(39, int, _s_detach, int64_t tid)
SYS_CALL(40, int, _s_join, int64_t tid, int64_t *ret)
SYS_CALL(41, int64_t, _s_wait_process, int64_t pid, int64_t *ret)

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

struct sig_info_t
{
    int64_t error;
    int64_t code;
    int64_t status;
    int64_t pid;
    int64_t tid;
};

SYS_CALL(42, int, _s_raise, int signum, sig_info_t *info)

struct sigtarget_t
{
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

SYS_CALL(43, int, _s_sigsend, sigtarget_t *target, int signum, sig_info_t *info)
SYS_CALL(44, void, _s_sigwait, int *num, sig_info_t *info)
SYS_CALL(45, int, _s_sigmask, int opt, sig_mask_t *valid, sig_mask_t *block, sig_mask_t *ignore)

SYS_CALL(46, int, _s_chdir, const char *new_workpath)
SYS_CALL(47, int64_t, _s_current_dir, char *path, uint64_t max_len)
SYS_CALL(48, int, _s_chroot, const char *path)

SYS_CALL(49, int, _s_get_cpu_running)
SYS_CALL(50, void, _s_setcpumask, uint64_t mask0, uint64_t mask1)
SYS_CALL(51, int, _s_getcpumask, uint64_t *mask0, uint64_t *mask1)
SYS_CALL(52, int, _s_tcb_set, void *p);
SYS_CALL(53, int, _s_fork);
SYS_CALL(54, int, _s_execve, const char *path, char *const argv[], char *const envp[]);
SYS_CALL(55, int, _s_clone, void *entry, void *arg, void *tcb);
SYS_CALL(56, int, _s_yield);

SYS_CALL(57, bool, _s_brk, uint64_t ptr)
SYS_CALL(58, uint64_t, _s_sbrk, int64_t offset)

#define MMAP_READ 1
#define MMAP_WRITE 2
#define MMAP_EXEC 4
#define MMAP_FILE 8
#define MMAP_SHARED 16

SYS_CALL(59, void *, _s_mmap, uint64_t start, fd_t fd, uint64_t offset, uint64_t len, uint64_t flags)
SYS_CALL(60, int, _s_mumap, void *addr, uint64_t size)
SYS_CALL(61, int64_t, _s_create_msg_queue, uint64_t msg_count, uint64_t msg_bytes)
SYS_CALL(62, int64_t, _s_write_msg_queue, int64_t key, uint64_t type, const void *buffer, uint64_t size, uint64_t flags)
SYS_CALL(63, int64_t, _s_read_msg_queue, int64_t key, uint64_t type, void *buffer, uint64_t size, uint64_t flags)
SYS_CALL(64, void, _s_close_msg_queue, int64_t key)

#define MSGQUEUE_FLAGS_NOBLOCK 1
#define MSGQUEUE_FLAGS_NOBLOCKOTHER 2

namespace mlibc
{

void sys_libc_log(const char *message) { _s_log(message); }

[[noreturn]] void sys_libc_panic()
{
    sys_libc_log("panic");
    while (true)
    {
        _s_exit(-1);
    }
}

[[noreturn]] void sys_exit(int status) { _s_exit(status); }
int sys_clock_get(int clock, time_t *secs, long *nanos)
{
    time_clock c;
    if (int ret = _s_clock(clock, &c); ret != 0)
    {
        return ret;
    }
    *secs = c.tv_sec;
    *nanos = c.tv_nsec;
    return 0;
}

int sys_tcb_set(void *pointer) { return _s_tcb_set(pointer); }

[[gnu::weak]] int sys_futex_tid() { return 1; }
int sys_futex_wait(int *pointer, int expected, const struct timespec *time)
{
    time_clock c;
    if (time != nullptr)
    {
        c.tv_sec = time->tv_sec;
        c.tv_nsec = time->tv_nsec;
        return _s_futex(pointer, FUTEX_WAIT, expected, &c);
    }
    else
    {
        return _s_futex(pointer, FUTEX_WAIT, expected, nullptr);
    }
}
int sys_futex_wake(int *pointer) { _s_futex(pointer, FUTEX_WAKE, 0, nullptr); }

int sys_anon_allocate(size_t size, void **pointer)
{
    auto p = _s_mmap(0, 0, 0, size, MMAP_READ | MMAP_WRITE);
    if (p == nullptr)
    {
        return -1;
    }
    *pointer = p;
    return 0;
}

int sys_anon_free(void *pointer, size_t size) { return _s_mumap(pointer, size); }

int sys_open(const char *pathname, int flags, mode_t mode, int *fd)
{
    int f = _s_open(pathname, mode, flags);
    if (f > 0)
    {
        *fd = f;
        return 0;
    };
    return f;
}

int sys_read(int fd, void *buf, size_t count, ssize_t *bytes_read)
{
    int64_t ret = _s_read(fd, buf, count, 0);
    if (ret >= 0)
    {
        *bytes_read = ret;
        return 0;
    }
    return ret;
}

int sys_write(int fd, const void *buf, size_t count, ssize_t *bytes_written)
{
    int64_t ret = _s_write(fd, buf, count, 0);
    if (ret >= 0)
    {
        *bytes_written = ret;
        return 0;
    }
    return ret;
}

int sys_seek(int fd, off_t offset, int whence, off_t *new_offset)
{
    int64_t ret = _s_lseek(fd, offset, whence);
    if (ret >= 0)
    {
        *new_offset = ret;
        return 0;
    }
    return ret;
}

int sys_close(int fd) { return _s_close(fd); }

int sys_isatty(int fd) { return _s_istty(fd); }

[[gnu::weak]] int sys_stat(fsfd_target fsfdt, int fd, const char *path, int flags, struct stat *statbuf);
// mlibc assumes that anonymous memory returned by sys_vm_map() is zeroed by the kernel / whatever is behind the sysdeps
int sys_vm_map(void *hint, size_t size, int prot, int flags, int fd, off_t offset, void **window)
{
    auto p = _s_mmap((uint64_t)hint, fd, offset, size, flags);
    if (p == nullptr)
    {
        return -1;
    }
    *window = p;
    return 0;
}
int sys_vm_unmap(void *pointer, size_t size) { return _s_mumap(pointer, size); }

void sys_yield() { _s_yield(); }
int sys_sleep(time_t *secs, long *nanos)
{
    time_clock c;
    memset(&c, 0, sizeof(c));
    if (secs != nullptr)
    {
        c.tv_sec = *secs;
    }
    if (nanos != nullptr)
    {
        c.tv_nsec = *nanos;
    }
    return _s_sleep(&c);
}

int sys_fork(pid_t *child)
{
    int ret = _s_fork();
    *child = ret;
    if (ret < 0)
    {
        return ret;
    }
    return 0;
}

int sys_clone(void *entry, void *user_arg, void *tcb, pid_t *pid_out)
{
    int ret = _s_clone(entry, user_arg, tcb);
    if (ret == 0)
    {
        *pid_out = _s_current_tid();
    };
    return ret;
}

int sys_execve(const char *path, char *const argv[], char *const envp[]) { return _s_execve(path, argv, envp); }

int sys_waitpid(pid_t pid, int *status, int flags, pid_t *ret_pid)
{
    int64_t ret;
    int64_t r = _s_wait_process(pid, &ret);
    *status = ret;
    return r;
}

int sys_access(const char *path, int mode) { return _s_access(path, mode); }

} // namespace mlibc