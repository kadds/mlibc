#include "sysdeps/linux/include/abi-bits/seek-whence.h"
#include <abi-bits/seek-whence.h>
#include <abi-bits/stat.h>
#include <abi-bits/vm-flags.h>
#include <bits/ensure.h>
#include <bits/off_t.h>
#include <bits/ssize_t.h>
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

SYS_CALL(0, void, sys_none, void)

#define OPEN_MODE_READ 1
#define OPEN_MODE_WRITE 2
#define OPEN_MODE_BIN 4
#define OPEN_MODE_APPEND 8

#define STDIN 0
#define STDOUT 1
#define STDERR 2
typedef int fd_t;

#define OPEN_ATTR_AUTO_CREATE_FILE 1

SYS_CALL(2, fd_t, _s_open, const char *path, uint64_t mode, uint64_t attr)
SYS_CALL(3, int, _s_close, fd_t fd);

#define RWFLAGS_NO_BLOCK 1
#define RWFLAGS_OVERRIDE 2

SYS_CALL(4, int64_t, _s_write, fd_t fd, const void *buffer, uint64_t len, uint64_t flags)
SYS_CALL(5, int64_t, _s_read, fd_t fd, void *buffer, uint64_t max_len, uint64_t flags)

#define LSEEK_MODE_CURRENT 0
#define LSEEK_MODE_BEGIN 1
#define LSEEK_MODE_END 2

SYS_CALL(6, int64_t, _s_pwrite, fd_t fd, uint64_t offset, const char *buffer, uint64_t len, uint64_t flags)
SYS_CALL(7, int64_t, _s_pread, fd_t fd, uint64_t offset, char *buffer, uint64_t max_len, uint64_t flags)

SYS_CALL(8, int64_t, _s_lseek, fd_t fd, int64_t offset, int mode)

SYS_CALL(9, int64_t, _s_select, uint64_t size, fd_t *rfd, fd_t *wfd, fd_t *errfd, uint64_t flags)

SYS_CALL(10, int64_t, _s_get_pipe, fd_t *fd1, fd_t *fd2)
SYS_CALL(11, int, _s_create_fifo, const char *path, uint64_t mode)

SYS_CALL(12, int64_t, _s_fcntl, fd_t fd, unsigned int operator_type, unsigned int target, unsigned int attr,
         void *value, uint64_t size)

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

SYS_CALL(16, int, _s_list_directory, fd_t fd, list_directory_result *result);
SYS_CALL(17, int, _s_rename, const char *src, const char *target);
SYS_CALL(18, int, _s_symbolink, const char *src, const char *target, uint64_t flags);

SYS_CALL(19, int, _s_create, const char *filepath)

#define ACCESS_MODE_READ 1
#define ACCESS_MODE_WRITE 2
#define ACCESS_MODE_EXEC 4
#define ACCESS_MODE_EXIST 8

SYS_CALL(20, int, _s_access, int64_t mode)

SYS_CALL(21, int, _s_mkdir, const char *path)
SYS_CALL(22, int, _s_rmdir, const char *path)
SYS_CALL(23, int, _s_chdir, const char *new_workpath)
SYS_CALL(24, int64_t, _s_current_dir, char *path, uint64_t max_len)
SYS_CALL(25, int, _s_chroot, const char *path)
SYS_CALL(26, int, _s_link, const char *src, const char *target)
SYS_CALL(27, int, _s_unlink, const char *target)

SYS_CALL(28, int, _s_mount, const char *dev, const char *mount_point, const char *fs_type, uint64_t flags,
         const char *data, uint64_t size)
SYS_CALL(29, int, _s_umount, const char *mount_point)

SYS_CALL(30, void, _s_exit, int64_t ret)
SYS_CALL(31, void, _s_sleep, uint64_t ms)
SYS_CALL(32, int64_t, _s_current_pid)
SYS_CALL(33, int64_t, _s_current_tid)

#define CP_FLAG_NORETURN 1
#define CP_FLAG_BINARY 2
#define CP_FLAG_SHARED_FILE 8
#define CP_FLAG_SHARED_NOROOT 16
#define CP_FLAG_SHARED_WORK_DIR 32

SYS_CALL(34, int64_t, _s_create_process, const char *filename, char *const args[], uint64_t flags)

#define CT_FLAG_IMMEDIATELY 1
#define CT_FLAG_NORETURN 4

SYS_CALL(35, int64_t, _s_create_thread, void *entry, uint64_t arg, uint64_t flags)
SYS_CALL(36, int, _s_detach, int64_t tid)
SYS_CALL(37, int, _s_join, int64_t tid, int64_t *ret)
SYS_CALL(38, int64_t, _s_wait_process, int64_t pid, int64_t *ret)
SYS_CALL(39, [[noreturn]] void, _s_exit_thread, int64_t ret)

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

SYS_CALL(40, int, _s_raise, int signum, sig_info_t *info)

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

SYS_CALL(41, int, _s_sigsend, sigtarget_t *target, int signum, sig_info_t *info)
SYS_CALL(42, void, _s_sigwait, int *num, sig_info_t *info)
SYS_CALL(43, int, _s_sigmask, int opt, sig_mask_t *valid, sig_mask_t *block, sig_mask_t *ignore)

SYS_CALL(47, int, _s_get_cpu_running)
SYS_CALL(48, void, _s_setcpumask, uint64_t mask0, uint64_t mask1)
SYS_CALL(49, int, _s_getcpumask, uint64_t *mask0, uint64_t *mask1)
SYS_CALL(50, bool, _s_brk, uint64_t ptr)
SYS_CALL(51, uint64_t, _s_sbrk, int64_t offset)

#define MMAP_READ 1
#define MMAP_WRITE 2
#define MMAP_EXEC 4
#define MMAP_FILE 8
#define MMAP_SHARED 16

SYS_CALL(52, void *, _s_mmap, uint64_t start, fd_t fd, uint64_t offset, uint64_t len, uint64_t flags)
SYS_CALL(53, int, _s_mumap, void *addr, uint64_t size)
SYS_CALL(54, int64_t, _s_create_msg_queue, uint64_t msg_count, uint64_t msg_bytes)
SYS_CALL(55, int64_t, _s_write_msg_queue, int64_t key, uint64_t type, const void *buffer, uint64_t size, uint64_t flags)
SYS_CALL(56, int64_t, _s_read_msg_queue, int64_t key, uint64_t type, void *buffer, uint64_t size, uint64_t flags)
SYS_CALL(57, void, _s_close_msg_queue, int64_t key)
SYS_CALL(60, int, _s_tcb_set, void *p);

#define MSGQUEUE_FLAGS_NOBLOCK 1
#define MSGQUEUE_FLAGS_NOBLOCKOTHER 2

namespace mlibc
{

void sys_libc_log(const char *message)
{
    _s_write(STDOUT, message, strlen(message), 0);
    _s_write(STDOUT, "\n", 1, 0);
}

[[noreturn]] void sys_libc_panic()
{
    sys_libc_log("panic");
    while (true)
    {
    }
}

[[noreturn]] void sys_exit(int status) { _s_exit(status); }
int sys_clock_get(int clock, time_t *secs, long *nanos) { return 0; }

int sys_tcb_set(void *pointer) { return _s_tcb_set(pointer); }

[[gnu::weak]] int sys_futex_tid()
{
    sys_libc_log("futex get");
    return 1;
}
int sys_futex_wait(int *pointer, int expected, const struct timespec *time)
{
    sys_libc_log("futex ok");
    return 0;
}
int sys_futex_wake(int *pointer)
{
    sys_libc_log("futex wake");
    return 0;
}

int sys_anon_allocate(size_t size, void **pointer)
{
    sys_libc_log("anon allocate");
    auto p = _s_mmap(0, 0, 0, size, MMAP_READ | MMAP_WRITE);
    if (p == nullptr)
    {
        return -1;
    }
    *pointer = p;
    return 0;
}
int sys_anon_free(void *pointer, size_t size)
{
    sys_libc_log("anon free");
    return _s_mumap(pointer, size);
}

int sys_open(const char *pathname, int flags, mode_t mode, int *fd)
{
    sys_libc_log("open");
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
    sys_libc_log("read");
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
    sys_libc_log("write");
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
    sys_libc_log("seek");
    int64_t ret = _s_lseek(fd, offset, whence);
    if (ret >= 0)
    {
        *new_offset = ret;
        return 0;
    }
    return ret;
}

int sys_close(int fd)
{
    sys_libc_log("close");
    return _s_close(fd);
}

[[gnu::weak]] int sys_stat(fsfd_target fsfdt, int fd, const char *path, int flags, struct stat *statbuf);
// mlibc assumes that anonymous memory returned by sys_vm_map() is zeroed by the kernel / whatever is behind the sysdeps
int sys_vm_map(void *hint, size_t size, int prot, int flags, int fd, off_t offset, void **window)
{
    sys_libc_log("mmap");
    auto p = _s_mmap((uint64_t)hint, fd, offset, size, flags);
    if (p == nullptr)
    {
        return -1;
    }
    *window = p;
    return 0;
}
int sys_vm_unmap(void *pointer, size_t size)
{
    sys_libc_log("unmap");
    return _s_mumap(pointer, size);
}
} // namespace mlibc