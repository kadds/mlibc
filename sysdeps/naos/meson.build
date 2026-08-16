sysdep_supported_options = {
	'posix': true,
}

rtld_sources += files(
	'generic/generic.cpp'
)

libc_sources += files(
	'generic/generic.cpp',
	'generic/entry.cpp'
)

if not no_headers
	install_headers(
		'include/abi-bits/auxv.h',
		'include/abi-bits/seek-whence.h',
		'include/abi-bits/vm-flags.h',
		'include/abi-bits/errno.h',
		'include/abi-bits/fcntl.h',
		'include/abi-bits/in.h',
		'include/abi-bits/resource.h',
		'include/abi-bits/stat.h',
		'include/abi-bits/signal.h',
		'include/abi-bits/socket.h',
		'include/abi-bits/termios.h',
		'include/abi-bits/time.h',
		'include/abi-bits/blkcnt_t.h',
		'include/abi-bits/blksize_t.h',
		'include/abi-bits/dev_t.h',
		'include/abi-bits/gid_t.h',
		'include/abi-bits/ino_t.h',
		'include/abi-bits/mode_t.h',
		'include/abi-bits/nlink_t.h',
		'include/abi-bits/pid_t.h',
		'include/abi-bits/uid_t.h',
		'include/abi-bits/access.h',
		'include/abi-bits/aio.h',
		'include/abi-bits/fd_set.h',
		'include/abi-bits/wait.h',
		'include/abi-bits/ipc.h',
		'include/abi-bits/msg.h',
		'include/abi-bits/rlim_t.h',
		'include/abi-bits/route.h',
		'include/abi-bits/sa_family_t.h',
		'include/abi-bits/sched_param.h',
		'include/abi-bits/sem.h',
		'include/abi-bits/sig-limits.h',
		'include/abi-bits/sigevent.h',
		'include/abi-bits/sigset_t.h',
		'include/abi-bits/sigval.h',
		'include/abi-bits/utsname.h',
		'include/abi-bits/utmp-defines.h',
		'include/abi-bits/utmpx.h',
		subdir: 'abi-bits',
		follow_symlinks: true
	)
	install_headers(
		'include/naos/fcntl.h',
		subdir: 'naos'
	)
	install_headers(
		'../../../../include/naos/framebuffer.h',
		subdir: 'naos'
	)
	install_headers(
		'../../../../include/linux/fb.h',
		subdir: 'linux'
	)
endif

if not headers_only
	crt = custom_target('crt1',
		build_by_default: true,
		command: c_compiler.cmd_array() + ['-c', '-o', '@OUTPUT@', '@INPUT@'],
		input: 'crt-x86_64/crt1.S',
		output: 'crt1.o',
		install: true,
		install_dir: get_option('libdir')
	)
endif
