#pragma once

#include <mlibc/sysdep-signatures.hpp>

namespace mlibc {

struct NaosSysdepTags :
	Access,
	AnonAllocate,
	AnonFree,
	Chdir,
	ClockGet,
	Close,
	Clone,
	Dup,
	Dup2,
	Execve,
	Exit,
	Fork,
	FutexTid,
	FutexWait,
	FutexWake,
	GetEgid,
	GetEuid,
	GetCwd,
	GetGid,
	GetPid,
	GetPpid,
	GetUid,
	Isatty,
	Kill,
	LibcLog,
	LibcPanic,
	Mkdir,
	Open,
	OpenDir,
	Pread,
	Pwrite,
	Read,
	ReadEntries,
	Rmdir,
	Seek,
	Sigaction,
	Sigprocmask,
	Sleep,
	PrepareStack,
	Stat,
	TcbSet,
	ThreadExit,
	Unlinkat,
	VmMap,
	VmUnmap,
	Waitpid,
	Write,
	Yield
{};

template<typename Tag>
using Sysdeps = SysdepOf<NaosSysdepTags, Tag>;

struct SysdepTraits {
	static constexpr bool usesRtNetlink = false;
};

} // namespace mlibc
