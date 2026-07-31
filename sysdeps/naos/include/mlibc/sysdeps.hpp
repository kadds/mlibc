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
	GetCwd,
	GetPid,
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
	Sleep,
	PrepareStack,
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
