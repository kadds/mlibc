#include <bits/ensure.h>
#include <mlibc/elf/startup.h>
#include <stdint.h>
#include <stdlib.h>

// defined by the POSIX library
void __mlibc_initLocale();

// NaOS uses the statically initialized C locale. Keep the legacy startup hook
// for the generic mlibc entry path, but there is nothing to initialize here.
void __mlibc_initLocale() {}

extern "C" uintptr_t *__dlapi_entrystack();
extern "C" void __dlapi_enter(uintptr_t *);

extern char **environ;
static mlibc::exec_stack_data __mlibc_stack_data;

namespace mlibc::naos_native {
int ensure_bootstrap();
}

struct LibraryGuard {
	LibraryGuard();
};

static LibraryGuard guard;

LibraryGuard::LibraryGuard() {
	__mlibc_initLocale();

	// Parse the exec() stack.
	mlibc::parse_exec_stack(__dlapi_entrystack(), &__mlibc_stack_data);
	mlibc::set_startup_data(
	    __mlibc_stack_data.argc, __mlibc_stack_data.argv, __mlibc_stack_data.envp
	);

	// Bootstrap the process namespace before user code can issue its first
	// open/chdir/read call. Syscall wrappers require this startup contract.
	if (mlibc::naos_native::ensure_bootstrap() != 0)
		exit(127);
}

extern "C" {
void __mlibc_entry(uintptr_t *entry_stack, int (*main_fn)(int argc, char *argv[], char *env[])) {
	__dlapi_enter(entry_stack);
	auto result = main_fn(__mlibc_stack_data.argc, __mlibc_stack_data.argv, environ);
	exit(result);
}
}
