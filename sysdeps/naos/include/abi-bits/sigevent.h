#ifndef _ABIBITS_SIGEVENT_H
#define _ABIBITS_SIGEVENT_H

#include <abi-bits/sigval.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SIGEV_SIGNAL 0
#define SIGEV_NONE 1
#define SIGEV_THREAD 2

struct sigevent {
	union sigval sigev_value;
	int sigev_notify;
	int sigev_signo;
	void (*sigev_notify_function)(union sigval);
};

#ifdef __cplusplus
}
#endif

#endif /* _ABIBITS_SIGEVENT_H */
