#ifndef _ABIBITS_IOCTLS_H
#define _ABIBITS_IOCTLS_H

/* Linux-compatible tty requests used by the generic mlibc PTY helpers. */
#define TCGETS 0x5401
#define TCSETS 0x5402
#define TCSETSW 0x5403
#define TCSETSF 0x5404
#define TCSBRK 0x5409
#define TCXONC 0x540A
#define TCFLSH 0x540B
#define TIOCSCTTY 0x540E
#define TIOCGPGRP 0x540F
#define TIOCSPGRP 0x5410
#define TIOCGWINSZ 0x5413
#define TIOCSWINSZ 0x5414
#define FIONREAD 0x541B
#define TIOCINQ FIONREAD
#define TIOCNOTTY 0x5422
#define TCSBRKP 0x5425
#define TIOCGSID 0x5429

/* _IOR('T', 0x30, int) and _IOW('T', 0x31, int) in the x86-64 ioctl ABI. */
#define TIOCGPTN 0x80045430
#define TIOCSPTLCK 0x40045431
#define TIOCSPTLGRANT 0x40045432

#define FIONBIO 0x5421
#define FIONCLEX 0x5450
#define FIOCLEX 0x5451

#define SIOCPROTOPRIVATE 0x89E0
#define SIOCGIFNAME 0x8910
#define SIOCGIFCONF 0x8912
#define SIOCGIFFLAGS 0x8913
#define SIOCSIFFLAGS 0x8914
#define SIOCGIFINDEX 0x8933

#endif /* _ABIBITS_IOCTLS_H */
