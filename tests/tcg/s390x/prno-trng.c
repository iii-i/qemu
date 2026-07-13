/*
 * Test that PERFORM RANDOM NUMBER OPERATION with the TRNG subfunction is
 * interruptible: filling a large buffer must not delay signal delivery (and,
 * in the kernel, interrupt handling) until the whole request is done.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <asm/ucontext.h>

/* Large enough that filling it keeps the CPU busy for many timer ticks. */
static unsigned char buf1[16 * 1024 * 1024];
static unsigned char buf2[16 * 1024 * 1024];

static volatile sig_atomic_t interrupted;

static void sigalrm_handler(int sig, siginfo_t *info, void *ucontext)
{
    struct ucontext *uc = ucontext;
    unsigned long addr = uc->uc_mcontext.regs.psw.addr;

    /*
     * Count the interrupts that were taken while prno (0xb93c) was being
     * processed: either on the instruction itself, which is then reissued,
     * or, after a partial completion advanced the PSW, on the branch right
     * behind it that reissues it.
     */
    if (*(unsigned short *)addr == 0xb93c ||
        *(unsigned short *)(addr - 4) == 0xb93c) {
        interrupted++;
    }
}

static void prno_trng(void *b1, unsigned long l1, void *b2, unsigned long l2)
{
    register unsigned long r0 asm("r0") = 0x72; /* TRNG function code */
    register unsigned long r2 asm("r2") = (unsigned long)b1;
    register unsigned long r3 asm("r3") = l1;
    register unsigned long r4 asm("r4") = (unsigned long)b2;
    register unsigned long r5 asm("r5") = l2;

    asm volatile("0: ppno %[r2],%[r4]\n" /* aka prno */
                 "   jo 0b" /* cc 3: partial completion, reissue */
                 : [r2] "+r" (r2), [r3] "+r" (r3),
                   [r4] "+r" (r4), [r5] "+r" (r5)
                 : "r" (r0)
                 : "cc", "memory");
}

int main(void)
{
    struct itimerval it = {
        .it_interval = { .tv_usec = 10000 }, /* 0.01s */
        .it_value = { .tv_usec = 10000 },
    };
    struct sigaction act;

    memset(&act, 0, sizeof(act));
    act.sa_sigaction = sigalrm_handler;
    act.sa_flags = SA_SIGINFO;
    assert(sigaction(SIGALRM, &act, NULL) == 0);
    assert(setitimer(ITIMER_REAL, &it, NULL) == 0);

    prno_trng(buf1, sizeof(buf1), buf2, sizeof(buf2));

    printf("interrupted %d times\n", interrupted);

    /*
     * prno processes a large request in several steps, so the timer must have
     * interrupted it in the middle a number of times. Without interruptibility
     * the whole buffer would be filled in one uninterruptible go.
     */
    assert(interrupted >= 3);

    return EXIT_SUCCESS;
}
