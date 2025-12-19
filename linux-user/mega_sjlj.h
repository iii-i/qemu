#ifndef LINUX_USER_MEGA_SJLJ_H
#define LINUX_USER_MEGA_SJLJ_H

struct mega_jmp_buf {
    char buf[1320];
};

void mega_setjmp(struct mega_jmp_buf *env, void (*func)(void *), void *arg);
void __attribute__((noreturn)) mega_longjmp(struct mega_jmp_buf *env);

void mega_set_state(struct mega_jmp_buf *env,
                    unsigned long pswm,
                    unsigned long pswa,
                    const unsigned long gprs[static 16],
                    const unsigned int acrs[static 16],
                    unsigned int fpc,
                    const unsigned long vxrs[static 32][2]);

#endif
