#include <asm/sigcontext.h>
#include <asm/siginfo.h>
#include <asm/signal.h>
#include <asm/ucontext.h>
#include <asm/unistd.h>
#include <string.h>
#include <unistd.h>

#include "qemu/compiler.h"

#include "mega_sjlj.h"

#ifdef __s390x__

struct rt_sigframe
{
    __u8 callee_used_stack[__SIGNAL_FRAMESIZE];
    __u16 svc_insn;
    struct siginfo info;
    struct ucontext_extended uc;
};
QEMU_BUILD_BUG_ON(sizeof(struct rt_sigframe) != sizeof(struct mega_jmp_buf));

static void init(struct rt_sigframe *f)
{
    memset(&f->uc, 0, sizeof(f->uc));
    syscall(__NR_sigaltstack, NULL, &f->uc.uc_stack);
    syscall(__NR_rt_sigprocmask, SIG_SETMASK, NULL, &f->uc.uc_sigmask, sizeof(f->uc.uc_sigmask));
}

void mega_setjmp(struct mega_jmp_buf *env, void (*func)(void *), void *arg)
{
    struct rt_sigframe *f = (struct rt_sigframe *)env->buf;
    _sigregs_ext *ext = &f->uc.uc_mcontext_ext;
    _sigregs *ctx = &f->uc.uc_mcontext;
    int done, tmp;

    init(f);
    asm volatile("epsw %[tmp],%[done]\n"
                 "risbgn %[done],%[tmp],0,64-32-1,32\n"
                 "stg %[done],%[pswm]\n"
                 "larl %[done],0f\n"
                 "stg %[done],%[pswa]\n"
                 "stmg %%r0,%%r15,%[gprs]\n"
                 "stam %%a0,%%a15,%[acrs]\n"
                 "stfpc %[fpc]\n"
                 "stdy %%f0,0*8(%[fprs])\n"
                 "stdy %%f1,1*8(%[fprs])\n"
                 "stdy %%f2,2*8(%[fprs])\n"
                 "stdy %%f3,3*8(%[fprs])\n"
                 "stdy %%f4,4*8(%[fprs])\n"
                 "stdy %%f5,5*8(%[fprs])\n"
                 "stdy %%f6,6*8(%[fprs])\n"
                 "stdy %%f7,7*8(%[fprs])\n"
                 "stdy %%f8,8*8(%[fprs])\n"
                 "stdy %%f9,9*8(%[fprs])\n"
                 "stdy %%f10,10*8(%[fprs])\n"
                 "stdy %%f11,11*8(%[fprs])\n"
                 "stdy %%f12,12*8(%[fprs])\n"
                 "stdy %%f13,13*8(%[fprs])\n"
                 "stdy %%f14,14*8(%[fprs])\n"
                 "stdy %%f15,15*8(%[fprs])\n"
                 "vsteg %%v0,0*16(%[vxrs_low]),1\n"
                 "vsteg %%v1,1*16(%[vxrs_low]),1\n"
                 "vsteg %%v2,2*16(%[vxrs_low]),1\n"
                 "vsteg %%v3,3*16(%[vxrs_low]),1\n"
                 "vsteg %%v4,4*16(%[vxrs_low]),1\n"
                 "vsteg %%v5,5*16(%[vxrs_low]),1\n"
                 "vsteg %%v6,6*16(%[vxrs_low]),1\n"
                 "vsteg %%v7,7*16(%[vxrs_low]),1\n"
                 "vsteg %%v8,8*16(%[vxrs_low]),1\n"
                 "vsteg %%v9,9*16(%[vxrs_low]),1\n"
                 "vsteg %%v10,10*16(%[vxrs_low]),1\n"
                 "vsteg %%v11,11*16(%[vxrs_low]),1\n"
                 "vsteg %%v12,12*16(%[vxrs_low]),1\n"
                 "vsteg %%v13,13*16(%[vxrs_low]),1\n"
                 "vsteg %%v14,14*16(%[vxrs_low]),1\n"
                 "vsteg %%v15,15*16(%[vxrs_low]),1\n"
                 "vstm %%v16,%%v31,%[vxrs_high]\n"
                 "lghi %[done],0\n"
                 "j 1f\n"
                 "0:\n"
                 "lghi %[done],1\n"
                 "1:"
                 : [done] "=&r" (done)
                 , [tmp] "=&r" (tmp)
                 , [pswm] "=T" (ctx->regs.psw.mask)
                 , [pswa] "=T" (ctx->regs.psw.addr)
                 , [gprs] "=S" (ctx->regs.gprs)
                 , [acrs] "=S" (ctx->regs.acrs)
                 , [fpc] "=T" (ctx->fpregs.fpc)
                 , [vxrs_high] "=S" (ext->vxrs_high)
                 : [fprs] "a" (&ctx->fpregs.fprs)
                 , [vxrs_low] "a" (&ext->vxrs_low)
                 : "memory");

    if (!done) {
        func(arg);
    }
}

void __attribute__((noreturn)) mega_longjmp(struct mega_jmp_buf *env)
{
    asm volatile("la %%r15,%[env]\n"
                 "svc %[nr]"
                 :
                 : [env] "R" (*env)
                 , [nr] "i" (__NR_rt_sigreturn));
    __builtin_unreachable();
}

void mega_set_state(struct mega_jmp_buf *env,
                    unsigned long pswm,
                    unsigned long pswa,
                    const unsigned long gprs[static 16],
                    const unsigned int acrs[static 16],
                    unsigned int fpc,
                    const unsigned long vxrs[static 32][2])
{
    struct rt_sigframe *f = (struct rt_sigframe *)env->buf;
    _sigregs_ext *ext = &f->uc.uc_mcontext_ext;
    _sigregs *ctx = &f->uc.uc_mcontext;
    int i;

    init(f);
    ctx->regs.psw.mask = pswm;
    ctx->regs.psw.addr = pswa;
    memcpy(ctx->regs.gprs, gprs, sizeof(ctx->regs.gprs));
    memcpy(ctx->regs.acrs, acrs, sizeof(ctx->regs.acrs));
    ctx->fpregs.fpc = fpc;
    for (i = 0; i < 16; i++) {
        memcpy(&ctx->fpregs.fprs[i], &vxrs[i][0], 8);
        ext->vxrs_low[i] = vxrs[i][1];
    }
    memcpy(&ext->vxrs_high, &vxrs[16], sizeof(ext->vxrs_high));
}

#endif
