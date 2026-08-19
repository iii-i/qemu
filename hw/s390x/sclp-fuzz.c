/*
 * In-process libFuzzer driver for the SCLP host->guest parser.
 *
 * The libFuzzer runtime (libclang_rt.fuzzer_no_main.a) is linked into
 * qemu-system-s390x; this file provides its three entry points and the
 * LLVMFuzzerRunDriver() call that hands QEMU's own thread to libFuzzer once
 * qemu_init() has brought up the machine, KVM and the guest. The mutation shim
 * (hw/s390x/sclp.c) runs on the vCPU thread and drives the guest's SCLP read
 * loop; this driver runs on the main-loop thread and, per input:
 *
 *   1. LLVMFuzzerTestOneInput() publishes the mutated SCCB into the rendezvous
 *      and pumps main_loop_wait() -- servicing KVM, the event-pending kick and
 *      the watchdog -- until the shim has folded the input's guest KCOV coverage
 *      into guest_counters[], the region registered with libFuzzer;
 *   2. on a timeout the guest wedged or crashed: classify the out-of-band log,
 *      save a reproducer for a real KASAN/panic, otherwise re-IPL and continue.
 *
 * There is no second process and no pipe: a guest death costs a re-IPL, not a
 * respawn; a fault in QEMU itself aborts the campaign loudly, as it should
 * (design S6, S7).
 */
#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "qemu/timer.h"
#include "system/replay.h"
#include "hw/s390x/sclp-fuzz.h"

/* Must match SCLP_FUZZ_COV_N in the shim and FUZZ_COV_N in the agent. */
#define COV_N 4000
#define MAX_SCCB 4096

/* The out-of-band crash channel (a virtio-console the guest also logs to),
 * independent of the fuzzed SCLP console -- see the Makefile's fuzz targets. */
#define OOB_LOG "crash-oob.log"

extern void __sanitizer_cov_8bit_counters_init(uint8_t *start, uint8_t *stop);
extern void __sanitizer_cov_pcs_init(const uintptr_t *pcs_beg,
                                     const uintptr_t *pcs_end);
extern int LLVMFuzzerRunDriver(int *argc, char ***argv,
                               int (*cb)(const uint8_t *data, size_t size));
size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t maxsize);

static uint8_t guest_counters[COV_N];
/* libFuzzer wants a PC table matching the counters. Guest PCs mean nothing here
 * (they live in another address space), so fabricate one distinct fake PC per
 * counter; {PC, flags} pairs, flags 0 = a plain edge. */
static uintptr_t guest_pcs[COV_N * 2];
static long resets;        /* times the guest died/hung and we re-IPLed it */
static bool fresh_boot = true; /* next input must tolerate the guest booting */

/* --- crash oracle (design S6, S8) --------------------------------------- */

/* Read up to cap-1 bytes of the OOB log starting at `off`, NUL-terminated. */
static size_t read_from(const char *path, long off, char *buf, size_t cap)
{
    FILE *f = fopen(path, "rb");
    size_t k;

    if (!f) {
        return 0;
    }
    fseek(f, off, SEEK_SET);
    k = fread(buf, 1, cap - 1, f);
    buf[k] = 0;
    fclose(f);
    return k;
}

static long oob_size(void)
{
    FILE *f = fopen(OOB_LOG, "rb");
    long sz;

    if (!f) {
        return 0;
    }
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fclose(f);
    return sz;
}

/*
 * Classify a guest death from what the OOB channel gained since `off` (the log
 * appends across re-IPLs, so a start offset isolates this input's output). On a
 * real crash, fill `bucket` (top-frame function, for dedup) and `desc` (a
 * one-line summary) and return 1; ordinary boot/printk noise returns 0.
 */
static int crash_signature(long off, char *bucket, size_t bn,
                           char *desc, size_t dn)
{
    static char buf[32768];
    char type[64] = "fault", func[160] = "unknown";
    char *k;
    size_t i;

    read_from(OOB_LOG, off, buf, sizeof(buf));

    k = strstr(buf, "BUG: KASAN:");
    if (k) {
        sscanf(k, "BUG: KASAN: %63s in %159[^+ \t\n]", type, func);
        snprintf(desc, dn, "KASAN %s in %s", type, func);
    } else if (strstr(buf, "Kernel panic") || strstr(buf, "Unable to handle") ||
               strstr(buf, "UBSAN") || strstr(buf, "Oops")) {
        /* No KASAN line: fall back to the first sclp_ frame we can see. */
        k = strstr(buf, "sclp_");
        if (k) {
            sscanf(k, "%159[a-zA-Z0-9_]", func);
        }
        snprintf(desc, dn, "panic/oops at %s", func);
    } else {
        return 0;
    }

    /* Dedup bucket = sanitized top-frame function name. */
    for (i = 0; func[i] && i < bn - 1; i++) {
        bucket[i] = (func[i] == '.') ? '_' : func[i];
    }
    bucket[i] = 0;
    return 1;
}

/*
 * The published input wedged the guest. Distinguish a real bug from a benign
 * quiesce/hang via the OOB log: a crash is a finding we save and let libFuzzer
 * record (abort, so it minimizes); a hang is expected in VM fuzzing, so return
 * and let the caller re-IPL. `off` is the OOB size when the input was published.
 */
static bool sclp_fuzz_crash(const uint8_t *data, size_t size, long off)
{
    char bucket[160], desc[256], name[192];
    const char *ignore = getenv("SCLP_FUZZ_IGNORE");
    FILE *f;

    if (!crash_signature(off, bucket, sizeof(bucket), desc, sizeof(desc))) {
        return false;
    }
    /*
     * Ignore-list: a known bug we are not hunting right now
     * (SCLP_FUZZ_IGNORE=<substring of the top frame>). Log it once and re-IPL so
     * the campaign digs past it instead of ending on the first easy crash.
     */
    if (ignore && *ignore && strstr(bucket, ignore)) {
        if (resets % 64 == 0) {
            fprintf(stderr, "sclp-fuzz: ignoring known crash %s\n", desc);
        }
        return false;
    }
    /* Dedup: name the reproducer by the crashing function. */
    snprintf(name, sizeof(name), "crash-%s.bin", bucket);
    f = fopen(name, "wb");
    if (f) {
        fwrite(data, 1, size, f);
        fclose(f);
    }
    f = fopen("crash-report.txt", "a");
    if (f) {
        fprintf(f, "%s  ->  %s (%zu bytes)\n", desc, name, size);
        fclose(f);
    }
    fprintf(stderr, "sclp-fuzz: OOB CRASH: %s -- saved %s\n", desc, name);
    return true;
}

/* --- libFuzzer entry points --------------------------------------------- */

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    for (int i = 0; i < COV_N; i++) {
        guest_pcs[2 * i] = 0x100000 + i; /* fake but distinct PC */
        guest_pcs[2 * i + 1] = 0;        /* flags: plain edge */
    }
    __sanitizer_cov_8bit_counters_init(guest_counters, guest_counters + COV_N);
    __sanitizer_cov_pcs_init(guest_pcs, guest_pcs + COV_N * 2);
    sclp_fuzz_arm_inprocess(guest_counters);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Tolerate a ~5s boot right after a (re)IPL; a live guest answers in
     * milliseconds, so a short deadline makes hangs cheap. */
    int timeout_ms = fresh_boot ? 15000 : 2500;
    int64_t deadline = qemu_clock_get_ms(QEMU_CLOCK_REALTIME) + timeout_ms;
    long off = oob_size();

    if (size > MAX_SCCB) {
        size = MAX_SCCB;
    }
    sclp_fuzz_publish_input(data, size);

    while (!sclp_fuzz_cov_ready()) {
        main_loop_wait(false);
        if (qemu_clock_get_ms(QEMU_CLOCK_REALTIME) < deadline) {
            continue;
        }
        /* Timed out: the guest hit a bug (the oracle) or a host-triggered path
         * that ends the VM. A real crash is a finding; a clean shutdown just
         * re-IPLs and carries on (design S7). */
        if (sclp_fuzz_crash(data, size, off)) {
            abort(); /* let libFuzzer record + minimize the reproducer */
        }
        resets++;
        if (resets % 16 == 1) {
            fprintf(stderr, "sclp-fuzz: guest reset #%ld (hang/host-triggered "
                    "shutdown), re-IPLing\n", resets);
        }
        memset(guest_counters, 0, sizeof(guest_counters));
        fresh_boot = true;
        sclp_fuzz_request_reboot();
        return 0;
    }
    fresh_boot = false;
    return 0;
}

/* --- structure-aware mutator (design S10) ------------------------------- */

static uint32_t xs;
static uint32_t rnd(void)
{
    xs ^= xs << 13;
    xs ^= xs >> 17;
    xs ^= xs << 5;
    return xs;
}

/* A spread of interesting length values, including invalid ones. */
static uint16_t fuzzy_len(void)
{
    switch (rnd() % 6) {
    case 0: return 0;             /* zero: terminates / degenerate */
    case 1: return 6;            /* header-only evbuf */
    case 2: return 8 + rnd() % 24;
    case 3: return 0x80;          /* > planted 16-byte buffer */
    case 4: return 0xfff0;        /* walks past the SCCB */
    default: return rnd() % 4096;
    }
}

/* Event types: bias toward the registered/planted ones plus wild values. */
static uint8_t fuzzy_type(void)
{
    switch (rnd() % 4) {
    case 0: return 0x30;          /* planted receiver */
    case 1: return 0x30 + rnd() % 4;
    case 2: return rnd() & 0xff;
    default: return 0;
    }
}

static void put16(uint8_t *p, uint16_t v)   /* big-endian, like s390 memory */
{
    p[0] = v >> 8;
    p[1] = v & 0xff;
}

size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t maxsize,
                               unsigned seed)
{
    xs = seed ? seed : 0x9e3779b9;

    /* Ensure a valid 8-byte SCCB header exists. */
    if (size < 8) {
        if (maxsize < 8) {
            return size;
        }
        memset(data + size, 0, 8 - size);
        size = 8;
    }

    switch (rnd() % 6) {
    case 0: /* append an event buffer (6-byte header + payload) */
    case 1: {
        size_t pay = rnd() % 24;
        size_t need = 6 + pay;
        if (size + need <= maxsize) {
            uint8_t *e = data + size;
            put16(e, fuzzy_len());       /* declared length (may lie) */
            e[2] = fuzzy_type();
            e[3] = rnd() & 0xff;         /* flags */
            put16(e + 4, 0);            /* reserved */
            for (size_t i = 0; i < pay; i++) {
                e[6 + i] = rnd() & 0xff;
            }
            size += need;
        }
        break;
    }
    case 2: /* chop the tail (short-read shapes) */
        if (size > 8) {
            size = 8 + rnd() % (size - 8);
        }
        break;
    case 3: /* poke a byte in the event-buffer area to a boundary value */
        if (size > 8) {
            size_t off = 8 + rnd() % (size - 8);
            static const uint8_t edge[] = { 0, 1, 6, 8, 0x7f, 0x80, 0xff };
            data[off] = edge[rnd() % sizeof(edge)];
        }
        break;
    case 4: /* set the SCCB length field -- often inconsistent on purpose */
        if (rnd() % 2) {
            put16(data, (uint16_t)size);     /* honest */
        } else {
            put16(data, fuzzy_len());        /* a lie */
        }
        return size;
    default: /* hand off to libFuzzer's byte mutator for raw entropy */
        return LLVMFuzzerMutate(data, size, maxsize);
    }

    /* Most iterations: keep the SCCB length consistent so the dispatch loop
     * actually walks the chain we built (a fraction stay inconsistent via case 4
     * above). */
    put16(data, (uint16_t)size);
    return size;
}

/* --- driver entry ------------------------------------------------------- */

/*
 * Build a libFuzzer argv from the environment and hand this thread to the
 * driver; it runs the whole campaign (corpus, mutation, minimization) and never
 * returns. SCLP_FUZZ_CORPUS is the corpus/seed directory list (a single file for
 * replay); SCLP_FUZZ_ARGS carries libFuzzer flags (-max_len, -max_total_time,
 * ...). qemu_init() already ran, so the machine is up; take the BQL and replay
 * mutex as the normal main loop would, then never give them back.
 */
int sclp_fuzz_run(void)
{
    g_auto(GStrv) flags = g_strsplit(getenv("SCLP_FUZZ_ARGS") ?: "", " ", -1);
    g_auto(GStrv) corpus = g_strsplit(getenv("SCLP_FUZZ_CORPUS") ?: "", " ", -1);
    g_autoptr(GPtrArray) argv = g_ptr_array_new();
    char **av;
    int ac;

    g_ptr_array_add(argv, (char *)"qemu-sclp-fuzz");
    for (char **p = flags; *p; p++) {
        if (**p) {
            g_ptr_array_add(argv, *p);
        }
    }
    for (char **p = corpus; *p; p++) {
        if (**p) {
            g_ptr_array_add(argv, *p);
        }
    }
    g_ptr_array_add(argv, NULL);
    ac = argv->len - 1;
    av = (char **)argv->pdata;

    replay_mutex_lock();
    bql_lock();
    LLVMFuzzerRunDriver(&ac, &av, LLVMFuzzerTestOneInput);
    exit(0);
}
