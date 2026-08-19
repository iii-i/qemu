/*
 * SCLP Support
 *
 * Copyright IBM, Corp. 2012
 *
 * Authors:
 *  Christian Borntraeger <borntraeger@de.ibm.com>
 *  Heinz Graalfs <graalfs@linux.vnet.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or (at your
 * option) any later version.  See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu/error-report.h"
#include "qemu/main-loop.h"
#include "qemu/thread.h"
#include "qemu/timer.h"
#include "qapi/error.h"
#include "hw/core/boards.h"
#include "system/memory.h"
#include "system/address-spaces.h"
#include "system/runstate.h"
#include "hw/s390x/sclp.h"
#include "hw/s390x/sclp-fuzz.h"
#include "hw/s390x/event-facility.h"
#include "hw/s390x/s390-pci-bus.h"
#include "hw/s390x/ipl.h"
#include "hw/s390x/cpu-topology.h"
#include "hw/s390x/s390-virtio-ccw.h"

static SCLPDevice *get_sclp_device(void)
{
    static SCLPDevice *sclp;

    if (!sclp) {
        sclp = S390_CCW_MACHINE(qdev_get_machine())->sclp;
    }
    return sclp;
}

/*
 * Host-driven mutation shim (Secure-Execution threat-model fuzzing scaffold).
 *
 * A real malicious hypervisor authors the SCCB bytes the guest parses, and is
 * not bound by the guest-protection checks sclp_service_call() performs. In
 * fuzzer mode QEMU overlays attacker-authored bytes onto the private work_sccb
 * of every targeted command (see sclp_fuzz_target_cmd()) *after* real emulation
 * and *after* QEMU's own boundary checks -- precisely the hostile,
 * invariant-violating response a fuzzer needs to deliver to test the guest's
 * own validation.
 *
 * The whole loop is driven from the host: QEMU keeps event-pending set (see
 * service_interrupt()), so the guest's SCLP driver keeps issuing reads from its
 * own interrupt path -- exactly what an untrusted hypervisor would provoke. No
 * in-guest replay knob and no per-event agent involvement; the agent only sets
 * up KCOV and advertises its buffer once. Each read is issued only after the
 * previous input's dispatch finished, giving a free per-input rendezvous.
 *
 * The overlay bytes are a raw SCCB image (a 2-byte big-endian length, the rest
 * of the header, then a chain of event buffers whose declared lengths are
 * deliberately independent of their real size -- over-read / short-read /
 * chain-walk shapes). Two transports feed them in, picked at READY: an external
 * libFuzzer harness over two pipes (fds in the environment), or an in-process
 * libFuzzer driver linked into QEMU itself (hw/s390x/sclp-fuzz.c), which pre-arms
 * the shim and rendezvouses over a condvar instead. Only the transport differs;
 * the vCPU-side loop below is identical for both.
 */
#define SCLP_FUZZ_CTL_CMD     0x00ff0001 /* reserved: never real SCLP emulation */
#define SCLP_FUZZ_OP_READY    1          /* enter fuzzer mode, advertise KCOV */

/* Size of the folded 8-bit coverage vector shipped to the harness each input. */
#define SCLP_FUZZ_COV_N       4000
/* The guest publishes its KCOV buffer's guest-physical pages so QEMU can read
 * coverage directly (design S6). Bound the page list (each page is 4K, so this
 * caps the buffer at 1M / 128K PCs). */
#define SCLP_FUZZ_COV_MAX_PAGES 256
#define SCLP_FUZZ_COV_PAGE      4096

/* Control block the guest and QEMU exchange over the reserved command
 * (big-endian on the wire). The guest appends the advertised KCOV page list
 * right after this fixed 32-byte prefix, so the layout must stay in sync with
 * the kernel's sclp_fuzz_advertise_cov(). */
typedef struct QEMU_PACKED SclpFuzzCtl {
    SCCBHeader h;
    uint32_t op;
    uint32_t reserved[5];
} SclpFuzzCtl;

static struct {
    bool active;             /* fuzzer mode is on */
    bool stop;               /* transport gone (pipe closed) or vCPU unpark */
    bool have_prev;          /* a previous input's coverage is pending */
    bool inproc;             /* in-process driver transport (vs. pipes) */
    int in_fd;               /* fuzzer -> QEMU: framed scenarios */
    int out_fd;              /* QEMU -> fuzzer: COV_N-byte coverage vectors */
    /* guest KCOV buffer, advertised once via READY, read directly each input */
    uint64_t cov_gpa[SCLP_FUZZ_COV_MAX_PAGES];
    unsigned cov_npages;
    uint64_t cov_words;
    QEMUBH *ev_bh;           /* fast path: one event-pending kick per read */
    QEMUTimer *ev_wd;        /* watchdog: recovers a lost kick if the loop stalls */
    /* in-process rendezvous with the driver's main-loop thread */
    uint8_t *counters;       /* driver's libFuzzer vector; coverage folds here */
    QemuMutex rz_lock;
    QemuCond in_cond;        /* driver publishes an input -> wake vCPU */
    bool in_ready;           /* an unconsumed input sits in slot[] */
    bool cov_ready;          /* the published input's coverage is folded */
    uint8_t slot[SCCB_SIZE]; /* the input the driver published */
    uint32_t slot_len;
} fuzz;

/* Watchdog period: how long the read loop may go quiet before we re-kick it. */
#define SCLP_FUZZ_EV_WATCHDOG_MS 2

/*
 * Keep the guest issuing Read-Event-Data.
 *
 * KVM splits an SCLP service signal into two deliveries: the SCCB *completion*
 * (with the event-pending bits masked off) and a standalone *event-pending*
 * notification. Only the latter makes the guest's driver queue another read
 * (drivers/s390/char/sclp.c gates on evbuf_pending). The event-pending bit is a
 * single collapsing level, so forcing it on completions is not reliable. So we
 * inject a dedicated event-pending signal per read from a bottom half (the fast
 * path), backed by a wall-clock watchdog that re-injects if the loop ever goes
 * quiet -- the fast path drives throughput, the watchdog guarantees liveness.
 */
static void sclp_fuzz_ev_arm(void)
{
    if (fuzz.active && !fuzz.stop) {
        timer_mod(fuzz.ev_wd, qemu_clock_get_ms(QEMU_CLOCK_REALTIME) +
                              SCLP_FUZZ_EV_WATCHDOG_MS);
    }
}

static void sclp_fuzz_ev_kick(void *opaque)
{
    if (fuzz.active && !fuzz.stop) {
        sclp_service_interrupt(0);
    }
}

static void sclp_fuzz_ev_watchdog(void *opaque)
{
    if (fuzz.active && !fuzz.stop) {
        sclp_service_interrupt(0);
        sclp_fuzz_ev_arm();
    }
}

/*
 * Fold this input's guest coverage into an 8-bit vector by reading the guest's
 * KCOV buffer directly from its published guest-physical pages -- no guest-side
 * copy, and off the fuzzed SCLP data path (design S6). cover[0] is the number of
 * PCs; cover[1..] are the PCs. Host and guest are the same (big-endian)
 * architecture under KVM, so the raw words need no swap.
 */
static void sclp_fuzz_read_cov(uint8_t *vec)
{
    g_autofree uint64_t *buf = NULL;
    uint64_t count = 0, w;
    unsigned pages;

    memset(vec, 0, SCLP_FUZZ_COV_N);
    if (!fuzz.cov_npages) {
        return;
    }
    address_space_read(&address_space_memory, fuzz.cov_gpa[0],
                       MEMTXATTRS_UNSPECIFIED, &count, sizeof(count));
    if (count > fuzz.cov_words - 1) {
        count = fuzz.cov_words - 1;
    }
    pages = ((count + 1) * sizeof(uint64_t) + SCLP_FUZZ_COV_PAGE - 1) /
            SCLP_FUZZ_COV_PAGE;
    if (pages > fuzz.cov_npages) {
        pages = fuzz.cov_npages;
    }
    buf = g_malloc(pages * SCLP_FUZZ_COV_PAGE);
    for (unsigned p = 0; p < pages; p++) {
        address_space_read(&address_space_memory, fuzz.cov_gpa[p],
                           MEMTXATTRS_UNSPECIFIED,
                           (uint8_t *)buf + p * SCLP_FUZZ_COV_PAGE,
                           SCLP_FUZZ_COV_PAGE);
    }
    for (w = 1; w <= count; w++) {
        uint64_t h = buf[w];

        h ^= h >> 33;
        h *= 0xff51afd7ed558ccdULL;
        h ^= h >> 29;
        if (vec[h % SCLP_FUZZ_COV_N] != 255) {
            vec[h % SCLP_FUZZ_COV_N]++;
        }
    }
}

/* Blocking pipe I/O from the vCPU thread: drop the BQL so the main loop runs. */
static bool sclp_fuzz_io(int fd, void *buf, size_t n, bool writing)
{
    uint8_t *p = buf;
    size_t off = 0;
    bool held = bql_locked();

    if (held) {
        bql_unlock();
    }
    while (off < n) {
        ssize_t r = writing ? write(fd, p + off, n - off)
                            : read(fd, p + off, n - off);
        if (r < 0 && errno == EINTR) {
            continue;
        }
        if (r <= 0) {
            break;
        }
        off += r;
    }
    if (held) {
        bql_lock();
    }
    return off == n;
}

/*
 * In-process transport (hw/s390x/sclp-fuzz.c). The driver's main-loop thread
 * publishes an input into slot[] and then pumps main_loop_wait until cov_ready;
 * the vCPU thread folds coverage straight into the driver's counter vector, sets
 * cov_ready, and waits on in_cond for the next input. The vCPU never holds the
 * BQL across that wait, so the driver's main_loop_wait can always take it
 * (design S5, S8).
 */
void sclp_fuzz_arm_inprocess(uint8_t *counters)
{
    fuzz.inproc = true;
    fuzz.counters = counters;
    qemu_mutex_init(&fuzz.rz_lock);
    qemu_cond_init(&fuzz.in_cond);
}

void sclp_fuzz_publish_input(const uint8_t *data, size_t size)
{
    qemu_mutex_lock(&fuzz.rz_lock);
    fuzz.slot_len = size > SCCB_SIZE ? SCCB_SIZE : size;
    memcpy(fuzz.slot, data, fuzz.slot_len);
    fuzz.in_ready = true;
    fuzz.cov_ready = false;
    qemu_cond_signal(&fuzz.in_cond);
    qemu_mutex_unlock(&fuzz.rz_lock);
}

bool sclp_fuzz_cov_ready(void)
{
    bool ready;

    qemu_mutex_lock(&fuzz.rz_lock);
    ready = fuzz.cov_ready;
    qemu_mutex_unlock(&fuzz.rz_lock);
    return ready;
}

void sclp_fuzz_request_reboot(void)
{
    /* Wake the vCPU if it is parked for an input, so the reset can pause it. */
    qemu_mutex_lock(&fuzz.rz_lock);
    fuzz.stop = true;
    qemu_cond_signal(&fuzz.in_cond);
    qemu_mutex_unlock(&fuzz.rz_lock);
    qemu_system_reset_request(SHUTDOWN_CAUSE_HOST_QMP_SYSTEM_RESET);
}

/* Ship the just-folded input's coverage to the transport. false: transport gone. */
static bool sclp_fuzz_ship_cov(void)
{
    uint8_t vec[SCLP_FUZZ_COV_N];

    if (fuzz.inproc) {
        sclp_fuzz_read_cov(fuzz.counters);
        qemu_mutex_lock(&fuzz.rz_lock);
        fuzz.cov_ready = true;
        qemu_mutex_unlock(&fuzz.rz_lock);
        return true;
    }
    sclp_fuzz_read_cov(vec);
    return sclp_fuzz_io(fuzz.out_fd, vec, SCLP_FUZZ_COV_N, true);
}

/* Pull the next input, blocking until it arrives. false: transport gone/stop. */
static bool sclp_fuzz_pull(uint8_t *buf, uint32_t *len)
{
    if (fuzz.inproc) {
        bool held = bql_locked();

        if (held) {
            bql_unlock();
        }
        qemu_mutex_lock(&fuzz.rz_lock);
        while (!fuzz.in_ready && !fuzz.stop) {
            qemu_cond_wait(&fuzz.in_cond, &fuzz.rz_lock);
        }
        if (fuzz.in_ready) {
            *len = fuzz.slot_len;
            memcpy(buf, fuzz.slot, *len);
            fuzz.in_ready = false;
        }
        qemu_mutex_unlock(&fuzz.rz_lock);
        if (held) {
            bql_lock();
        }
        return !fuzz.stop;
    }
    if (!sclp_fuzz_io(fuzz.in_fd, len, sizeof(*len), false)) {
        return false;
    }
    if (*len > SCCB_SIZE) {
        *len = SCCB_SIZE;
    }
    return !*len || sclp_fuzz_io(fuzz.in_fd, buf, *len, false);
}

/*
 * The reserved control command's only op: READY. It arms fuzzer mode -- the
 * in-process driver pre-armed the shim (sclp_fuzz_arm_inprocess), or the
 * external harness passed pipe fds via the environment -- and records the guest
 * KCOV buffer's guest-physical pages, which the guest kernel advertised in this
 * SCCB after the fixed prefix ({u64 npages, u64 words, gpa[]}). Its completion
 * interrupt -- with event-pending forced on (see service_interrupt()) -- kicks
 * off the host-driven read loop.
 *
 * READY is repeatable: after a guest death the in-process driver re-IPLs it, the
 * agent re-runs, and this re-records the new boot's KCOV pages and re-arms the
 * loop. The rendezvous slot is deliberately left untouched, so an input the
 * driver published across the reboot survives to the first read (design S6).
 */
static void sclp_fuzz_control(SCCB *sccb)
{
    const char *in = getenv("SCLP_FUZZ_IN_FD");
    const char *out = getenv("SCLP_FUZZ_OUT_FD");
    uint64_t *pub = (uint64_t *)((uint8_t *)sccb + sizeof(SclpFuzzCtl));
    unsigned i;

    if (!fuzz.inproc && in && out) {
        fuzz.in_fd = atoi(in);
        fuzz.out_fd = atoi(out);
    }
    if (fuzz.inproc || (in && out)) {
        fuzz.active = true;
        fuzz.stop = false;
        fuzz.have_prev = false;
        if (!fuzz.ev_bh) {
            fuzz.ev_bh = qemu_bh_new(sclp_fuzz_ev_kick, NULL);
            fuzz.ev_wd = timer_new_ms(QEMU_CLOCK_REALTIME,
                                      sclp_fuzz_ev_watchdog, NULL);
        }
        qemu_bh_schedule(fuzz.ev_bh);
        sclp_fuzz_ev_arm();
        fuzz.cov_npages = be64_to_cpu(pub[0]);
        fuzz.cov_words = be64_to_cpu(pub[1]);
        if (fuzz.cov_npages > SCLP_FUZZ_COV_MAX_PAGES) {
            fuzz.cov_npages = SCLP_FUZZ_COV_MAX_PAGES;
        }
        for (i = 0; i < fuzz.cov_npages; i++) {
            fuzz.cov_gpa[i] = be64_to_cpu(pub[2 + i]);
        }
        info_report("sclp-fuzz: fuzzer mode (%s, kcov %u pages / %" PRIu64
                    " words)", fuzz.inproc ? "in-process" : "pipe",
                    fuzz.cov_npages, fuzz.cov_words);
    }
    sccb->h.response_code = cpu_to_be16(SCLP_RC_NORMAL_COMPLETION);
}

/*
 * Commands whose host-authored response we overlay. Read-Event-Data is the
 * async event path; the read-info commands are guest-initiated request/response
 * whose responses are fixed structs the guest walks by host-controlled
 * counts/offsets (e.g. sclp_fill_core_info()'s memcpy off ->offset_configured).
 * A fuzzed event can itself provoke one of these (an EVTYP_CONFMGMDATA event ->
 * sclp_conf_receiver_fn -> smp_rescan_cpus -> Read-CPU-Info), so overlaying them
 * too lets that whole chain be driven hostile, steered by coverage. The write
 * commands (console, event-mask handshake) are deliberately left honest so the
 * SCLP control plane keeps working.
 */
static bool sclp_fuzz_target_cmd(uint32_t code)
{
    switch (code & SCLP_CMD_CODE_MASK) {
    case SCLP_CMD_READ_EVENT_DATA:
    case SCLP_CMDW_READ_CPU_INFO:
    case SCLP_CMDW_READ_SCP_INFO:
    case SCLP_CMDW_READ_SCP_INFO_FORCED:
        return true;
    default:
        return false;
    }
}

/*
 * Host-driven event/response injection + coverage read, done at each targeted
 * command.
 *
 * In fuzzer mode QEMU keeps event-pending set (service_interrupt()), so the
 * guest's own SCLP driver loops "dispatch previous event, then read the next
 * one" entirely in its interrupt path -- the same code an untrusted hypervisor
 * would drive. Each targeted command is therefore issued only *after* the
 * previous input's dispatch finished, which is exactly the rendezvous we need:
 * read+ship that input's coverage, pull the next input from the harness, reset
 * the guest's coverage counter, and overlay the input onto this response.
 *
 * No in-guest replay knob, no marker, no per-event agent involvement.
 */
static void sclp_fuzz_mutate(SCCB *work_sccb, uint32_t code, uint16_t cap)
{
    uint8_t input[SCCB_SIZE];
    uint64_t zero = 0;
    uint32_t len = 0;

    if (!sclp_fuzz_target_cmd(code)) {
        return;
    }
    if (!fuzz.active || fuzz.stop) {
        return;
    }

    /* The previous input's dispatch is done; ship its coverage. */
    if (fuzz.have_prev && !sclp_fuzz_ship_cov()) {
        fuzz.stop = true;
        return;
    }

    /* Pull the next input (blocks until the transport delivers one). */
    if (!sclp_fuzz_pull(input, &len)) {
        fuzz.stop = true;
        return;
    }

    /* Reset the guest coverage count, then overlay the input for this read. */
    address_space_write(&address_space_memory, fuzz.cov_gpa[0],
                        MEMTXATTRS_UNSPECIFIED, &zero, sizeof(zero));
    memcpy(work_sccb, input, len > cap ? cap : len);
    /*
     * Force a "successful" response code so the guest actually parses our bytes
     * rather than dropping them: Read-Event-Data completion is 0x0020, the
     * read-info commands report 0x0010. The payload the guest then walks (the
     * evbuf chain, or the read-info struct's counts/offsets) stays fully
     * attacker-controlled -- that is what we fuzz.
     */
    work_sccb->h.response_code = cpu_to_be16(
        (code & SCLP_CMD_CODE_MASK) == SCLP_CMD_READ_EVENT_DATA ?
        SCLP_RC_NORMAL_COMPLETION : SCLP_RC_NORMAL_READ_COMPLETION);
    fuzz.have_prev = true;

    /* Ensure the guest issues the next read; push the watchdog out. */
    qemu_bh_schedule(fuzz.ev_bh);
    sclp_fuzz_ev_arm();
}

static inline bool sclp_command_code_valid(uint32_t code)
{
    switch (code & SCLP_CMD_CODE_MASK) {
    case SCLP_CMDW_READ_SCP_INFO:
    case SCLP_CMDW_READ_SCP_INFO_FORCED:
    case SCLP_CMDW_READ_CPU_INFO:
    case SCLP_CMDW_CONFIGURE_IOA:
    case SCLP_CMDW_DECONFIGURE_IOA:
    case SCLP_CMD_READ_EVENT_DATA:
    case SCLP_CMD_WRITE_EVENT_DATA:
    case SCLP_CMD_WRITE_EVENT_MASK:
        return true;
    }
    return false;
}

static bool sccb_verify_boundary(uint64_t sccb_addr, uint16_t sccb_len,
                                 uint32_t code)
{
    uint64_t sccb_max_addr = sccb_addr + sccb_len - 1;
    uint64_t sccb_boundary = (sccb_addr & TARGET_PAGE_MASK) + TARGET_PAGE_SIZE;

    switch (code & SCLP_CMD_CODE_MASK) {
    case SCLP_CMDW_READ_SCP_INFO:
    case SCLP_CMDW_READ_SCP_INFO_FORCED:
    case SCLP_CMDW_READ_CPU_INFO:
        /*
         * An extended-length SCCB is only allowed for Read SCP/CPU Info and
         * is allowed to exceed the 4k boundary. The respective commands will
         * set the length field to the required length if an insufficient
         * SCCB length is provided.
         */
        if (s390_has_feat(S390_FEAT_EXTENDED_LENGTH_SCCB)) {
            return true;
        }
        /* fallthrough */
    default:
        if (sccb_max_addr < sccb_boundary) {
            return true;
        }
    }

    return false;
}

static void prepare_cpu_entries(MachineState *ms, CPUEntry *entry, int *count)
{
    uint8_t features[SCCB_CPU_FEATURE_LEN] = { 0 };
    int i;

    s390_get_feat_block(S390_FEAT_TYPE_SCLP_CPU, features);
    for (i = 0, *count = 0; i < ms->possible_cpus->len; i++) {
        if (!ms->possible_cpus->cpus[i].cpu) {
            continue;
        }
        entry[*count].address = ms->possible_cpus->cpus[i].arch_id;
        entry[*count].type = 0;
        memcpy(entry[*count].features, features, sizeof(features));
        (*count)++;
    }
}

#define SCCB_REQ_LEN(s, max_cpus) (sizeof(s) + max_cpus * sizeof(CPUEntry))

static inline bool ext_len_sccb_supported(SCCBHeader header)
{
    return s390_has_feat(S390_FEAT_EXTENDED_LENGTH_SCCB) &&
           header.control_mask[2] & SCLP_VARIABLE_LENGTH_RESPONSE;
}

/* Provide information about the configuration, CPUs and storage */
static void read_SCP_info(SCLPDevice *sclp, SCCB *sccb)
{
    ReadInfo *read_info = (ReadInfo *) sccb;
    MachineState *machine = MACHINE(qdev_get_machine());
    int cpu_count;
    int rnmax;
    int required_len = SCCB_REQ_LEN(ReadInfo, machine->possible_cpus->len);
    int offset_cpu = s390_has_feat(S390_FEAT_EXTENDED_LENGTH_SCCB) ?
                     offsetof(ReadInfo, entries) :
                     SCLP_READ_SCP_INFO_FIXED_CPU_OFFSET;
    CPUEntry *entries_start = (void *)sccb + offset_cpu;

    if (be16_to_cpu(sccb->h.length) < required_len) {
        if (ext_len_sccb_supported(sccb->h)) {
            sccb->h.length = cpu_to_be16(required_len);
        }
        sccb->h.response_code = cpu_to_be16(SCLP_RC_INSUFFICIENT_SCCB_LENGTH);
        return;
    }

    if (s390_has_topology()) {
        read_info->stsi_parm = SCLP_READ_SCP_INFO_MNEST;
    }

    /* CPU information */
    prepare_cpu_entries(machine, entries_start, &cpu_count);
    read_info->entries_cpu = cpu_to_be16(cpu_count);
    read_info->offset_cpu = cpu_to_be16(offset_cpu);
    read_info->highest_cpu = cpu_to_be16(machine->smp.max_cpus - 1);

    read_info->ibc_val = cpu_to_be32(s390_get_ibc_val());

    /* Configuration Characteristic (Extension) */
    s390_get_feat_block(S390_FEAT_TYPE_SCLP_CONF_CHAR,
                         read_info->conf_char);
    s390_get_feat_block(S390_FEAT_TYPE_SCLP_CONF_CHAR_EXT,
                         read_info->conf_char_ext);

    if (s390_has_feat(S390_FEAT_EXTENDED_LENGTH_SCCB)) {
        s390_get_feat_block(S390_FEAT_TYPE_SCLP_FAC134,
                            &read_info->fac134);
        s390_get_feat_block(S390_FEAT_TYPE_SCLP_FAC139,
                            &read_info->fac139);
    }

    read_info->facilities = cpu_to_be64(SCLP_HAS_CPU_INFO |
                                        SCLP_HAS_IOA_RECONFIG);

    read_info->mha_pow = s390_get_mha_pow();
    read_info->hmfai = cpu_to_be32(s390_get_hmfai());
    read_info->rnsize = 1;

    /*
     * We don't support standby memory. maxram_size is used for sizing the
     * memory device region, which is not exposed through SCLP but through
     * diag500.
     */
    rnmax = machine->ram_size >> 20;
    if (rnmax < 0x10000) {
        read_info->rnmax = cpu_to_be16(rnmax);
    } else {
        read_info->rnmax = cpu_to_be16(0);
        read_info->rnmax2 = cpu_to_be64(rnmax);
    }

    s390_ipl_convert_loadparm((char *)S390_CCW_MACHINE(machine)->loadparm,
                                read_info->loadparm);

    sccb->h.response_code = cpu_to_be16(SCLP_RC_NORMAL_READ_COMPLETION);
}

/* Provide information about the CPU */
static void sclp_read_cpu_info(SCLPDevice *sclp, SCCB *sccb)
{
    MachineState *machine = MACHINE(qdev_get_machine());
    ReadCpuInfo *cpu_info = (ReadCpuInfo *) sccb;
    int cpu_count;
    int required_len = SCCB_REQ_LEN(ReadCpuInfo, machine->possible_cpus->len);

    if (be16_to_cpu(sccb->h.length) < required_len) {
        if (ext_len_sccb_supported(sccb->h)) {
            sccb->h.length = cpu_to_be16(required_len);
        }
        sccb->h.response_code = cpu_to_be16(SCLP_RC_INSUFFICIENT_SCCB_LENGTH);
        return;
    }

    prepare_cpu_entries(machine, cpu_info->entries, &cpu_count);
    cpu_info->nr_configured = cpu_to_be16(cpu_count);
    cpu_info->offset_configured = cpu_to_be16(offsetof(ReadCpuInfo, entries));
    cpu_info->nr_standby = cpu_to_be16(0);

    /* The standby offset is 16-byte for each CPU */
    cpu_info->offset_standby = cpu_to_be16(cpu_info->offset_configured
        + cpu_info->nr_configured*sizeof(CPUEntry));


    sccb->h.response_code = cpu_to_be16(SCLP_RC_NORMAL_READ_COMPLETION);
}

static void sclp_configure_io_adapter(SCLPDevice *sclp, SCCB *sccb,
                                      bool configure)
{
    int rc;

    if (be16_to_cpu(sccb->h.length) < 16) {
        rc = SCLP_RC_INSUFFICIENT_SCCB_LENGTH;
        goto out_err;
    }

    switch (((IoaCfgSccb *)sccb)->atype) {
    case SCLP_RECONFIG_PCI_ATYPE:
        if (s390_has_feat(S390_FEAT_ZPCI)) {
            if (configure) {
                s390_pci_sclp_configure(sccb);
            } else {
                s390_pci_sclp_deconfigure(sccb);
            }
            return;
        }
        /* fallthrough */
    default:
        rc = SCLP_RC_ADAPTER_TYPE_NOT_RECOGNIZED;
    }

 out_err:
    sccb->h.response_code = cpu_to_be16(rc);
}

static void sclp_execute(SCLPDevice *sclp, SCCB *sccb, uint32_t code)
{
    SCLPDeviceClass *sclp_c = SCLP_GET_CLASS(sclp);
    SCLPEventFacility *ef = sclp->event_facility;
    SCLPEventFacilityClass *efc = EVENT_FACILITY_GET_CLASS(ef);

    switch (code & SCLP_CMD_CODE_MASK) {
    case SCLP_CMDW_READ_SCP_INFO:
    case SCLP_CMDW_READ_SCP_INFO_FORCED:
        sclp_c->read_SCP_info(sclp, sccb);
        break;
    case SCLP_CMDW_READ_CPU_INFO:
        sclp_c->read_cpu_info(sclp, sccb);
        break;
    case SCLP_CMDW_CONFIGURE_IOA:
        sclp_configure_io_adapter(sclp, sccb, true);
        break;
    case SCLP_CMDW_DECONFIGURE_IOA:
        sclp_configure_io_adapter(sclp, sccb, false);
        break;
    default:
        efc->command_handler(ef, sccb, code);
        break;
    }
}

/*
 * We only need the address to have something valid for the
 * service_interrupt call.
 */
#define SCLP_PV_DUMMY_ADDR 0x4000
int sclp_service_call_protected(S390CPU *cpu, uint64_t sccb, uint32_t code)
{
    CPUS390XState *env = &cpu->env;
    SCLPDevice *sclp = get_sclp_device();
    SCLPDeviceClass *sclp_c = SCLP_GET_CLASS(sclp);
    SCCBHeader header;
    g_autofree SCCB *work_sccb = NULL;

    s390_cpu_pv_mem_read(env_archcpu(env), 0, &header, sizeof(SCCBHeader));

    work_sccb = g_malloc0(be16_to_cpu(header.length));
    s390_cpu_pv_mem_read(env_archcpu(env), 0, work_sccb,
                         be16_to_cpu(header.length));

    if ((code & SCLP_CMD_CODE_MASK) == SCLP_FUZZ_CTL_CMD) {
        sclp_fuzz_control(work_sccb);
        goto out_write;
    }

    if (!sclp_command_code_valid(code)) {
        work_sccb->h.response_code = cpu_to_be16(SCLP_RC_INVALID_SCLP_COMMAND);
        goto out_write;
    }

    sclp_c->execute(sclp, work_sccb, code);
out_write:
    sclp_fuzz_mutate(work_sccb, code, be16_to_cpu(header.length));
    s390_cpu_pv_mem_write(env_archcpu(env), 0, work_sccb,
                          be16_to_cpu(work_sccb->h.length));
    sclp_c->service_interrupt(sclp, SCLP_PV_DUMMY_ADDR);
    return 0;
}

int sclp_service_call(S390CPU *cpu, uint64_t sccb, uint32_t code)
{
    CPUS390XState *env = &cpu->env;
    SCLPDevice *sclp = get_sclp_device();
    SCLPDeviceClass *sclp_c = SCLP_GET_CLASS(sclp);
    SCCBHeader header;
    g_autofree SCCB *work_sccb = NULL;
    AddressSpace *as = CPU(cpu)->as;
    const MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;
    MemTxResult ret;

    /* first some basic checks on program checks */
    if (env->psw.mask & PSW_MASK_PSTATE) {
        return -PGM_PRIVILEGED;
    }
    if (address_space_is_io(CPU(cpu)->as, sccb)) {
        return -PGM_ADDRESSING;
    }
    if ((sccb & ~0x1fffUL) == 0 || (sccb & ~0x1fffUL) == env->psa
        || (sccb & ~0x7ffffff8UL) != 0) {
        return -PGM_SPECIFICATION;
    }

    /* the header contains the actual length of the sccb */
    ret = address_space_read(as, sccb, attrs, &header, sizeof(SCCBHeader));
    if (ret != MEMTX_OK) {
        return -PGM_ADDRESSING;
    }

    /* Valid sccb sizes */
    if (be16_to_cpu(header.length) < sizeof(SCCBHeader)) {
        return -PGM_SPECIFICATION;
    }

    /*
     * we want to work on a private copy of the sccb, to prevent guests
     * from playing dirty tricks by modifying the memory content after
     * the host has checked the values.
     * Reuse the previously fetched header
     */
    work_sccb = g_malloc0(be16_to_cpu(header.length));
    ret = address_space_read(as, sccb, attrs,
                            work_sccb, be16_to_cpu(header.length));
    if (ret != MEMTX_OK) {
        return -PGM_ADDRESSING;
    }
    work_sccb->h = header;

    if ((code & SCLP_CMD_CODE_MASK) == SCLP_FUZZ_CTL_CMD) {
        sclp_fuzz_control(work_sccb);
        goto out_write;
    }

    if (!sclp_command_code_valid(code)) {
        work_sccb->h.response_code = cpu_to_be16(SCLP_RC_INVALID_SCLP_COMMAND);
        goto out_write;
    }

    if (!sccb_verify_boundary(sccb, be16_to_cpu(work_sccb->h.length), code)) {
        work_sccb->h.response_code = cpu_to_be16(SCLP_RC_SCCB_BOUNDARY_VIOLATION);
        goto out_write;
    }

    sclp_c->execute(sclp, work_sccb, code);
out_write:
    sclp_fuzz_mutate(work_sccb, code, be16_to_cpu(header.length));
    ret = address_space_write(as, sccb, attrs,
                              work_sccb, be16_to_cpu(header.length));
    if (ret != MEMTX_OK) {
        return -PGM_PROTECTION;
    }

    sclp_c->service_interrupt(sclp, sccb);

    return 0;
}

static void service_interrupt(SCLPDevice *sclp, uint32_t sccb)
{
    SCLPEventFacility *ef = sclp->event_facility;
    SCLPEventFacilityClass *efc = EVENT_FACILITY_GET_CLASS(ef);

    uint32_t param = sccb & ~3;

    /* Indicate whether an event is still pending */
    param |= efc->event_pending(ef) ? 1 : 0;

    /*
     * In fuzzer mode, always report an event pending so the guest's SCLP driver
     * re-arms and issues the next Read-Event-Data from its own interrupt path.
     * That self-sustaining loop is what lets the host drive every input without
     * an in-guest agent in the loop (see the shim comment above).
     */
    if (fuzz.active && !fuzz.stop) {
        param |= 1;
    }

    if (!param) {
        /* No need to send an interrupt, there's nothing to be notified about */
        return;
    }
    s390_sclp_extint(param);
}

void sclp_service_interrupt(uint32_t sccb)
{
    SCLPDevice *sclp = get_sclp_device();
    SCLPDeviceClass *sclp_c = SCLP_GET_CLASS(sclp);

    sclp_c->service_interrupt(sclp, sccb);
}

/* qemu object creation and initialization functions */
static void sclp_realize(DeviceState *dev, Error **errp)
{
    SCLPDevice *sclp = SCLP(dev);

    /*
     * qdev_device_add searches the sysbus for TYPE_SCLP_EVENTS_BUS. As long
     * as we can't find a fitting bus via the qom tree, we have to add the
     * event facility to the sysbus, so e.g. a sclp console can be created.
     */
    if (!sysbus_realize(SYS_BUS_DEVICE(sclp->event_facility), errp)) {
        return;
    }
}

static void sclp_init(Object *obj)
{
    SCLPDevice *sclp = SCLP(obj);
    Object *new;

    new = object_new(TYPE_SCLP_EVENT_FACILITY);
    object_property_add_child(obj, TYPE_SCLP_EVENT_FACILITY, new);
    object_unref(new);
    sclp->event_facility = EVENT_FACILITY(new);
}

static void sclp_class_init(ObjectClass *oc, const void *data)
{
    SCLPDeviceClass *sc = SCLP_CLASS(oc);
    DeviceClass *dc = DEVICE_CLASS(oc);

    dc->desc = "SCLP (Service-Call Logical Processor)";
    dc->realize = sclp_realize;
    dc->hotpluggable = false;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    /*
     * Reason: Creates TYPE_SCLP_EVENT_FACILITY in sclp_init
     * which is a non-pluggable sysbus device
     */
    dc->user_creatable = false;

    sc->read_SCP_info = read_SCP_info;
    sc->read_cpu_info = sclp_read_cpu_info;
    sc->execute = sclp_execute;
    sc->service_interrupt = service_interrupt;
}

static const TypeInfo sclp_info = {
    .name = TYPE_SCLP,
    .parent = TYPE_DEVICE,
    .instance_init = sclp_init,
    .instance_size = sizeof(SCLPDevice),
    .class_init = sclp_class_init,
    .class_size = sizeof(SCLPDeviceClass),
};

static void register_types(void)
{
    type_register_static(&sclp_info);
}
type_init(register_types);
