/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * In-process SCLP fuzzing: the rendezvous the QEMU-embedded libFuzzer driver
 * (hw/s390x/sclp-fuzz.c) and the mutation shim (hw/s390x/sclp.c) share.
 *
 * The shim owns the rendezvous state and the vCPU-thread side; the driver owns
 * libFuzzer and the main-loop side. These are the only symbols that cross the
 * two files.
 */
#ifndef HW_S390X_SCLP_FUZZ_H
#define HW_S390X_SCLP_FUZZ_H

/*
 * Switch the shim's transport from the external-harness pipes to the in-process
 * driver, and hand it the driver's libFuzzer counter vector (SCLP_FUZZ_COV_N
 * bytes) to fold guest coverage into directly. Called once, from
 * LLVMFuzzerInitialize, before the guest boots.
 */
void sclp_fuzz_arm_inprocess(uint8_t *counters);

/* Hand the next input to the vCPU thread and wake it (main-loop thread). */
void sclp_fuzz_publish_input(const uint8_t *data, size_t size);

/* True once the vCPU thread has folded the published input's coverage. */
bool sclp_fuzz_cov_ready(void);

/*
 * Recover a wedged guest: unpark the vCPU thread if it is waiting for an input,
 * then request a re-IPL. The next READY re-arms the loop (main-loop thread).
 */
void sclp_fuzz_request_reboot(void);

/* Driver entry point, called from system/main.c in place of the main loop. */
int sclp_fuzz_run(void);

#endif
