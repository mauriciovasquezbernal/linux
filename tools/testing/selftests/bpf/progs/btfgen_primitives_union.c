// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <stdint.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

struct {
	char in[256];
	char out[256];
} data = {};

union a_union {
	int y;
	int z;
};

#define CORE_READ(dst, src) bpf_core_read(dst, sizeof(*(dst)), src)

SEC("raw_tracepoint/sys_enter")
int test_btfgen_primitives(void *ctx)
{
	union a_union *in = (void *)&data.in;
	union a_union *out = (void *)&data.out;

	if (CORE_READ(&out->y, &in->y))
		return 1;

	return 0;
}
