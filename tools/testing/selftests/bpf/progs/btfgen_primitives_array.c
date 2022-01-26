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

struct core_reloc_arrays_substruct {
	int c;
	int d;
};

struct core_reloc_arrays {
	int a[5];
	char b[2][3][4];
	struct core_reloc_arrays_substruct c[3];
	struct core_reloc_arrays_substruct d[1][2];
	struct core_reloc_arrays_substruct f[][2];
};
#define CORE_READ(dst, src) bpf_core_read(dst, sizeof(*(dst)), src)

SEC("raw_tracepoint/sys_enter")
int test_btfgen_primitives(void *ctx)
{
	struct core_reloc_arrays *in = (void *)&data.in;
	struct core_reloc_arrays *out = (void *)&data.out;

	if (CORE_READ(&out->a[0], &in->a[0]))
		return 1;

	return 0;
}
