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

enum core_reloc_primitives_enum {
	A = 0,
	B = 1,
};

struct core_reloc_primitives {
	char a;
	int b;
	enum core_reloc_primitives_enum c;
	void *d;
	int (*f)(const char *);
};

#define CORE_READ(dst, src) bpf_core_read(dst, sizeof(*(dst)), src)

SEC("raw_tracepoint/sys_enter")
int test_btfgen_primitives(void *ctx)
{
	struct core_reloc_primitives *in = (void *)&data.in;
	struct core_reloc_primitives *out = (void *)&data.out;

	if (CORE_READ(&out->a, &in->a))
		return 1;

	return 0;
}
