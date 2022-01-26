// SPDX-License-Identifier: GPL-2.0-only

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <linux/limits.h>

#include <bpf/libbpf.h>
#include <bpf/btf.h>

#include "bpf_util.h"

static int run_btfgen(const char *src_btf, const char *dst_btf, const char *objspaths[])
{
	char command[4096];
	int ret, i, n;

	n = snprintf(command, sizeof(command),
		     "./tools/build/bpftool/bpftool gen min_core_btf %s %s", src_btf, dst_btf);
	assert(n >= 0 && n < sizeof(command));

	for (i = 0; objspaths[i] != NULL; i++) {
		assert(sizeof(command) - strlen(command) > strlen(objspaths[i]) + 1);
		strcat(command, " ");
		strcat(command, objspaths[i]);
	}

	printf("Executing bpftool: %s\n", command);
	printf("---\n");
	ret = system(command);
	printf("---\n");
	return ret;
}

struct btfgen_test {
	const char *descr;
	const char *src_btf;
	const char *bpfobj[16];
	void (*run_test)(struct btf *btf);
};

static void check_btfgen_primitive_struct(struct btf *btf)
{
	struct btf_member *members;
	const struct btf_type *t;
	int id;

	assert(btf__type_cnt(btf) == 3);

	id = btf__find_by_name_kind(btf, "core_reloc_primitives", BTF_KIND_STRUCT);
	assert(id > 0);

	t = btf__type_by_id(btf, id);
	assert(btf_vlen(t) == 1);

	members = btf_members(t);

	id = btf__find_by_name_kind(btf, "char", BTF_KIND_INT);
	assert(id > 0);

	/* the type of the struct member must be the char */
	assert(members[0].type == id);
}

static void check_btfgen_primitive_union(struct btf *btf)
{
	struct btf_member *members;
	const struct btf_type *t;
	int id;

	/* void, a_union and int*/
	assert(btf__type_cnt(btf) == 3);

	id = btf__find_by_name_kind(btf, "a_union", BTF_KIND_UNION);
	assert(id > 0);

	t = btf__type_by_id(btf, id);
	assert(btf_vlen(t) == 1);

	members = btf_members(t);

	id = btf__find_by_name_kind(btf, "int", BTF_KIND_INT);
	assert(id > 0);

	/* the type of the union member must be the integer */
	assert(members[0].type == id);
}

static void check_btfgen_primitive_array(struct btf *btf)
{
	int array_id, array_type_id, array_index_type_id;
	struct btf_array *array;

	/* void, struct, array, int (array index type) and int (array type) */
	assert(btf__type_cnt(btf) == 5);

	array_id = btf__find_by_name_kind(btf, "", BTF_KIND_ARRAY);
	assert(array_id > 0);

	array = btf_array(btf__type_by_id(btf, array_id));

	array_type_id = btf__find_by_name_kind(btf, "int", BTF_KIND_INT);
	assert(array_type_id > 0);

	array_index_type_id = btf__find_by_name_kind(btf, "__ARRAY_SIZE_TYPE__", BTF_KIND_INT);
	assert(array_index_type_id > 0);

	/* check that array types are the correct ones */
	assert(array->type == array_type_id);
	assert(array->index_type == array_index_type_id);
}

/* If there are relocations in two different BPF objects involving
 * different members of the same struct, then the generated BTF should
 * contain a single instance of such struct with both fields.
 */
static void check_btfgen_primitive_structs_different_objects(struct btf *btf)
{
	struct btf_member *members;
	const struct btf_type *t;
	int struct_id, char_id, int_id;

	/* void, struct, int and char */
	assert(btf__type_cnt(btf) == 4);

	struct_id = btf__find_by_name_kind(btf, "core_reloc_primitives", BTF_KIND_STRUCT);
	assert(struct_id > 0);

	t = btf__type_by_id(btf, struct_id);
	assert(btf_vlen(t) == 2);

	members = btf_members(t);

	char_id = btf__find_by_name_kind(btf, "char", BTF_KIND_INT);
	assert(char_id > 0);

	int_id = btf__find_by_name_kind(btf, "int", BTF_KIND_INT);
	assert(int_id > 0);

	for (int i = 0; i < btf_vlen(t); i++) {
		const char *name = btf__str_by_offset(btf, members[i].name_off);

		if (!strcmp("a", name))
			assert(members[i].type == char_id);
		else if (!strcmp("b", name))
			assert(members[i].type == int_id);
	}
}

static struct btfgen_test btfgen_tests[] = {
	{
		"primitive struct",
		"btfgen_btf_source.o",
		{
			"btfgen_primitives_struct.o",
		},
		check_btfgen_primitive_struct,
	},
	{
		"primitive union",
		"btfgen_btf_source.o",
		{
			"btfgen_primitives_union.o",
		},
		check_btfgen_primitive_union,
	},
	{
		"primitive array",
		"btfgen_btf_source.o",
		{
			"btfgen_primitives_array.o",
		},
		check_btfgen_primitive_array,
	},
	{
		"primitive structs in different objects",
		"btfgen_btf_source.o",
		{
			"btfgen_primitives_struct.o",
			"btfgen_primitives_struct2.o",
		},
		check_btfgen_primitive_structs_different_objects,
	},
};

void test_gen_min_core_btf(void)
{
	char target_path[PATH_MAX];
	struct btfgen_test *test;
	struct btf *dst_btf;
	int ret;

	for (int i = 0; i < ARRAY_SIZE(btfgen_tests); i++) {
		char dir_path[] = "/tmp/btfgen-XXXXXX";

		test = &btfgen_tests[i];

		printf("Running %s\n", test->descr);

		mkdtemp(dir_path);

		snprintf(target_path, sizeof(target_path), "%s/foo.btf", dir_path);

		ret = run_btfgen(test->src_btf, target_path, test->bpfobj);
		assert(ret == 0);

		dst_btf = btf__parse(target_path, NULL);
		assert(dst_btf != NULL);

		test->run_test(dst_btf);

		printf("Test %s: PASS\n", test->descr);
	}

	printf("%s: PASS\n", __func__);
}

int main(void)
{
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	test_gen_min_core_btf();

	printf("test_bpftool: OK\n");

	return 0;
}
