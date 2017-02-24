#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include <osmocom/core/utils.h>
#include <osmocom/ctrl/control_cmd.h>

inline void check_type(enum ctrl_type c)
{
	const char *t = get_value_string(ctrl_type_vals, c);
	int v = get_string_value(ctrl_type_vals, t);

	printf("ctrl type %d is %s ", c, t);
	if (v < 0)
		printf("[PARSE FAILED]\n");
	else
		printf("-> %d %s\n", v, c != v ? "FAIL" : "OK");
}

int main(int argc, char **argv)
{
	printf("Checking ctrl types...\n");

	check_type(CTRL_TYPE_UNKNOWN);
	check_type(CTRL_TYPE_GET);
	check_type(CTRL_TYPE_SET);
	check_type(CTRL_TYPE_GET_REPLY);
	check_type(CTRL_TYPE_SET_REPLY);
	check_type(CTRL_TYPE_TRAP);
	check_type(CTRL_TYPE_ERROR);
	check_type(64);

	return 0;
}
