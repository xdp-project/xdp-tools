#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "xdp_redirect.h"

int main(int argc, char *argv[])
{
	const char *command;

	if (argc <= 2)
		goto end;
	command = argv[1];
	if (!strcmp("basic", command))
		return xdp_redirect_basic_main(argc - 1, argv + 1);
	else if (!strcmp("cpumap", command))
		return xdp_redirect_cpumap_main(argc - 1, argv + 1);
	else if (!strcmp("devmap", command))
		return xdp_redirect_devmap_main(argc - 1, argv + 1);
	else if (!strcmp("devmap_multi", command))
		return xdp_redirect_devmap_multi_main(argc - 1, argv + 1);
end:
	fprintf(stderr, "Usage: xdp-redirect [command] <options>\n"
		"\t[command] must be one of basic, cpumap, devmap, devmap_multi\n"
		"Please see %s(8) for more details.\n", program_invocation_short_name);
	return 1;
}
