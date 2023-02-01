/* SPDX-License-Identifier: GPL-2.0 */

#include "test_utils.h"
#include "../libxdp_internal.h"

int main(__unused int argc, __unused char** argv)
{
	silence_libbpf_logging();
	return libxdp_check_kern_compat();
}
