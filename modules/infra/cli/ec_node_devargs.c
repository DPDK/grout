// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "ecoli_string.h"

#include <ecoli.h>

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

EC_LOG_TYPE_REGISTER(node_devargs);

static int ec_node_devargs_parse(
	const struct ec_node *node,
	struct ec_pnode *pstate,
	const struct ec_strvec *strvec
) {
	(void)node;
	(void)pstate;

	if (ec_strvec_len(strvec) == 0)
		return EC_PARSE_NOMATCH;

	return 1;
}

#define SYS_PCI_DEVICES "/sys/bus/pci/devices"
#define PCI_CLASS_ETH "0x020000"

static int ec_node_devargs_complete(
	const struct ec_node *node,
	struct ec_comp *comp,
	const struct ec_strvec *strvec
) {
	struct dirent *de = NULL;
	const char *word;
	DIR *dir = NULL;
	char buf[512];
	int ret = -1;
	int fd = -1;
	ssize_t n;

	if (ec_strvec_len(strvec) != 1)
		goto out;

	word = ec_strvec_val(strvec, 0);

	dir = opendir(SYS_PCI_DEVICES);
	if (dir == NULL)
		goto fail; // sysfs not mounted.

	// find pci devices with device class "Ethernet Controller" (0x020000)
	while ((de = readdir(dir)) != NULL) {
		if (fd != -1)
			close(fd);

		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;

		if (!ec_str_startswith(de->d_name, word))
			continue;

		snprintf(buf, sizeof(buf), "%s/%s", de->d_name, "class");
		if ((fd = openat(dirfd(dir), buf, O_RDONLY)) < 0)
			continue;

		if ((n = read(fd, buf, sizeof(buf))) < 0)
			continue;
		buf[n - 1] = '\0';

		if (strcmp(buf, PCI_CLASS_ETH) != 0)
			continue;

		if (!ec_comp_add_item(comp, node, EC_COMP_FULL, word, de->d_name))
			goto fail;
	}

out:
	ret = 0;
fail:
	if (fd != -1)
		close(fd);
	if (dir != NULL)
		closedir(dir);
	return ret;
}

static struct ec_node_type ec_node_devargs_type = {
	.name = "devargs",
	.parse = ec_node_devargs_parse,
	.complete = ec_node_devargs_complete,
};

EC_NODE_TYPE_REGISTER(ec_node_devargs_type);
