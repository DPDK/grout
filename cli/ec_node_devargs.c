// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include <gr_macro.h>

#include <ecoli.h>

#include <dirent.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>

EC_LOG_TYPE_REGISTER(node_devargs);

static int
ec_node_devargs_parse(const struct ec_node *, struct ec_pnode *, const struct ec_strvec *strvec) {
	if (ec_strvec_len(strvec) == 0)
		return EC_PARSE_NOMATCH;

	return 1;
}

#define SYS_PCI_DEVICES "/sys/bus/pci/devices"
#define PCI_CLASS_ETH "0x020000"
static const char *const dpdk_vdevs[] = {
	"net_null",
	"net_tap",
	"net_tun",
	"net_vhost",
	"net_virtio_user",
};

static int ec_node_devargs_complete(
	const struct ec_node *node,
	struct ec_comp *comp,
	const struct ec_strvec *strvec
) {
	const char *word, *driver;
	struct dirent *de = NULL;
	char buf[512], buf2[512];
	DIR *dir = NULL;
	int ret = -1;
	int fd = -1;
	ssize_t n;

	if (ec_strvec_len(strvec) != 1)
		goto out;

	word = ec_strvec_val(strvec, 0);

	dir = opendir(SYS_PCI_DEVICES);
	if (dir == NULL)
		goto out; // sysfs not mounted.

	while ((de = readdir(dir)) != NULL) {
		if (fd != -1)
			close(fd);

		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		if (!ec_str_startswith(de->d_name, word))
			continue;

		// check for device class "Ethernet Controller" (0x020000)
		snprintf(buf, sizeof(buf), "%s/%s", de->d_name, "class");
		if ((fd = openat(dirfd(dir), buf, O_RDONLY)) < 0)
			continue;
		if ((n = read(fd, buf, sizeof(buf))) < 0)
			continue;
		buf[n - 1] = '\0'; // last character is a new line
		if (strcmp(buf, PCI_CLASS_ETH) != 0)
			continue;

		// check if the bound driver is known to dpdk
		snprintf(buf, sizeof(buf), "%s/%s", de->d_name, "driver");
		if ((n = readlinkat(dirfd(dir), buf, buf2, sizeof(buf2))) < 0)
			continue;
		buf2[n] = '\0';
		driver = basename(buf2);
		if (strcmp(driver, "vfio-pci") != 0 && strcmp(driver, "mlx5_core") != 0)
			continue;

		if (!ec_comp_add_item(comp, node, EC_COMP_FULL, word, de->d_name))
			goto fail;
	}

	for (unsigned i = 0; i < ARRAY_DIM(dpdk_vdevs); i++) {
		if (!ec_str_startswith(dpdk_vdevs[i], word))
			continue;
		if (!ec_comp_add_item(comp, node, EC_COMP_PARTIAL, word, dpdk_vdevs[i]))
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
