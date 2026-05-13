# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Christophe Fontaine
# Copyright (c) 2025 Robin Jarry

FROM quay.io/centos/centos:stream10 AS builder

COPY *.rpm /tmp

RUN mkdir -p /tmp/null
RUN dnf -y install --nodocs --setopt=install_weak_deps=0 \
	--releasever 10 --installroot /tmp/null \
	coreutils-single glibc-minimal-langpack catatonit \
	/tmp/*."`rpm --eval '%_arch'`".rpm
RUN dnf -y --installroot /tmp/null clean all
RUN rm -rf /tmp/null/var/cache/* /tmp/null/var/log/dnf* /tmp/null/tmp/*
RUN sed -i 's#^zebra_options=.*#zebra_options="-A 127.0.0.1 --log stdout -M dplane_grout"#' /tmp/null/etc/frr/daemons
RUN echo '#!/bin/sh' > /tmp/null/usr/bin/frr && \
	echo '. /usr/libexec/frr/frrcommon.sh' >> /tmp/null/usr/bin/frr && \
	echo 'exec /usr/libexec/frr/watchfrr $(daemon_list)' >> /tmp/null/usr/bin/frr && \
	chmod 755 /tmp/null/usr/bin/frr

FROM scratch
COPY --from=builder /tmp/null/ /
STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/usr/libexec/catatonit/catatonit", "--"]
CMD ["/usr/bin/grout"]
