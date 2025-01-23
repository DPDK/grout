# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Robin Jarry

FROM registry.access.redhat.com/ubi9/ubi:latest
COPY grout*.rpm /tmp
RUN rm -f /tmp/grout-debug*.rpm
RUN dnf -y install --nodocs --setopt=install_weak_deps=0 /tmp/grout*.rpm
RUN dnf -y --enablerepo='*' clean all
RUN rm -f /tmp/grout*.rpm
CMD ["/usr/bin/grout"]
