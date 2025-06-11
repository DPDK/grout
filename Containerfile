# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Christophe Fontaine
# dummy change

FROM registry.access.redhat.com/ubi9 as ubi-builder
COPY grout.*.rpm /tmp
RUN mkdir -p /tmp/null
RUN dnf -y install --nodocs --setopt=install_weak_deps=0 --releasever 9 --installroot /tmp/null /tmp/grout.$(arch).rpm
RUN dnf -y --installroot /tmp/null clean all
RUN rm -rf /tmp/null/var/cache/* /tmp/null/var/log/dnf* /tmp/null/var/log/yum.*

FROM registry.access.redhat.com/ubi9-micro
COPY --from=ubi-builder /tmp/null/ /
CMD ["/usr/bin/grout"]
