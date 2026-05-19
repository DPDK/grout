# Quadlet Examples

Example systemd/podman quadlet files for running grout with FRR in containers.

- `grout.container` starts the grout daemon in privileged mode with hugepages,
  VFIO and PCI access. An init script is executed after startup to configure
  interfaces.
- `frr.container` starts the FRR routing suite in grout's network namespace so
  that it can manage grout interfaces via the dplane plugin.
- `grout-metrics.container` exposes grout's openmetrics unix socket over TCP
  port 9111 using socat, in a separate network namespace.
- `grout-netns.service` creates a named network namespace for grout.
- `grout-bind@.service` is a templated unit that binds a network device for
  grout usage. Enable one instance per netdev (e.g. `grout-bind@ens1f0`). For
  VFIO-capable devices, the netdev is unbound from its kernel driver and bound
  to vfio-pci. For mellanox NICs, the netdev is moved into the grout network
  namespace.
- `grout-bind` and `grout-unbind` are the helper scripts used by the templated
  service.

The grout container declares an anonymous volume on `/run`. Both FRR and the
metrics proxy inherit it via `VolumesFrom=grout` to access grout's API and
metrics sockets.

## Host Configuration

The following files must exist on the host before starting the containers:

- `/etc/grout.init` -- grcli script executed after grout starts (e.g. interface
  and route configuration).
- `/etc/frr/frr.conf` -- FRR integrated configuration file. Mounted read-write
  so that changes made via vtysh are persisted on the host.

## Installation

Copy the `.container` and `.service` files to `/etc/containers/systemd/` and the
scripts to `/usr/local/bin/`:

    cp *.container /etc/containers/systemd/
    cp *.service /etc/systemd/system/
    cp grout-bind grout-unbind /usr/local/bin/
    systemctl daemon-reload

Enable the bind service for each network device that grout should use:

    systemctl enable --now grout-bind@ens1f0
    systemctl enable --now grout-bind@ens1f1

Then start grout:

    systemctl start grout
