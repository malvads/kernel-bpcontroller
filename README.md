# kernel-bpcontroller

Linux kernel module to control bypass on network segments managed by custom bpctl bridges.

## What it does

Hooks into the kernel’s AF_PACKET notifier via a kprobe to monitor network device events.  
When a link goes down on a master or slave interface of a bpctl bridge, it triggers the bpctl ioctl to enable bypass on that segment.

No polling. No kernel network stack modifications. Just hooking and reacting.

## How it works

- Registers a kprobe on `packet_notifier` (the AF_PACKET kernel notifier function).
- On netdevice events, the kprobe pre-handler runs before `packet_notifier`.
- Checks if the device is part of a bpctl bridge interface pair.
- If a `NETDEV_CHANGE` event with link down (`__LINK_STATE_NOCARRIER`) is detected:
  - Schedules deferred work to run outside interrupt context.
  - Work calls `bpctl_kernel_ioctl` with `SET_BYPASS` on the master interface.
- On load, scans all network devices to build a list of bpctl bridge interface pairs (master/slave/bridge).

## License

GPL v2 or later

## Author

Miguel Álvarez <malvarez@redborder.com>
