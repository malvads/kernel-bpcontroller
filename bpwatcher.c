/*
 * Copyright (C) 2025 Eneo Tecnologia S.L.
 * Author: Miguel Álvarez <malvarez@redborder.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/workqueue.h>

#define AFPACKET_KERNEL_NOTIFIER_TRACE "packet_notifier"
#define MAX_NUM_DEVICES 64
#define IGNORE_IFACE_PREFIX "lo"
#define KALLSYM "kallsyms_lookup_name"
#define BPCTL_MAGIC_NUM 'J'
#define BPCTL_IOCTL_TX_MSG(cmd) _IOWR(BPCTL_MAGIC_NUM, cmd, struct bpctl_cmd)

typedef enum {
  IF_SCAN,
  GET_DEV_NUM,
  IS_BYPASS,
  GET_BYPASS_SLAVE,
  GET_BYPASS_CAPS,
  GET_WD_SET_CAPS,
  SET_BYPASS,
  GET_BYPASS
} BPCTL_COMPACT_CMND_TYPE_SD;

typedef int (*bpctl_kernel_ioctl_t)(unsigned int ioctl_num, void *ioctl_param);

struct bpctl_cmd {
  int status;
  int data[8];
  int in_param[8];
  int out_param[8];
};

struct iface_pair {
  char master[IFNAMSIZ];
  char slave[IFNAMSIZ];
  char bridge[IFNAMSIZ];
  int master_ifindex;
};

struct bypass_work_data {
  struct work_struct work;
  int master_ifindex;
};

static struct iface_pair iface_pairs[MAX_NUM_DEVICES / 2] = {};
static int iface_pair_count = 0;
static bpctl_kernel_ioctl_t bpctl_kernel_ioctl_ptr = NULL;
static unsigned long (*kallsyms_lookup_name_ptr)(const char *name) = NULL;

static void bypass_work_handler(struct work_struct *work);
static void check_and_handle_link_down(const char *ifname);

static int resolve_kallsyms_lookup_name(void)
{
  int ret;
  struct kprobe kp = {
    .symbol_name = KALLSYM
  };

  ret = register_kprobe(&kp);
  if (ret < 0)
    return ret;

  kallsyms_lookup_name_ptr = (void *)kp.addr;
  unregister_kprobe(&kp);

  return 0;
}

static int resolve_bpctl_ioctl(void)
{
  if (!kallsyms_lookup_name_ptr)
    return -EINVAL;

  bpctl_kernel_ioctl_ptr = (bpctl_kernel_ioctl_t)kallsyms_lookup_name_ptr("bpctl_kernel_ioctl");
  if (!bpctl_kernel_ioctl_ptr)
    return -ENOENT;

  return 0;
}

static void load_bypass_interfaces(void)
{
  struct net_device *dev;

  rtnl_lock();
  for_each_netdev(&init_net, dev) {
    struct net_device *upper = netdev_master_upper_dev_get(dev);
    if (!upper)
      continue;

    if (strncmp(upper->name, "bpbr", 4) == 0) {
      bool found = false;

      for (int i = 0; i < iface_pair_count; i++) {
        if (strcmp(iface_pairs[i].bridge, upper->name) == 0) {
          if (iface_pairs[i].slave[0] == '\0') {
            strlcpy(iface_pairs[i].slave, dev->name, IFNAMSIZ);
          }
          found = true;
          break;
        }
      }

      if (!found && iface_pair_count < (MAX_NUM_DEVICES / 2)) {
        strlcpy(iface_pairs[iface_pair_count].bridge, upper->name, IFNAMSIZ);
        strlcpy(iface_pairs[iface_pair_count].master, dev->name, IFNAMSIZ);
        iface_pairs[iface_pair_count].master_ifindex = dev->ifindex;
        iface_pair_count++;
      }
    }
  }
  rtnl_unlock();

  for (int i = 0; i < iface_pair_count; i++) {
    printk(KERN_INFO "[rb-bpcontroller] %s => master:%s (idx:%d) slave:%s\n",
           iface_pairs[i].bridge,
           iface_pairs[i].master,
           iface_pairs[i].master_ifindex,
           iface_pairs[i].slave[0] ? iface_pairs[i].slave : "N/A");
  }
}

static void bypass_work_handler(struct work_struct *work)
{
  struct bypass_work_data *data = container_of(work, struct bypass_work_data, work);
  struct bpctl_cmd cmd;
  int rc;

  if (!bpctl_kernel_ioctl_ptr) {
    kfree(data);
    return;
  }

  memset(&cmd, 0, sizeof(cmd));
  cmd.in_param[1] = data->master_ifindex;
  cmd.in_param[2] = 1;

  rc = bpctl_kernel_ioctl_ptr(BPCTL_IOCTL_TX_MSG(SET_BYPASS), &cmd);
  if (rc < 0) {
    printk(KERN_ERR "[rb-bpcontroller] ioctl failed on master_ifindex=%d: rc=%d\n",
           data->master_ifindex, rc);
  } else {
    printk(KERN_INFO "[rb-bpcontroller] Bypass enabled on master_ifindex=%d\n",
           data->master_ifindex);
  }

  kfree(data);
}

static void check_and_handle_link_down(const char *ifname)
{
  for (int i = 0; i < iface_pair_count; i++) {
    if (!strcmp(ifname, iface_pairs[i].master) || !strcmp(ifname, iface_pairs[i].slave)) {
      struct bypass_work_data *data = kmalloc(sizeof(*data), GFP_ATOMIC);
      if (!data)
        return;

      INIT_WORK(&data->work, bypass_work_handler);
      data->master_ifindex = iface_pairs[i].master_ifindex;
      schedule_work(&data->work);
      break;
    }
  }
}

static int pre_packet_notifier(struct kprobe *p, struct pt_regs *regs)
{
  unsigned long msg = regs->si;
  void *ptr = (void *)regs->dx;
  struct net_device *dev = netdev_notifier_info_to_dev(ptr);

  if (!dev || strncmp(dev->name, IGNORE_IFACE_PREFIX, strlen(IGNORE_IFACE_PREFIX)) == 0)
    return 0;

  if (msg == NETDEV_CHANGE && test_bit(__LINK_STATE_NOCARRIER, &dev->state)) {
    check_and_handle_link_down(dev->name);
  }

  return 0;
}

static struct kprobe kp = {
  .symbol_name = AFPACKET_KERNEL_NOTIFIER_TRACE,
  .pre_handler = pre_packet_notifier,
};

static int __init packet_notifier_hook_init(void)
{
  int ret;

  ret = resolve_kallsyms_lookup_name();
  if (ret)
    return ret;

  ret = resolve_bpctl_ioctl();
  if (ret)
    return ret;

  load_bypass_interfaces();

  ret = register_kprobe(&kp);
  if (ret < 0)
    return ret;

  printk(KERN_INFO "[rb-bpcontroller] Kprobe registered on %s\n", AFPACKET_KERNEL_NOTIFIER_TRACE);
  return 0;
}

static void __exit packet_notifier_hook_exit(void)
{
  unregister_kprobe(&kp);
  printk(KERN_INFO "[rb-bpcontroller] Kprobe unregistered\n");
}

module_init(packet_notifier_hook_init);
module_exit(packet_notifier_hook_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Miguel Alvarez");
MODULE_DESCRIPTION("Enable bypass on link-down of master or slave of bpctl bridge");
