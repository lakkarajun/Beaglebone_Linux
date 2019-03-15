/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#include <linux/bitmap.h>
#include <linux/rtnetlink.h>
#include <net/sock.h>
#include <linux/phy.h>
#include <linux/netdevice.h>
#include <net/genetlink.h>
#include <net/sock.h>
#include "microchip_netlink.h"

static const struct nla_policy phy_wake_policy[PHYNL_ATTR_MAX+1] = {
	[WAKE_ATTR_PHYACCESS]		= { .type = NLA_NESTED },
};

static const struct nla_policy phy_acc_policy[PHYACC_ATTR_MAX + 1] = {
	[PHYACC_ATTR_IFNAME] 		= { .type = NLA_STRING },
	[PHYACC_ATTR_MODE]		= { .type = NLA_U8 },
	[PHYACC_ATTR_BANK_ADDR]		= { .type = NLA_U8 },
	[PHYACC_ATTR_OFFSET_ADDR]	= { .type = NLA_U16 },
	[PHYACC_ATTR_VAL] 		= { .type = NLA_U16 },
};

static const struct nla_policy cabdiag_req_policy[CABDIAG_REQ_ATTR_MAX + 1] = {
	[CABDIAG_REQ_ATTR_IFNAME]     = { .type = NLA_STRING },
	[CABDIAG_REQ_ATTR_CMD]        = { .type = NLA_U8 },
	[CABDIAG_REQ_ATTR_PAIRS_MASK] = { .type = NLA_U8 },
	[CABDIAG_REQ_ATTR_TIMEOUT]    = { .type = NLA_U8 },
};

static const struct nla_policy cabdiag_pair_sta_policy[CABDIAG_PAIR_STA_ATTR_MAX + 1] = {
	[CABDIAG_PAIR_STA_ATTR_RESULT] = { .type = NLA_U8 },
	[CABDIAG_PAIR_STA_ATTR_LENGTH] = { .type = NLA_U8 },
};

static const struct nla_policy cabdiag_sta_policy[CABDIAG_STA_ATTR_MAX + 1] = {
	[CABDIAG_STA_ATTR_IFNAME]     = { .type = NLA_STRING },
	[CABDIAG_STA_ATTR_PAIRS_MASK] = { .type = NLA_U8 },
	[CABDIAG_STA_ATTR_STATUS]     = NLA_POLICY_NESTED_ARRAY(cabdiag_pair_sta_policy),
};

static const struct nla_policy cabdiag_op_policy[CABDIAG_OP_ATTR_MAX + 1] = {
	[CABDIAG_ATTR_REQUEST]  = { .type = NLA_NESTED },
	[CABDIAG_ATTR_STATUS]   = { .type = NLA_NESTED },
};

extern struct genl_family microchipphy_genl_family;

static struct phy_device *phydev;
static struct phy_driver *phydriver;

static int do_phy_read(struct phy_device *phydev, unsigned short phybank, unsigned short phyaddr)
{
	int val=0;

	/* do phy read
	 * For now, SMI access only.
	 */
	if (!phydev)
		return -EINVAL;

	if (phybank == PHYACC_ATTR_BANK_SMI) {
		val = phy_read(phydev, phyaddr);	
	}

	return val;
}

static void do_phy_write(struct phy_device *phydev, unsigned short phybank, unsigned short phyaddr, int phyval)
{
	/* do phy write
	 * For now, SMI access only.
	 */
	if (!phydev)
		return;

	if (phybank == PHYACC_ATTR_BANK_SMI) {
		phy_write(phydev, phyaddr, (u16)phyval);
	}
}

int phy_register_access(struct genl_info *info, struct nlattr *nest)
{
	struct net *net = genl_info_net(info);
	struct nlattr *tb[PHYACC_ATTR_MAX + 1];
	struct net_device *netdev=NULL;
	unsigned short mode=0, phybank=0;
	unsigned short phyaddr = 0;
	int phyval = 0;
	struct sk_buff *msg;
	int ret;
	void *hdr;

	if (!nest) {
		printk("message error\n");
		return -EINVAL;
	}

	ret = nla_parse_nested(tb, PHYACC_ATTR_MAX, nest, phy_acc_policy, info->extack);
	if (ret < 0)
		return ret;

	if (tb[PHYACC_ATTR_IFNAME]) {
		netdev = dev_get_by_name(net, (char *)nla_data(tb[PHYACC_ATTR_IFNAME]));
		if (netdev) {
			printk("netdev->name = %s\n", netdev->name);
			phydev = netdev->phydev;
			if (phydev) {
				printk("phydev->phy_id = 0x%x\n", phydev->phy_id);
				if (phydev->drv) {
					phydriver = netdev->phydev->drv;
				} else {
					printk("netdev->phydev->drv == NULL\n");
					return -EINVAL;
				}
			} else {
				dev_put(netdev);
				printk("netdev->phydev == NULL\n");
				return -EINVAL;
			}
		} else {
			printk("can't find net device\n");
			return -ENODEV;
		}
	}

	if (tb[PHYACC_ATTR_MODE])
		mode = nla_get_u16(tb[PHYACC_ATTR_MODE]);

	if (tb[PHYACC_ATTR_BANK_ADDR])
		phybank = nla_get_u16(tb[PHYACC_ATTR_BANK_ADDR]);

	if (tb[PHYACC_ATTR_OFFSET_ADDR])
		phyaddr = nla_get_u16(tb[PHYACC_ATTR_OFFSET_ADDR]);

	if (tb[PHYACC_ATTR_VAL])
		phyval = (int)nla_get_u32(tb[PHYACC_ATTR_VAL]);

	if (phydev) {
		if (mode == PHYACC_ATTR_MODE_READ) {
			/* do PHY read */
			phyval = do_phy_read(phydev, phybank, phyaddr);
		} else if (mode == PHYACC_ATTR_MODE_WRITE) {
			/* do PHY write */
			do_phy_write(phydev, phybank, phyaddr, phyval);
		}
	} else {
		printk("phydev == NULL\n");
		return -ENODEV;
	}

	/* reply back */
	msg = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put_reply(msg, info, &microchipphy_genl_family, 0, PHYNL_CMD_WAKE);

	nest = nla_nest_start(msg, WAKE_ATTR_PHYACCESS | NLA_F_NESTED);
	nla_put_u16(msg, PHYACC_ATTR_MODE, mode);
	nla_put_u16(msg, PHYACC_ATTR_BANK_ADDR, mode);
	nla_put_u16(msg, PHYACC_ATTR_OFFSET_ADDR, phyaddr);
	nla_put_u32(msg, PHYACC_ATTR_VAL, phyval);
	nla_nest_end(msg, nest);

	genlmsg_end(msg, hdr);
	genlmsg_reply(msg, info);

	//genlmsg_multicast(&microchipphy_genl_family, msg, 0, 0, GFP_ATOMIC);

	if (netdev)
		dev_put(netdev);

	return 0;
}

int phynl_wake_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *tb[PHYNL_ATTR_MAX+1];
	int ret;

	/* handle received params */
	ret = genlmsg_parse(info->nlhdr, &microchipphy_genl_family, tb, PHYNL_ATTR_MAX, phy_wake_policy, info ? info->extack : NULL);
	if (ret < 0) {
		printk("%s(): genlmsg_parse returns %d\n", __func__, ret);
		return ret;
	}

	if (tb[WAKE_ATTR_PHYACCESS]) {
		/* do phy register access */
		ret = phy_register_access(info, tb[WAKE_ATTR_PHYACCESS]);
		if (ret < 0) {
			printk("phy_register_access returns %d\n", ret);
			return ret;
		}
	}

	return 0;
}

int phynl_wake_notification(int notification_type)
{
	struct nlattr *nest;
	struct sk_buff *msg;
	void *hdr;

	/* notify event to user space */
	msg = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, 0, 0, &microchipphy_genl_family, 0, PHYNL_CMD_WAKE);

	nest = nla_nest_start(msg, WAKE_ATTR_NOTIFICATION | NLA_F_NESTED);
	nla_put_u32(msg, WAKENOTI_ATTR_STATUS, notification_type);
	nla_nest_end(msg, nest);

	genlmsg_end(msg, hdr);
	genlmsg_multicast(&microchipphy_genl_family, msg, 0, 0, GFP_ATOMIC);

	return 0;
}
EXPORT_SYMBOL(phynl_wake_notification);

static int phy_cabdiag_request(struct genl_info *info, struct nlattr *nest)
{
	struct net *net = genl_info_net(info);
	struct nlattr *tb[PHYACC_ATTR_MAX + 1];
	struct phynl_cabdiag_req cabdiag;
	struct net_device *netdev=NULL;
	struct sk_buff *msg;
	int ret;
	void *hdr;

	if (!nest) {
		printk("message error\n");
		return -EINVAL;
	}

	memset(&cabdiag, 0, sizeof(struct phynl_cabdiag_req));
	ret = nla_parse_nested(tb, CABDIAG_REQ_ATTR_MAX, nest, cabdiag_req_policy, info->extack);
	if (ret < 0)
		return ret;

	if (tb[CABDIAG_REQ_ATTR_IFNAME]) {
		netdev = dev_get_by_name(net, (char *)nla_data(tb[CABDIAG_REQ_ATTR_IFNAME]));
		if (netdev) {
			phydev = netdev->phydev;
			if (phydev) {
				if (phydev->drv) {
					phydriver = netdev->phydev->drv;
				} else {
					printk("netdev->phydev->drv == NULL\n");
					return -EINVAL;
				}
			} else {
				dev_put(netdev);
				printk("netdev->phydev == NULL\n");
				return -EINVAL;
			}
		} else {
			printk("can't find net device\n");
			return -ENODEV;
		}
	}

	if (tb[CABDIAG_REQ_ATTR_CMD])
		cabdiag.cmd = nla_get_u8(tb[CABDIAG_REQ_ATTR_CMD]);

	if (tb[CABDIAG_REQ_ATTR_PAIRS_MASK])
		cabdiag.pairs_bitmask = nla_get_u8(tb[CABDIAG_REQ_ATTR_PAIRS_MASK]);

	if (tb[CABDIAG_REQ_ATTR_TIMEOUT])
		cabdiag.timeout = nla_get_u8(tb[CABDIAG_REQ_ATTR_TIMEOUT]);

	if (phydev) {
		/* Enable PHY cable diagnostics */
		if (phydriver->set_cable_diag) {
			phydriver->set_cable_diag(phydev, (void *)&cabdiag);
		} else {
			printk("phydev->set_cable_diag == NULL\n");
			return -ENODEV;
		}
	} else {
		printk("phydev == NULL\n");
		return -ENODEV;
	}

	/* reply back */
	msg = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put_reply(msg, info, &microchipphy_genl_family, 0, PHYNL_CMD_CABDIAG);

	nest = nla_nest_start(msg, CABDIAG_ATTR_REQUEST | NLA_F_NESTED);
	nla_put_u8(msg, CABDIAG_REQ_ATTR_CMD, cabdiag.cmd);
	nla_put_u8(msg, CABDIAG_REQ_ATTR_PAIRS_MASK, cabdiag.pairs_bitmask);
	nla_put_u8(msg, CABDIAG_REQ_ATTR_TIMEOUT, cabdiag.timeout);
	nla_nest_end(msg, nest);

	genlmsg_end(msg, hdr);
	genlmsg_reply(msg, info);

	if (netdev)
		dev_put(netdev);

	return 0;
}

static int phy_cabdiag_status(struct genl_info *info, struct nlattr *nest)
{
	struct net *net = genl_info_net(info);
	struct nlattr *tb[PHYACC_ATTR_MAX + 1];
	struct phynl_cabdiag_status status;
	struct net_device *netdev=NULL;
	struct sk_buff *msg;
	int ret;
	__be64 val_64;
	void *hdr;

	if (!nest) {
		printk("message error\n");
		return -EINVAL;
	}

	memset(&status, 0, sizeof(struct phynl_cabdiag_status));
	ret = nla_parse_nested(tb, CABDIAG_STA_ATTR_MAX, nest, cabdiag_sta_policy, info->extack);
	if (ret < 0)
		return ret;

	if (tb[CABDIAG_STA_ATTR_IFNAME]) {
		netdev = dev_get_by_name(net, (char *)nla_data(tb[CABDIAG_STA_ATTR_IFNAME]));
		if (netdev) {
			phydev = netdev->phydev;
			if (phydev) {
				if (phydev->drv) {
					phydriver = netdev->phydev->drv;
				} else {
					printk("netdev->phydev->drv == NULL\n");
					return -EINVAL;
				}
			} else {
				dev_put(netdev);
				printk("netdev->phydev == NULL\n");
				return -EINVAL;
			}
		} else {
			printk("can't find net device\n");
			return -ENODEV;
		}
	}

	if (tb[CABDIAG_STA_ATTR_PAIRS_MASK])
		status.pairs_bitmask = nla_get_u8(tb[CABDIAG_STA_ATTR_PAIRS_MASK]);

	if (phydev) {
		/* Get PHY cable diagnostics status */
		if (phydriver->get_cable_diag) {
			phydriver->get_cable_diag(phydev, (void *)&status);
		} else {
			printk("phydev->set_cable_diag == NULL\n");
			return -ENODEV;
		}
	} else {
		printk("phydev == NULL\n");
		return -ENODEV;
	}

	/* reply back */
	msg = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put_reply(msg, info, &microchipphy_genl_family, 0, PHYNL_CMD_CABDIAG);

	nest = nla_nest_start(msg, CABDIAG_ATTR_STATUS | NLA_F_NESTED);
	nla_put_string(msg, CABDIAG_STA_ATTR_IFNAME, netdev->name);
	nla_put_u8(msg, CABDIAG_STA_ATTR_PAIRS_MASK, status.pairs_bitmask);
	val_64 = ((__be64)status.pairs[CABDIAG_PAIR_D].length << 56 |
			  (__be64)status.pairs[CABDIAG_PAIR_D].result << 48 |
			  (__be64)status.pairs[CABDIAG_PAIR_C].length << 40 |
			  (__be64)status.pairs[CABDIAG_PAIR_C].result << 32 |
			  (__be64)status.pairs[CABDIAG_PAIR_B].length << 24 |
			  (__be64)status.pairs[CABDIAG_PAIR_B].result << 16 |
			  (__be64)status.pairs[CABDIAG_PAIR_A].length << 8  |
			  status.pairs[CABDIAG_PAIR_A].result);
	nla_put_be64(msg, CABDIAG_STA_ATTR_STATUS, val_64, 4);
	nla_nest_end(msg, nest);

	genlmsg_end(msg, hdr);
	genlmsg_reply(msg, info);

	if (netdev)
		dev_put(netdev);

	return 0;
}

int phynl_cabdiag_notification(int notification_type)
{
	struct nlattr *nest;
	struct sk_buff *msg;
	void *hdr;

	/* notify event to user space */
	msg = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, 0, 0, &microchipphy_genl_family, 0, PHYNL_CMD_CABDIAG);

	nest = nla_nest_start(msg, CABDIAG_ATTR_NOTIFICATION | NLA_F_NESTED);
	// Raju: Need to fix
	nla_put_string(msg, CABDIAG_NOTIF_ATTR_IFNAME, "cabdiag_eth0");
	nla_put_s32(msg, CABDIAG_NOTIF_ATTR_TYPE, notification_type);
	nla_nest_end(msg, nest);

	genlmsg_end(msg, hdr);
	genlmsg_multicast(&microchipphy_genl_family, msg, 0, 0, GFP_ATOMIC);

	return 0;
}
EXPORT_SYMBOL(phynl_cabdiag_notification);

static int phynl_cabdiag_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *tb[CABDIAG_OP_ATTR_MAX+1];
	int ret;

	/* handle received params */
	ret = genlmsg_parse(info->nlhdr, &microchipphy_genl_family, tb, CABDIAG_OP_ATTR_MAX,
						cabdiag_op_policy, info ? info->extack : NULL);
	if (ret < 0) {
		printk("%s(): genlmsg_parse returns %d\n", __func__, ret);
		return ret;
	}

	if (tb[CABDIAG_ATTR_REQUEST]) {
		/* phy cable diagnostics request */
		ret = phy_cabdiag_request(info, tb[CABDIAG_ATTR_REQUEST]);
		if (ret < 0) {
			printk("phy_cabdiag_request returns %d\n", ret);
			return ret;
		}
	}

	if (tb[CABDIAG_ATTR_STATUS]) {
		/* phy cable diagnostics status */
		ret = phy_cabdiag_status(info, tb[CABDIAG_ATTR_STATUS]);
		if (ret < 0) {
			printk("phy_cabdiag_status returns %d\n", ret);
			return ret;
		}
	}

	return 0;
}

#define	MICROCHIPPHY_GENL_NAME		"microchipphy"
#define	MICROCHIPPHY_GENL_VERSION	1
#define	MICROCHIPPHY_MCGRP_MONITOR	"phy_monitor"

static struct genl_multicast_group microchipphy_genl_mcgroups[] = {
	{
		.name = MICROCHIPPHY_MCGRP_MONITOR
	},
};

static const struct genl_ops microchipphy_genl_ops[] = {
	{
		.cmd	= PHYNL_CMD_WAKE,
		.doit	= phynl_wake_doit,
	},
	{
		.cmd	= PHYNL_CMD_CABDIAG,
		.doit	= phynl_cabdiag_doit,
	},
};

struct genl_family microchipphy_genl_family = {
	.hdrsize	= 0,
	.name		= MICROCHIPPHY_GENL_NAME,
	.version	= MICROCHIPPHY_GENL_VERSION,
	.netnsok	= true,
	.parallel_ops	= false,
	.ops		= microchipphy_genl_ops,
	.n_ops		= ARRAY_SIZE(microchipphy_genl_ops),
	.mcgrps		= microchipphy_genl_mcgroups,
	.n_mcgrps	= ARRAY_SIZE(microchipphy_genl_mcgroups),
};

/* module setup */

static int __init microchipphy_genl_init(void)
{
	int ret;

	printk("%s()\n", __func__);
	ret = genl_register_family(&microchipphy_genl_family);
	if (ret < 0)
		panic("microchipphy: could not register genetlink family\n");

	return 0;
}

static void __exit microchipphy_genl_exit(void)
{
	genl_unregister_family(&microchipphy_genl_family);
	printk("%s()\n", __func__);
}

module_init(microchipphy_genl_init);
module_exit(microchipphy_genl_exit);

