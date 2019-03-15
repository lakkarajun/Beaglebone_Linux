/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef __MICROCHIP_NETLINK_H
#define __MICROCHIP_NETLINK_H 

#include <linux/rtnetlink.h>
#include <linux/phy.h>
#include <linux/netdevice.h>
#include <net/genetlink.h>

/* genetlink setup */
enum {
	PHYNL_CMD_NOOP,
	PHYNL_CMD_EVENT,		/* only for notifications */

	PHYNL_CMD_WAKE,
	PHYNL_CMD_SLEEP,

	PHYNL_CMD_CABDIAG,

	__PHYNL_CMD_CNT,
	PHYNL_CMD_MAX = (__PHYNL_CMD_CNT - 1)
};

enum {
	PHYNL_ATTR_NOOP,
	WAKE_ATTR_PHYACCESS,		/* phyaccess nested types */
	WAKE_ATTR_NOTIFICATION,

	__PHYNL_ATTR_CNT,
	PHYNL_ATTR_MAX = (__PHYNL_ATTR_CNT - 1)
};

/* phyaccess nested types */
#define	PHYACC_ATTR_MODE_READ		0
#define	PHYACC_ATTR_MODE_WRITE		1

#define	PHYACC_ATTR_BANK_SMI		0
#define	PHYACC_ATTR_BANK_MISC		1
#define	PHYACC_ATTR_BANK_PCS		2
#define	PHYACC_ATTR_BANK_AFE		3
#define	PHYACC_ATTR_BANK_DSP		4
#define	PHYACC_ATTR_BANK_INSTRUMENT	5

enum {
	PHYACC_ATTR_NOOP,
	PHYACC_ATTR_IFNAME,
	PHYACC_ATTR_MODE,
	PHYACC_ATTR_BANK_ADDR,
	PHYACC_ATTR_OFFSET_ADDR,
	PHYACC_ATTR_VAL,

	__PHYACC_ATTR_CNT,
	PHYACC_ATTR_MAX = (__PHYACC_ATTR_CNT - 1)
};

#define	WAKENOTI_ATTR_STATUS_OK		0
#define	WAKENOTI_ATTR_STATUS_ABORT	1
#define	WAKENOTI_ATTR_STATUS_FAILURE	2

enum {
	WAKENOTI_ATTR_NOOP,
	WAKENOTI_ATTR_STATUS,

	__WAKENOTI_ATTR_CNT,
	WAKENOTI_ATTR_MAX = (__WAKENOTI_ATTR_CNT - 1)
};

#define CABDIAG_PAIR_A_MASK 0x0001
#define CABDIAG_PAIR_B_MASK 0x0002
#define CABDIAG_PAIR_C_MASK 0x0004
#define CABDIAG_PAIR_D_MASK 0x0008

enum {
	CABDIAG_PAIR_NONE,
	CABDIAG_PAIR_A,
	CABDIAG_PAIR_B,
	CABDIAG_PAIR_C,
	CABDIAG_PAIR_D,

	__CABDIAG_PAIR_CNT,
	CABDIAG_PAIR_MAX = ( __CABDIAG_PAIR_CNT - 1)
};

enum {
	CABDIAG_OP_ATTR_NOOP,
	CABDIAG_ATTR_REQUEST,        /* Cable diagnostics reqest nested types */
	CABDIAG_ATTR_STATUS,         /* Cable diagnostics status nested types */
	CABDIAG_ATTR_NOTIFICATION,

	__CABDIAG_OP_ATTR_CNT,
	CABDIAG_OP_ATTR_MAX = (__CABDIAG_OP_ATTR_CNT - 1)
};

enum {
	CABDIAG_REQ_ATTR_NOOP,
	CABDIAG_REQ_ATTR_IFNAME,
	CABDIAG_REQ_ATTR_CMD,
	CABDIAG_REQ_ATTR_PAIRS_MASK,
	CABDIAG_REQ_ATTR_TIMEOUT,

	__CABDIAG_REQ_ATTR_CNT,
	CABDIAG_REQ_ATTR_MAX = (__CABDIAG_REQ_ATTR_CNT - 1)
};

enum {
	CABDIAG_PAIR_STA_ATTR_NOOP,
	CABDIAG_PAIR_STA_ATTR_RESULT,
	CABDIAG_PAIR_STA_ATTR_LENGTH,

	__CABDIAG_PAIR_STA_ATTR_CNT,
	CABDIAG_PAIR_STA_ATTR_MAX = (__CABDIAG_PAIR_STA_ATTR_CNT - 1)
};

enum {
	CABDIAG_STA_ATTR_NOOP,
	CABDIAG_STA_ATTR_IFNAME,
	CABDIAG_STA_ATTR_PAIRS_MASK,
	CABDIAG_STA_ATTR_STATUS,

	__CABDIAG_STA_ATTR_CNT,
	CABDIAG_STA_ATTR_MAX = (__CABDIAG_STA_ATTR_CNT - 1)
};

enum {
	CABDIAG_NOTIF_ATTR_NOOP,
	CABDIAG_NOTIF_ATTR_IFNAME,
	CABDIAG_NOTIF_ATTR_TYPE,

	__CABDIAG_NOTIF_ATTR_CNT,
	CABDIAG_NOTIF_ATTR_MAX = (__CABDIAG_NOTIF_ATTR_CNT - 1)
};

struct phynl_cabdiag_req {
	u8 cmd;           /* Start or stop diagnostics */
	u8 pairs_bitmask; /* Allows settings diagnostics request just for a pair */
	u8 timeout;       /* Timeout in seconds */
};

struct phynl_cabdiag_pair_status {
	u8 result; /* 0 = Good, 1 = Short, 2 = Open, 3 = broken */
	u8 length; /* Length in meters */
};

struct phynl_cabdiag_status {
	u8 pairs_bitmask; /* Allows settings diagnostics request just for a pair */
	struct phynl_cabdiag_pair_status pairs[CABDIAG_PAIR_MAX + 1];
};

extern int phynl_cabdiag_notification(int notification_type);

#endif /* __MICROCHIP_NETLINK_H */
