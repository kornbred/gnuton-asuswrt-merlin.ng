/*
 * <:copyright-BRCM:2021:DUAL/GPL:standard
 *
 *    Copyright (c) 2021 Broadcom
 *    All Rights Reserved
 *
 * Unless you and Broadcom execute a separate written software license
 * agreement governing use of this software, this software is licensed
 * to you under the terms of the GNU General Public License version 2
 * (the "GPL"), available at http://www.broadcom.com/licenses/GPLv2.php,
 * with the following added to such license:
 *
 *    As a special exception, the copyright holders of this software give
 *    you permission to link this software with independent modules, and
 *    to copy and distribute the resulting executable under terms of your
 *    choice, provided that you also meet, for each linked independent
 *    module, the terms and conditions of the license of that module.
 *    An independent module is a module which is not derived from this
 *    software.  The special exception does not apply to any modifications
 *    of the software.
 *
 * Not withstanding the above, under no circumstances may you combine
 * this software in any way with any other Broadcom software provided
 * under a license other than the GPL, without Broadcom's express prior
 * written consent.
 *
 * :>
 */

#ifndef _LINUX_SGS_H_
#define _LINUX_SGS_H_

#define SGS_CT_ACCEL_BIT		0
#define SGS_CT_BLOCK_BIT		1
#define SGS_CT_SESSION_BIT		2
#define SGS_CT_TERMINATED_BIT		3
#define SGS_CT_FROM_SGS_BIT		4
#define SGS_CT_IS_LOCAL_BIT		30
#define SGS_CT_INIT_FROM_WAN_BIT	31

enum {
	SGS_CT_FIN_SENT_BIT,
	SGS_CT_FIN_SEEN_BIT,
	SGS_CT_RST_SEEN_BIT,
};

struct sgs_ct_info_dir {
	u32		seq;
	u32		ack_seq;
	u32		next_seq;

	u32		fin_seq;
	u32		fin_ack_seq;
	u32		fin_next_seq;
	unsigned long	flags;
};

struct sgs_ct_info {
	unsigned long		flags;
	unsigned long		packet_count;
	struct sgs_ct_info_dir	dir[2];
};

static inline int sgs_ct_fin_presented(unsigned long flags)
{
	return test_bit(SGS_CT_FIN_SEEN_BIT, &flags) ||
	       test_bit(SGS_CT_FIN_SENT_BIT, &flags);
}

static inline int sgs_ct_is_closed(struct sgs_ct_info *sgs)
{
	return sgs_ct_fin_presented(sgs->dir[0].flags) &&
	       sgs_ct_fin_presented(sgs->dir[1].flags);
}

static inline int sgs_ct_is_error(struct sgs_ct_info *sgs)
{
	return test_bit(SGS_CT_RST_SEEN_BIT, &sgs->dir[0].flags) ||
	       test_bit(SGS_CT_RST_SEEN_BIT, &sgs->dir[1].flags);
}

struct nf_conn;

struct sgs_core_hooks {
	void (*delete)(struct nf_conn *ct);
};

int sgs_core_hooks_register(struct sgs_core_hooks *h);
void sgs_nf_ct_delete_from_lists(struct nf_conn *ct);
void sgs_core_hooks_unregister(void);

#endif /* _LINUX_SGS_H_ */
