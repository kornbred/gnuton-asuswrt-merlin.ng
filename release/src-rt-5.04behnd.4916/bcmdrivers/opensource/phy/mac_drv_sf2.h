/*
   Copyright (c) 2017 Broadcom Corporation
   All Rights Reserved

    <:label-BRCM:2017:DUAL/GPL:standard

    Unless you and Broadcom execute a separate written software license
    agreement governing use of this software, this software is licensed
    to you under the terms of the GNU General Public License version 2
    (the "GPL"), available at http://www.broadcom.com/licenses/GPLv2.php,
    with the following added to such license:

       As a special exception, the copyright holders of this software give
       you permission to link this software with independent modules, and
       to copy and distribute the resulting executable under terms of your
       choice, provided that you also meet, for each linked independent
       module, the terms and conditions of the license of that module.
       An independent module is a module which is not derived from this
       software.  The special exception does not apply to any modifications
       of the software.

    Not withstanding the above, under no circumstances may you combine
    this software in any way with any other Broadcom software provided
    under a license other than the GPL, without Broadcom's express prior
    written consent.

:>
*/

/*
 *  Created on: Jun 2017
 *      Author: steven.hsieh@broadcom.com
 */

#ifndef __MAC_DRV_SF2_H__
#define __MAC_DRV_SF2_H__

/* definition for mac_drv priv flags */
#define SF2MAC_DRV_PRIV_FLAG_MGMT               (1<<1)
#define SF2MAC_DRV_PRIV_FLAG_SHRINK_IPG         (1<<2)  // for IMP port with clock speed can't support full line rate due to brcm tag
#define SF2MAC_DRV_PRIV_FLAG_SW_EXT             (1<<3)  // for SF2_DUAL indicating MAC/port is on external switch1
#define SF2MAC_DRV_PRIV_FLAG_EXTSW_CONNECTED    (1<<4)  // for SF2_DUAL indicating MAC/port is connected to external switch
#define SF2MAC_DRV_PRIV_FLAG_RMT_LPBK_EN        (1<<5)  // remote loopback is enabled for this MAC
#define SF2MAC_DRV_PRIV_FLAG_64_40BIT_MIB       (1<<6)  // 64/40bit mib counters instead of 64/32bit 

typedef struct
{
    unsigned long priv_flags;
    void (*rreg)(int page, int reg, void *data_out, int len);
    void (*wreg)(int page, int reg, void *data_in,  int len);
    uint16_t saved_pmap;    // save port based vlan map to be restored when remote loopback is disabled
    mac_stats_t mac_stats;  // accumulated software counters
    mac_stats_t last_mac_stats; // last hw counters
    mac_stats_t scratch_stats; // current hw counters
} sf2_mac_dev_priv_data_t;

#endif

