/*
* <:copyright-BRCM:2022:DUAL/GPL:standard
* 
*    Copyright (c) 2022 Broadcom 
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
:>
*/

#include "sw_gso_hook.h"
#include <linux/spinlock_types.h>

extern int sw_gso_log_init(void*);

int sw_gso_hook_init(void)
{
    sw_gso_log_init((void *)bcmLog_logIsEnabled(BCM_LOG_ID_LOG, BCM_LOG_LEVEL_ERROR));

    return 0;
}

void* pkt_get_queue(void* buf)
{
    return nbuff_get_queue(buf);
}

void pkt_set_queue(void* buf,void *queue)
{
    nbuff_set_queue(buf,queue);
}

int sw_gso_get_wait_queue_head_t_sz(void)
{
    return (int)sizeof(wait_queue_head_t);
}

void* sw_gso_alloc_spinlock(void)
{
    spinlock_t *lock=NULL;

    lock = kmalloc(sizeof(spinlock_t), GFP_ATOMIC);

    if(lock != NULL)
    {
       spin_lock_init(lock);
    }

    return (void*)lock;
}

void sw_gso_free_spinlock(void* lock)
{
    if(lock != NULL)
    {
       kfree((void*)lock);
    }

    return;
}

void sw_gso_spin_lock_bh(void* lock)
{
    spin_lock_bh((spinlock_t*)lock);
}

void sw_gso_spin_unlock_bh(void* lock)
{
    spin_unlock_bh((spinlock_t*)lock);
}