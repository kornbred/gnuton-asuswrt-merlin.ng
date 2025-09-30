#
# Linux AFC Makefile to build afc library and afc daemon
#
# Copyright (C) 2024, Broadcom. All Rights Reserved.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
# OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
#
# <<Broadcom-WL-IPTag/Dual:>>
#
# $Id: Makefile 832722 2023-11-12 00:09:11Z $

AFCDINSTALLDIR = $(INSTALLDIR)/afcd

# set this to 'y' to use static lib instead of shared lib; helps replace just afcd while debugging
# AFC_LIB_STATIC=y

ifneq ($(AFC_LIB_STATIC),y)
AFC_LIB  = libafc.so
else
AFC_LIB  = libafc.a
endif

AFC_D    = afcd
AFC_CLI  = afc_cli
TARGET   = $(AFC_LIB) $(AFC_D) $(AFC_CLI)

CFLAGS	+= -I. -I$(TOP)/shared -I$(SRCBASE)/../components/opensource/jsonc \
		-I$(BCM_FSBUILD_DIR)/public/include \
		-I$(SRCBASE)/include -I$(SRCBASE)/../components/shared \
		-I$(SRCBASE)/../components/bcmhal/include \
		-I$(SRCBASE)/common/include -I$(SRCBASE)/../components/wlioctl/include	\
		-I$(SRCBASE)/common/include/proto -I$(SRCBASE)/../components/shared/proto \
		-I$(SRCBASE)/../components/proto/include \
		-I$(SRCBASE)/../components/math/include \
		-I$(SRCBASE)/../components/apps/locpold/include

CFLAGS  += $(if $(WLAN_ComponentIncPath),$(WLAN_ComponentIncPath),$(addprefix -I,$(wildcard $(SRCBASE)/shared/bcmwifi/include)))

ifneq ($(NO_BCMINTERNAL), 1)
CFLAGS	+= -DBCMINTERNAL
endif
CFLAGS	+= -DBCMDBG -g -s -O2 -Wall -Werror -fPIC

LDFLAGS += $(EXTRA_LDFLAGS)
LDFLAGS += -L$(BCM_FSBUILD_DIR)/lib -L$(BCM_FSBUILD_DIR)/public/lib
LDFLAGS += -L$(TOP)/shared -L$(INSTALLDIR)/shared/usr/lib -lshared
LDFLAGS += -L$(TOP)/nvram -lnvram -ljson-c -lcurl
LDFLAGS += -L. -lafc -lm

vpath %.c $(SRCBASE)/shared/bcmwifi/src

AFC_LIB_OBJS = afc_json.o bcmwifi_rclass.o bcmwifi_channels.o afc.o
AFC_LIB_INC  = afc.h afc_shared.h

AFC_D_OBJS = afcd.o afc_sock_util.o
AFC_D_INC  = afc_sock_util.h afcd.h afc_shared.h

AFC_CLI_OBJS = afc_cli.o afc_sock_util.o
AFC_CLI_INC  = afc.h afc_shared.h afc_sock_util.h

all: $(TARGET)

$(AFC_LIB): $(AFC_LIB_OBJS)
ifneq ($(AFC_LIB_STATIC),y)
	$(CC) -shared $^ -o $@
else
	$(AR) rc $@ $^
endif

$(AFC_D): $(AFC_LIB) $(AFC_D_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(AFC_CLI): $(AFC_LIB) $(AFC_CLI_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(AFC_LIB_OBJS): $(AFC_LIB_INC)

$(AFC_D_OBJS): $(AFC_D_INC)

$(AFC_CLI_OBJS): $(AFC_CLI_INC)

install: all
# Now install to router install directory from prebuilt
	install -d $(AFCDINSTALLDIR)/usr/lib
	install -d $(AFCDINSTALLDIR)/usr/sbin/
ifneq ($(AFC_LIB_STATIC),y)
# Install AFC Lib
	install -m 755 $(AFC_LIB) $(AFCDINSTALLDIR)/usr/lib
	$(STRIP) $(AFCDINSTALLDIR)/usr/lib/$(AFC_LIB)
endif
# Install AFC Daemon and CLI
	install $(AFC_D) $(AFC_CLI) $(AFCDINSTALLDIR)/usr/sbin/
	$(STRIP) $(AFCDINSTALLDIR)/usr/sbin/$(AFC_D)
	$(STRIP) $(AFCDINSTALLDIR)/usr/sbin/$(AFC_CLI)

clean:
	rm -f *.o *.a *.so *.bak $(TARGET) *~
