export KMODDIR?=updates
KMODDIR_ARG:="INSTALL_MOD_DIR=$(KMODDIR)"
ifneq ($(origin KLIB), undefined)
KMODPATH_ARG:="INSTALL_MOD_PATH=$(KLIB)"
else
export KLIB:=/lib/modules/$(shell uname -r)
endif
export KLIB_BUILD ?=	$(KLIB)/build

###DESTDIR?=

ifneq ($(TARGET_BUILD_VARIANT), user)
EXTRA_CFLAGS += -DCONFIG_CRYPTO_MOTOROLA_FAULT_INJECTION
endif

###NOSTDINC_FLAGS := $(CFLAGS)

override EXTRA_CFLAGS += \
    -fno-pic \
    -DKERNEL \
    -D_KERNEL \
    -I$(src)/include/

export PWD :=	$(shell pwd)

# These exported as they are used by the scripts
# to check config and compat autoconf

modules:
	$(MAKE) -C $(KLIB_BUILD) M=$(PWD) modules
	@touch $@

install-modules: modules
	$(MAKE) -C $(KLIB_BUILD) M=$(PWD) $(KMODDIR_ARG) $(KMODPATH_ARG) \
		modules_install

clean:
	@if [ -d net -a -d $(KLIB_BUILD) ]; then \
		$(MAKE) -C $(KLIB_BUILD) M=$(PWD) clean ;\
	fi
	@rm -f $(CREL_PRE)*

.PHONY: clean modules install-modules
