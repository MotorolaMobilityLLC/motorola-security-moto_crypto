# This must be defined with = so that the variables are evaluated at build time
# instead of include time, as they are defined later

.PHONY: build_moto-crypto

TGT_DEVICE = $(TARGET_DEVICE)

TGT_ARCH = $(TARGET_ARCH)

# Qualcomm and intel builds use KERNEL_OUT variablem, and OMAP uses KERNEL_BUILD_DIR
ifneq ($(KERNEL_OUT),)
  TGT_KERNEL_INT = $(KERNEL_OUT)
else
  TGT_KERNEL_INT = $(KERNEL_BUILD_DIR)
endif

TGT_OUT = $(TARGET_OUT)

build_moto-crypto: $(INSTALLED_KERNEL_TARGET)
	TARGET_TOOLS_PREFIX="$(ANDROID_BUILD_TOP)/$(TARGET_TOOLS_PREFIX)" bash -x motorola/security/moto_crypto/moto_crypto.sh -c $(TGT_DEVICE) -a $(TGT_ARCH) -o $(TGT_KERNEL_INT) -u $(TGT_OUT)



