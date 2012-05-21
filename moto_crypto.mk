# This must be defined with = so that the variables are evaluated at build time
# instead of include time, as they are defined later

.PHONY: build_moto-crypto

TGT_PRODUCT = $(TARGET_PRODUCT)

TGT_ARCH = $(TARGET_ARCH)

TGT_KERNEL_INT = $(KERNEL_OUT)

TGT_OUT = $(TARGET_OUT)

build_moto-crypto: $(INSTALLED_KERNEL_TARGET)
	TARGET_TOOLS_PREFIX="$(ANDROID_BUILD_TOP)/$(TARGET_TOOLS_PREFIX)" motorola/security/moto_crypto/moto_crypto.sh -c $(TGT_PRODUCT) -a $(TGT_ARCH) -o $(TGT_KERNEL_INT) -u $(TGT_OUT)



