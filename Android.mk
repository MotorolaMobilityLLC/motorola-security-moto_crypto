LOCAL_PATH := $(call my-dir)

DLKM_DIR := $(TOP)/device/qcom/common/dlkm

include $(CLEAR_VARS)
KBUILD_OPTIONS            := TARGET_BUILD_VARIANT=$(TARGET_BUILD_VARIANT)
LOCAL_MODULE              := moto_crypto.ko
LOCAL_MODULE_TAGS         := optional
LOCAL_MODULE_DEBUG_ENABLE := false
LOCAL_MODULE_PATH         := $(TARGET_OUT_VENDOR)/lib/modules
include $(DLKM_DIR)/AndroidKernelModule.mk

include $(CLEAR_VARS)

${TARGET_OUT_VENDOR}/lib/modules/moto_crypto_hmac_sha256: $(TARGET_OUT_VENDOR)/lib/modules/moto_crypto.ko
	motorola/security/moto_crypto/scripts/fips_module_hmac.py 3c091d83745f3ed32cab47458950bca648561bc54d738fe5ee34235ff1100d4a $< > ${TARGET_OUT_VENDOR}/lib/modules/moto_crypto_hmac_sha256

LOCAL_MODULE                  := generate_moto_crypto_signature
LOCAL_MODULE_TAGS             := optional
LOCAL_ADDITIONAL_DEPENDENCIES := ${TARGET_OUT_VENDOR}/lib/modules/moto_crypto_hmac_sha256
include $(BUILD_PHONY_PACKAGE)
