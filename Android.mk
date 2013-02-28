LOCAL_PATH := $(call my-dir)

ifeq ($(call is-android-codename,JELLY_BEAN),true)
       DLKM_DIR := $(TOP)/device/qcom/common/dlkm
else
       DLKM_DIR := build/dlkm
endif

include $(CLEAR_VARS)
KBUILD_OPTIONS            := TARGET_BUILD_VARIANT=$(TARGET_BUILD_VARIANT)
LOCAL_MODULE              := moto_crypto.ko
LOCAL_MODULE_TAGS         := optional
LOCAL_MODULE_DEBUG_ENABLE := false
LOCAL_MODULE_PATH         := $(TARGET_OUT)/lib/modules
include $(DLKM_DIR)/AndroidKernelModule.mk

.PHONY: build_moto-crypto
build_moto-crypto: $(TARGET_OUT)/lib/modules/moto_crypto.ko
	motorola/security/moto_crypto/scripts/fips_module_hmac.py 3c091d83745f3ed32cab47458950bca648561bc54d738fe5ee34235ff1100d4a $< > ${TARGET_OUT}/lib/modules/moto_crypto_hmac_sha256
