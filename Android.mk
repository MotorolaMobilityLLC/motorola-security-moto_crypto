#
# Build Motorola Linux Kernel Cryptographic Module as a Dynamically Loadable
# Kernel Module (DLKM)
#
DLKM_DIR          := build/dlkm
LOCAL_PATH        := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE      := moto_crypto.ko
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_PATH := $(TARGET_OUT)/lib/modules

include $(DLKM_DIR)/AndroidKernelModule.mk

