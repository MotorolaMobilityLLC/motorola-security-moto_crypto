ifneq ($(TARGET_BUILD_VARIANT), user)
EXTRA_CFLAGS += -DCONFIG_CRYPTO_MOTOROLA_FAULT_INJECTION
endif

EXTRA_CFLAGS += \
    -fno-pic \
    -DKERNEL \
    -D_KERNEL \
    -I$(M)/include/

obj-m += moto_crypto.o
moto_crypto-y := \
    src/moto_crypto_main.o \
    src/moto_crypto_util.o \
    src/moto_testmgr.o \
    src/moto_aes.o \
    src/moto_tdes.o \
    src/moto_sha1.o \
    src/moto_sha256.o \
    src/moto_sha512.o \
    src/moto_hmac.o \
    src/moto_ansi_cprng.o

ifeq ($(CONFIG_CRYPTO_MOTOROLA_FIPS_TEST_MODULES),y)

obj-m += moto_crypto_test.o
moto_crypto_test-y := \
    test/moto_crypto_test.o

obj-m += moto_crypto_user.o
moto_crypto_user-y := \
    test/moto_crypto_user.o

endif
