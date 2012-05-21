#include <moto_aes.h>
#include <moto_tdes.h>
#include <moto_sha.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/jiffies.h>
#include <linux/scatterlist.h>
#include <linux/err.h>

#include "moto_crypto_main.h"

#define MOTO_CRYPTO_CLASS "moto_crypto"
#define MOTO_CRYPTO_FIPS_VERSION "1.0"
#define MOTO_CRYPTO_ATTR_FIPS_ENABLED     "fips_enabled"
#define MOTO_CRYPTO_ATTR_FIPS_VERSION     "fips_version"
#define MOTO_CRYPTO_ATTR_FIPS_POST_RESULT "fips_post_result"

extern int moto_prng_init(void);
extern void moto_prng_mod_fini(void);

static char *moto_integrity_hmac_sha256_expected_value;

/**
 * Holds FIPS crypto POST result:
 * 0: passed
 * other values: POST failed 
 */
static unsigned failures = 0;

unsigned char const moto_integrity_hmac_sha256_key[] = {
	0x3c, 0x09, 0x1d, 0x83, 0x74, 0x5f, 0x3e, 0xd3,
	0x2c, 0xab, 0x47, 0x45, 0x89, 0x50, 0xbc, 0xa6,
	0x48, 0x56, 0x1b, 0xc5, 0x4d, 0x73, 0x8f, 0xe5,
	0xee, 0x34, 0x23, 0x5f, 0xf1, 0x10, 0x0d, 0x4a
	};

/**
 * Store of whether Motorola FIPS crypto feature is enabled:
 * 0: disabled (default value)
 * 1: enabled
 */
static int fips_enabled = 0;

/**
 * Show handler for moto_crypto_class attributes
 */
static ssize_t moto_crypto_attr_show(struct class *class,
				     struct class_attribute *attribute,
				     char *buf)
{
	int n = 0;
	const char *attr_name = attribute->attr.name;
	if (!strcmp(MOTO_CRYPTO_ATTR_FIPS_ENABLED, attr_name)) {
		n = snprintf(buf, PAGE_SIZE, "%s\n",
			     (fips_enabled ? "1" : "0"));
	}
	else if (!strcmp(MOTO_CRYPTO_ATTR_FIPS_VERSION, attr_name)) {
		n = snprintf(buf, PAGE_SIZE, "%s\n", MOTO_CRYPTO_FIPS_VERSION);
	}
	else if (!strcmp(MOTO_CRYPTO_ATTR_FIPS_POST_RESULT, attr_name)) {
	  n = ((failures == 0) ?
	       snprintf(buf, PAGE_SIZE, "0\n") :
	       snprintf(buf, PAGE_SIZE, "0x%08x\n", failures));
    }
    printk(KERN_DEBUG "moto_crypto_attr_show: %s=%s",
	   attr_name,
	   n > 0 ? buf : "\n");
    return n;
}

/**
 * Attributes of moto_crypto_class
 */
static struct class_attribute moto_crypto_class_attrs[] = {
    {
	.attr = { .name = MOTO_CRYPTO_ATTR_FIPS_ENABLED, .mode = S_IRUGO },
	.show = moto_crypto_attr_show
    },
    {
	.attr = { .name = MOTO_CRYPTO_ATTR_FIPS_VERSION, .mode = S_IRUGO },
	.show = moto_crypto_attr_show
    },
    {
	.attr = { .name = MOTO_CRYPTO_ATTR_FIPS_POST_RESULT, .mode = S_IRUGO },
	.show = moto_crypto_attr_show
    },
    __ATTR_NULL
};

/**
 * sysfs class to expose Motorola FIPS crypto module status into user space
 * as text files in /sys/class/moto_crypto/
 */
static struct class moto_crypto_class = {
	.name        = MOTO_CRYPTO_CLASS,
	.class_attrs = moto_crypto_class_attrs,
};

#if defined(CONFIG_MODULE_EXTRA_COPY) && defined(MODULE)

static ssize_t scan_hex(unsigned char *const buf,
			size_t buf_size,
			const char *const hex)
{
	size_t bi = 0;
	size_t hi;
	unsigned prev = -1, cur;
	for (hi = 0; hex[hi] != 0; hi++) {
		if (hex[hi] >= '0' && hex[hi] <= '9')
			cur = hex[hi] - '0';
		else if (hex[hi] >= 'a' && hex[hi] <= 'f')
			cur = hex[hi] - 'a' + 10;
		else if (hex[hi] >= 'A' && hex[hi] <= 'f')
			cur = hex[hi] - 'F' + 10;
		else if (hex[hi] == '-' || hex[hi] == ' ')
			continue;
		else {
			printk(KERN_ERR
			       "invalid character at %zu (%u)", hi, hex[hi]);
			return -EINVAL;
		}
		if (prev == -1)
			prev = cur;
		else {
			if (bi >= buf_size) {
				printk(KERN_ERR "buffer too large at %zu", hi);
				return -ENOSPC;
			}
			buf[bi++] = prev << 4 | cur;
			prev = -1;
		}
	}
	return bi;
}

/* Allocate a scatterlist for a vmalloc block. The scatterlist is allocated
   with kmalloc. Buffers of arbitrary alignment are supported.
   This function is derived from other vmalloc_to_sg functions in the kernel
   tree, but note that its second argument is a size in bytes, not in pages.
 */
static struct scatterlist *vmalloc_to_sg(unsigned char *const buf,
					 size_t const bytes)
{
	struct scatterlist *sg_array = NULL;
	struct page *pg;
	/* Allow non-page-aligned pointers, so the first and last page may
	   both be partial. */
	unsigned const page_count = bytes / PAGE_SIZE + 2;
	unsigned char *ptr;
	unsigned i;

	sg_array = kcalloc(page_count, sizeof(*sg_array), GFP_KERNEL);
	if (sg_array == NULL)
		goto abort;
	sg_init_table(sg_array, page_count);
	for (i = 0, ptr = (void *)((unsigned long)buf & PAGE_MASK);
	     ptr < buf + bytes;
	     i++, ptr += PAGE_SIZE) {
		pg = vmalloc_to_page(ptr);
		if (pg == NULL)
			goto abort;
		sg_set_page(&sg_array[i], pg, PAGE_SIZE, 0);
	}
	/* Rectify the first page which may be partial. The last page may
	   also be partial but its offset is correct so it doesn't matter. */
	sg_array[0].offset = offset_in_page(buf);
	sg_array[0].length = PAGE_SIZE - offset_in_page(buf);
	return sg_array;
abort:
	if (sg_array != NULL)
		kfree(sg_array);
	return NULL;
}

static int self_test_integrity(const char *alg_name, struct module *mod)
{
	unsigned char expected[32];
	unsigned char actual[32];
	struct scatterlist *sg = NULL;
	struct hash_desc desc = {NULL, 0};
	size_t digest_length;
	size_t const key_length = sizeof(moto_integrity_hmac_sha256_key);
	int error;

	if (mod->raw_binary_ptr == NULL)
		return -ENXIO;
	if (moto_integrity_hmac_sha256_expected_value == NULL)
		return -ENOENT;
	error = scan_hex(expected, sizeof(expected),
			 moto_integrity_hmac_sha256_expected_value);
	if (error < 0) {
		printk(KERN_ERR
		       "FIPS module: Badly formatted hmac_sha256 parameter "
		       "(should be a hex string)\n");
		return -EIO;
	};

	desc.tfm = crypto_alloc_hash(alg_name, 0, 0);
	if (IS_ERR_OR_NULL(desc.tfm)) {
		printk(KERN_ERR "crypto_alloc_hash(%s) failed\n", alg_name);
		error = (desc.tfm == NULL ? -ENOMEM : (int)desc.tfm);
		goto abort;
	}
	digest_length = crypto_hash_digestsize(desc.tfm);
	printk(KERN_INFO "alg_name=%s driver_name=%s digest_length=%u\n",
	     alg_name,
	     crypto_tfm_alg_driver_name(crypto_hash_tfm(desc.tfm)),
	     digest_length);

	error = crypto_hash_setkey(desc.tfm, moto_integrity_hmac_sha256_key, 
				   key_length);
	if (error) {
		printk(KERN_ERR "crypto_hash_setkey(%s) failed: %d\n",
		      alg_name, error);
		goto abort;
	}

	sg = vmalloc_to_sg(mod->raw_binary_ptr, mod->raw_binary_size);
	if (IS_ERR_OR_NULL(sg)) {
		printk(KERN_ERR "vmalloc_to_sg(%lu) failed: %d\n",
		      mod->raw_binary_size, (int)sg);
		error = (sg == NULL ? -ENOMEM : (int)sg);
		goto abort;
	}

	error = crypto_hash_digest(&desc, sg, mod->raw_binary_size, actual);
	if (error) {
		printk(KERN_ERR "crypto_hash_digest(%s) failed: %d\n",
		      alg_name, error);
		goto abort;
	}

	kfree(sg);
	crypto_free_hash(desc.tfm);

#ifdef CONFIG_CRYPTO_MOTOROLA_FAULT_INJECTION
	if (fault_injection_mask & MOTO_CRYPTO_MODULE_INTEGRITY) {
		printk(KERN_WARNING
		       "Moto crypto: injecting fault in integrity check!\n");
		actual[0] ^= 0xff;
	}
#endif

	if (memcmp(expected, actual, digest_length)) {
		printk(KERN_ERR "wrong %s digest value\n", alg_name);
		error = -EINVAL;
	} else {
	  printk(KERN_INFO "%s: digest successful\n", alg_name);
		error = 0;
	}

	return error;

abort:
	if (!IS_ERR_OR_NULL(sg))
		kfree(sg);
	if (!IS_ERR_OR_NULL(desc.tfm))
		crypto_free_hash(desc.tfm);
	return error == -ENOMEM ? error : -EIO;
}
#endif

/* Finalizes all algorithms in the module */
static void finalize_algorithms(void) {
	moto_aes_fini();
	moto_tdes_fini();
	moto_sha1_fini();
	moto_sha256_fini();
	moto_sha512_fini();
	moto_hmac_fini();
	moto_prng_mod_fini();
}

/* Module entry point */
static int __init moto_crypto_init(void)
{
	int err;
	unsigned long start_jiffies;
	long diff;

	printk(KERN_INFO "moto_crypto_main: moto_crypto_init\n");
	printk(KERN_INFO "moto_crypto_main: fips_enabled=%d\n", fips_enabled);
#ifdef CONFIG_CRYPTO_MOTOROLA_FAULT_INJECTION
	printk(KERN_INFO
	       "moto_crypto_main: fault_injection_mask_string=%s\n",
	       fault_injection_mask_string);
	if (fault_injection_mask_string != NULL) {
		sscanf(fault_injection_mask_string, "%x",
		       &fault_injection_mask);
		printk(KERN_INFO
		       "moto_crypto_main: fault_injection_mask=%0x\n",
		       fault_injection_mask);
	}
#endif

	start_jiffies = jiffies;

	/* Register sysfs entries for Motorola FIPS crypto module status */
	err = class_register(&moto_crypto_class);
	if (err) {
		printk(KERN_ERR "moto_crypto_init(): "
		       "failed to register sysfs class, error %d\n", err);
		return err;
	}
	failures = 0;

	err = moto_aes_start();
	if (err) {
		failures |= MOTO_CRYPTO_FAILED_ALG_AES;
		goto out;
	}
	err = moto_tdes_start();
	if (err) {
		failures |= MOTO_CRYPTO_FAILED_ALG_TDES;
		goto out;
	}
	err = moto_sha1_start();
	if (err) {
		failures |= MOTO_CRYPTO_FAILED_ALG_SHA1;
		goto out;
	}
	err = moto_sha256_start();
	if (err) {
		failures |= MOTO_CRYPTO_FAILED_ALG_SHA256;
		goto out;
	}
	err = moto_sha512_start();
	if (err) {
		failures |= MOTO_CRYPTO_FAILED_ALG_SHA512;
		goto out;
	}
	err = moto_hmac_start();
	if (err) {
		failures |= MOTO_CRYPTO_FAILED_ALG_HMAC;
		goto out;
	}
	err = moto_prng_init();
	if (err) {
		failures |= MOTO_CRYPTO_FAILED_ALG_RNG;
		goto out;
	}

#if defined(CONFIG_MODULE_EXTRA_COPY) && defined(MODULE)
	switch (self_test_integrity("moto_hmac(moto-sha256)", &__this_module)) {
	case 0:
		printk(KERN_INFO
		       "FIPS crypto module integrity check passed\n");
		break;
	case -ENXIO:
		printk(KERN_ERR
		       "FIPS crypto module integrity check can only be run "
		       "when the module is loaded");
		failures |= MOTO_CRYPTO_FAILED_INTEGRITY;
		goto out;
	case -ENOENT:
		printk(KERN_ERR
		       "FIPS crypto module integrity check cannot be made: "
		       "Missing HMAC_SHA256 parameter\n");
		/* FALLTHROUGH */
	default:
		printk(KERN_ERR
		       "FIPS crypto module self test integrity error\n");
		failures |= MOTO_CRYPTO_FAILED_INTEGRITY;
		goto out;
	}
#endif

	printk(KERN_INFO
	       "moto_crypto_main: moto_crypto_init successful initialization\n");

out:
	if (failures) {
		finalize_algorithms();
	}
	diff = (long)jiffies - (long)start_jiffies;
	printk(KERN_INFO "moto_crypto_main: Time to init: %ld msec\n", 
	       diff * 1000 / HZ);
	return 0;
}

/* Module finalization function */
static void __exit moto_crypto_fini(void)
{
	printk(KERN_INFO "moto_crypto_fini\n");
	class_unregister(&moto_crypto_class);
	finalize_algorithms();
}


module_init(moto_crypto_init);
module_exit(moto_crypto_fini);

module_param_named(hmac_sha256, moto_integrity_hmac_sha256_expected_value, 
		   charp, 0444);
MODULE_PARM_DESC(hmac_sha256, "Module HMAC SHA-256 to be checked");

#ifdef CONFIG_CRYPTO_MOTOROLA_FAULT_INJECTION
unsigned fault_injection_mask;
char *fault_injection_mask_string;
module_param_named(fault, fault_injection_mask_string, charp, 0644);
#endif

/**
 * FIPS mode parameter, may be defined in the module loading command line: 
 * disabled: fips=0 (default value)
 * enabled:  fips=1
 *
 * Example: insmod moto_crypto.ko fips=1
 */
module_param_named(fips, fips_enabled, int, 0);
MODULE_PARM_DESC(fips, "FIPS mode: fips=0 -> disabled; fips=1 -> enabled");


MODULE_DESCRIPTION("Motorola cryptographic module");
MODULE_LICENSE("GPL");
MODULE_ALIAS("moto_crypto");
