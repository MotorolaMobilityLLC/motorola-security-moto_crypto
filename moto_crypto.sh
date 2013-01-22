#!/bin/bash

#
# File descriptor 3 will output the the original stderr of the
# invoked shell. We do this so that a function can directly exit on failure...
# but still output its failure message.
exec 3>&2
exec 2>&1

function exit_on_error {
    if [ "$1" -ne 0 ]; then
        echo >&3 "moto_crypto.sh: $2 exited with error $1"
        exit 1
    fi
}

# defaults
TOP=`pwd`
_target_arch=""
_kernel_out=""
_target_out=""

init_variables() {
    local custom_board=$1

    echo >&3 "moto_crypto.sh: custom board = ${custom_board}"
    echo >&3 "moto_crypto.sh: TARGET_TOOLS_PREFIX = ${TARGET_TOOLS_PREFIX}"

    #export PATH="`dirname ${TARGET_TOOLS_PREFIX}`:$PATH"
    if [ -z "$CROSS_COMPILE" ];then
        export CROSS_COMPILE="`basename ${TARGET_TOOLS_PREFIX}`"
    fi

    export ARCH=$2
    echo >&3 "moto_crypto.sh: ARCH = $ARCH"
    echo >&3 "moto_crypto.sh: CROSS_COMPILE = $CROSS_COMPILE"

    if [ -z "${custom_board}" ]; then
        echo >&3 "moto_crypto.sh: no custom board specified"
        exit_on_error 2 custom_board
    fi

    case "${custom_board}" in
    generic_x86 | vbox )
        BOARD=generic_x86
        ;;
    *)
	BOARD=${custom_board}
	;;
    esac
    #  Modify PRODUCT_OUT defenition to match IKJBOMAP2278's change,
    #  otherwise this module will be missing when HW_CONFIG is set
    if [ "${HW_CONFIG}" == "" ]; then
       PRODUCT_OUT=${TOP}/out/target/product/${BOARD}
    else
       PRODUCT_OUT=${TOP}/out/target/product/${BOARD}-${HW_CONFIG}
    fi
    KERNEL_BUILD_DIR=$3
}

make_compat() {
    echo >&3 "moto_crypto.sh: making moto_crypto module"
    local COMPAT_SRC_DIR=$TOP/motorola/security/moto_crypto
    local MODULE_DEST_TMP=${PRODUCT_OUT}/moto_crypto
    local MODULE_DEST=${PRODUCT_OUT}/system/lib/modules

    rm -rf ${MODULE_DEST_TMP}
    mkdir -p ${MODULE_DEST_TMP}/src
    mkdir -p ${MODULE_DEST_TMP}/test
    mkdir -p ${MODULE_DEST_TMP}/include
    mkdir -p ${MODULE_DEST};
    cp -r ${COMPAT_SRC_DIR}/src/* ${MODULE_DEST_TMP}/src
    cp -r ${COMPAT_SRC_DIR}/test/* ${MODULE_DEST_TMP}/test
    cp -r ${COMPAT_SRC_DIR}/include/* ${MODULE_DEST_TMP}/include
    cp ${COMPAT_SRC_DIR}/Makefile ${MODULE_DEST_TMP}

    cd ${MODULE_DEST_TMP}

    make ARCH=${ARCH} INSTALL_MOD_STRIP=--strip-unneeded KLIB=${MODULE_DEST_TMP} KLIB_BUILD=${KERNEL_BUILD_DIR} install-modules
    exit_on_error $? make

    find ${MODULE_DEST_TMP} -name "*.ko" -exec cp -vf {} ${MODULE_DEST} \;
    exit_on_error $? find

    echo >&3 "moto_crypto.sh: generating moto_crypto HMAC"
    ${COMPAT_SRC_DIR}/scripts/fips_module_hmac.py 3c091d83745f3ed32cab47458950bca648561bc54d738fe5ee34235ff1100d4a ${MODULE_DEST}/moto_crypto.ko > ${MODULE_DEST}/moto_crypto_hmac_sha256
    cd ${TOP}
}

usage() {
    echo "Usage: $0 [-c custom_board]"

    echo ""
    echo " -c [generic_x86|vbox|mfld_cdk|mfld_pr2|mfld_gi|mfld_dv10|ctp_pr0|ctp_pr1|sc1|smi|henry|mrfl_vp|mrfl_hvp|mrfl_sle]"
    echo "                          custom board (target platform)"
}

check_full_path() {
    local  __resultvar=$1
    local path_to_return=$2

    if [ ${path_to_return:0:1} != '/' ]
    then
        path_to_return=${TOP}/${path_to_return}
    fi

    eval $__resultvar="'$path_to_return'"
}

main() {
    echo "$0 $*"

    local custom_board_list=""

    while getopts c:a:o:u: opt
    do
        case "${opt}" in
        h)
            usage
            exit 0
            ;;
        c)
            custom_board_list="${OPTARG}"
            ;;
        C)
            _clean=1
            ;;
	a) 
	   _target_arch=${OPTARG}
           echo "Target arch: ${_target_arch}"
	   ;;
	o) 
           check_full_path _kernel_out ${OPTARG}
	   echo "kernel: ${_kernel_out}"
	   ;;
	u) 
           check_full_path _target_out ${OPTARG}
	   echo "target out: ${_target_out}"
	   ;;
        ?)
            echo "Unknown option"
            usage
            exit 0
            ;;
        esac
    done

    for custom_board in $custom_board_list
    do
        echo >&3 "---------------------------------"
        echo >&3 "Building moto_crypto for $custom_board"
        echo >&3 "---------------------------------"
        init_variables "$custom_board" $_target_arch $_kernel_out 
        make_compat ${custom_board} $_target_out
        exit_on_error $? make_compat
    done
    exit 0
}

main $*
