#!/bin/bash
set -e

readonly BASE_URI="https://hailo-hailort.s3.eu-west-2.amazonaws.com"
readonly HRT_VERSION=4.23.0
readonly FW_AWS_DIR="Hailo10/${HRT_VERSION}/FW"
readonly list_of_files=(
    "image-fs"
    "customer_certificate.bin"
    "fitImage"
    "scu_fw.bin"
    "u-boot.dtb.signed"
    "u-boot-spl.bin"
    "u-boot-tfa.itb"
)

function download_fw(){
    for file in ${list_of_files[@]}
    do
        wget -N ${BASE_URI}/${FW_AWS_DIR}/${file}
    done
}

function create_fw_dir(){
    local dir_name=hailo10h_fw_${HRT_VERSION}
    mkdir -p ${dir_name}
    cd ${dir_name}
}

function main(){
    create_fw_dir
    download_fw
}

main
