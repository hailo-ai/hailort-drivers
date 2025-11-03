#!/bin/bash
set -e

readonly BASE_URI="https://hailo-hailort.s3.eu-west-2.amazonaws.com"
readonly HRT_VERSION=5.1.1
readonly FW_AWS_DIR="Hailo10H/${HRT_VERSION}/FW"
readonly fw_file="hailo10h_fw.tar.gz"

function download_fw(){
    wget -N ${BASE_URI}/${FW_AWS_DIR}/${fw_file}
}

function create_fw_dir(){
    local dir_name=hailo10h_fw_${HRT_VERSION}
    mkdir -p ${dir_name}
    cd ${dir_name}
}

function unpack_fw(){
    tar -xzf ${fw_file}
}

function main(){
    create_fw_dir
    download_fw
    unpack_fw
}

main
