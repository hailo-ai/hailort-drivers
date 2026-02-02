#!/bin/bash
set -e

readonly UPLOAD_BIN="/opt/hailo/bin/hailo_rfs_upload"
readonly IMAGE_FILE="/opt/hailo/image_files/current_image.ext4"

if [[ ! -x "${UPLOAD_BIN}" ]]; then
    logger -t hailo-usb -p user.err "hailo_rfs_upload not found or not executable: ${UPLOAD_BIN}"
    exit 1
fi

if [[ ! -f "${IMAGE_FILE}" ]]; then
    logger -t hailo-usb -p user.err "Image file not found: ${IMAGE_FILE}"
    exit 1
fi

logger -t hailo-usb -p user.info "Uploading image file: ${IMAGE_FILE}"
if ! "${UPLOAD_BIN}" "${IMAGE_FILE}"; then
    logger -t hailo-usb -p user.err "Failed to upload image file: ${IMAGE_FILE}"
    exit 1
fi