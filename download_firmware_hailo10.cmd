:: cmd
@ECHO OFF

set BASE_URI=https://hailo-hailort.s3.eu-west-2.amazonaws.com
set HRT_VERSION=5.2.0
set FW_AWS_DIR=Hailo10H/%HRT_VERSION%/FW
set FW_FILE=hailo10h_fw.tar.gz
set FW_DIR=hailo10h_fw_%HRT_VERSION%

:: Create firmware directory
ECHO Creating firmware directory: %FW_DIR%
mkdir %FW_DIR%
cd %FW_DIR%

:: Download firmware from AWS
ECHO Downloading Hailo10H Firmware from S3
powershell -c "wget %BASE_URI%/%FW_AWS_DIR%/%FW_FILE% -outfile %FW_FILE%"

:: Unpack firmware
powershell -c "tar -xzf %FW_FILE%"
del %FW_FILE%