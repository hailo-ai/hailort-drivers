%global module hailo_pci

%global kernel 5.14.0-587.el9
%global baserelease 1

%global debug_package %{nil}

%global __spec_install_post \
  %{?__debug_package:%{__debug_install_post}} \
  %{__arch_install_post} \
  %{__os_install_post} \
  %{__mod_compress_install_post}

%global __mod_compress_install_post find %{buildroot}/lib/modules -type f -name \*.ko -exec xz  --compress --check=crc32 --lzma2=dict=1MiB \{\} \\;


Name:             hailort-drivers
Version:          4.21.0
Release:          %{baserelease}%{?dist}
Summary:          Hailo8 PCIe driver

License:          GPLv2
URL:              https://github.com/hailo-ai/hailort-drivers
Source0:          https://github.com/hailo-ai/hailort/releases/%{name}-%{version}.tar.gz
Source1:          hailo8_fw.%{version}.bin

Patch1:           hailo-rhel9.patch

ExclusiveArch:    x86_64 aarch64

BuildRequires:    gcc
BuildRequires:    kernel-rpm-macros
BuildRequires:    kmod
BuildRequires:    make
BuildRequires:    redhat-rpm-config
BuildRequires:    xz

BuildRequires:    kernel-abi-stablelists = %{kernel}
BuildRequires:    kernel-devel-uname-r = %{kernel}.%{_arch}

Requires:         kernel-uname-r >= %{kernel}.%{_arch}

Provides:         installonlypkg(kernel-module)
Provides:         kernel-modules >= %{kernel}.%{_arch}

Requires(post):   %{_sbindir}/depmod


%description
The Hailo8 PCIe driver is necessary for interacting with a Hailo8 device over the PCIe interface. It connects the HailoRT library to the device and loads the device's firmware when using this interface. The driver is responsible for managing the Hailo device, communicating with it, and transferring data to and from the device.

%prep
%setup -q -n %{name}
%patch1 -p1

%build
pushd linux/pcie
%{__make} all
popd

%install
%{__install} -D -t %{buildroot}/lib/modules/%{kernel}.%{_arch}/extra/misc linux/pcie/%{module}.ko
mkdir -p %{buildroot}/lib/firmware/hailo
%{__install} %{SOURCE1} %{buildroot}/lib/firmware/hailo/hailo8_fw.bin
%{__install} -D -t %{buildroot}/etc/udev/rules.d/ linux/pcie/51-hailo-udev.rules

# Make .ko objects temporarily executable for automatic stripping
find %{buildroot}/lib/modules -type f -name \*.ko -exec chmod u+x \{\} \+

%clean
%{__rm} -rf %{buildroot}

%post
depmod -a

%files
%defattr(644,root,root,755)
/lib/modules/%{kernel}.%{_arch}
/etc/udev/rules.d/51-hailo-udev.rules
/lib/firmware/hailo/hailo8_fw.bin
%license LICENSE

%changelog
* Tue Jun 03 2025 Sebastian Hetze <shetze@redhat.com>
- initial build
