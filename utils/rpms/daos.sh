#!/bin/bash
# (C) Copyright 2025 Google LLC
# WORK IN PROGRESS
set -eEuo pipefail
root="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"
. "${root}/fpm_common.sh"

if [ -z "${SL_PREFIX}" ]; then
  echo "daos is not built"
  exit 1
fi

bins=()
dbg_bin=()
dbg_lib=()
files=()
libs=()
internal_libs=()
data=()

VERSION=${daos_version}
RELEASE=${daos_release}
LICENSE="BSD-2-Clause-Patent"
ARCH="${isa}"
DESCRIPTION="The Distributed Asynchronous Object Storage (DAOS) is an open-source
software-defined object store designed from the ground up for
massively distributed Non Volatile Memory (NVM). DAOS takes advantage
of next generation NVM technology like Storage Class Memory (SCM) and
NVM express (NVMe) while presenting a key-value storage interface and
providing features such as transactional non-blocking I/O, advanced
data protection with self healing on top of commodity hardware, end-
to-end data integrity, fine grained data control and elastic storage
to optimize performance and cost."
URL="https://daos.io"

TARGET_PATH="${bindir}"
list_files files "${SL_SPDK_PREFIX}/bin/daos_spdk*"
clean_bin dbg_bin "${files[@]}"
create_install_list bins "${files[@]}"

BASE_PATH="${tmp}/${datadir}/daos/spdk"
TARGET_PATH="${datadir}/daos/spdk"
list_files files "${SL_SPDK_PREFIX}/share/daos/spdk/*"
create_install_list data "${files[@]}"

TARGET_PATH="${libdir}/daos_srv"
list_files files "${SL_SPDK_PREFIX}/lib64/daos_srv/libspdk.so.*" \
  "${SL_SPDK_PREFIX}/lib64/daos_srv/librte*.so.*"
clean_bin dbg_lib "${files[@]}"
create_install_list libs "${files[@]}"

TARGET_PATH="${libdir}/daos_srv/dpdk/pmds-22.0"
list_files files "${SL_SPDK_PREFIX}/lib64/daos_srv/dpdk/pmds-22.0/lib*.so.*"
clean_bin dbg_lib "${files[@]}"
create_install_list internal_libs "${files[@]}"

ARCH="${isa}"
build_package "daos-spdk" "${bins[@]}" "${data[@]}" "${libs[@]}" "${internal_libs[@]}"
build_debug_package "daos-spdk" "${dbg_bin[@]}" "${dbg_lib[@]}"

echo "%define daoshome %{_exec_prefix}/lib/%{name}
%define server_svc_name daos_server.service
%define agent_svc_name daos_agent.service
%define sysctl_script_name 10-daos_server.conf

%bcond_without server
%bcond_without olddaos

%if %{with server}
%global daos_build_args FIRMWARE_MGMT=yes
%else
%global daos_build_args client test
%endif
%global mercury_version   2.4
%global libfabric_version 1.15.1-1
%global argobots_version 1.2
%global __python %{__python3}

%if (0%{?rhel} >= 8)
# https://bugzilla.redhat.com/show_bug.cgi?id=1955184
%define _use_internal_dependency_generator 0
%define __find_requires %{SOURCE1}
%endif

Name:          daos
Version:       2.7.101
Release:       8%{?relval}%{?dist}
Summary:       DAOS Storage Engine

License:       BSD-2-Clause-Patent
URL:           https://github.com/daos-stack/daos
Source0:       %{name}-%{version}.tar.gz
Source1:       bz-1955184_find-requires
%endif
%description
The Distributed Asynchronous Object Storage (DAOS) is an open-source
software-defined object store designed from the ground up for
massively distributed Non Volatile Memory (NVM). DAOS takes advantage
of next generation NVM technology like Storage Class Memory (SCM) and
NVM express (NVMe) while presenting a key-value storage interface and
providing features such as transactional non-blocking I/O, advanced
data protection with self healing on top of commodity hardware, end-
to-end data integrity, fine grained data control and elastic storage
to optimize performance and cost.

%if %{with olddaos}
%if %{with server}
%package server
Summary: The DAOS server
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: spdk-tools >= 22.01.2
Requires: ndctl
# needed to set PMem configuration goals in BIOS through control-plane
%if (0%{?suse_version} >= 1500)
Requires: ipmctl >= 03.00.00.0423
Requires: libpmemobj1 >= 2.1.0-1.suse1500
Requires: libfabric1 >= %{libfabric_version}
%else
Requires: ipmctl >= 03.00.00.0468
Requires: libpmemobj >= 2.1.0-1%{?dist}
%endif
Requires: libfabric >= %{libfabric_version}
Requires: mercury >= %{mercury_version}
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
Requires: numactl
Requires: pciutils
%{?systemd_requires}

%description server
This is the package needed to run a DAOS server
%endif

%package admin
Summary: DAOS admin tools
Requires: %{name}%{?_isa} = %{version}-%{release}

%description admin
This package contains DAOS administrative tools (e.g. dmg).

%package client
Summary: The DAOS client
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: mercury >= %{mercury_version}
Requires: libfabric >= %{libfabric_version}
%if (0%{?suse_version} >= 1500)
Requires: libfabric1 >= %{libfabric_version}
%endif
Requires: /usr/bin/fusermount3
%{?systemd_requires}

%description client
This is the package needed to run a DAOS client

%package tests
Summary: The entire DAOS test suite
Requires: %{name}-client-tests%{?_isa} = %{version}-%{release}
BuildArch: noarch

%description tests
This is the package is a metapackage to install all of the test packages

%package tests-internal
Summary: The entire internal DAOS test suite
Requires: %{name}-tests = %{version}-%{release}
Requires: %{name}-client-tests-openmpi%{?_isa} = %{version}-%{release}
Requires: %{name}-client-tests-mpich = %{version}-%{release}
Requires: %{name}-serialize%{?_isa} = %{version}-%{release}
BuildArch: noarch

%description tests-internal
This is the package is a metapackage to install all of the internal test
packages

%package client-tests
Summary: The DAOS test suite
Requires: %{name}-client%{?_isa} = %{version}-%{release}
Requires: %{name}-admin%{?_isa} = %{version}-%{release}
Requires: %{name}-devel%{?_isa} = %{version}-%{release}
%if (0%{?suse_version} >= 1500)
Requires: libprotobuf-c-devel
%else
Requires: protobuf-c-devel
%endif
Requires: fio
Requires: git
Requires: dbench
Requires: lbzip2
Requires: attr
Requires: ior
Requires: go >= 1.21
%if (0%{?suse_version} >= 1315)
Requires: lua-lmod
Requires: libcapstone-devel
%else
Requires: Lmod
Requires: capstone-devel
%endif
Requires: pciutils-devel
%if (0%{?suse_version} > 0)
Requires: libndctl-devel
%endif
%if (0%{?rhel} >= 8)
Requires: ndctl-devel
Requires: daxctl-devel
%endif

%description client-tests
This is the package needed to run the DAOS test suite (client tests)

%package client-tests-openmpi
Summary: The DAOS client test suite - tools which need openmpi
Requires: %{name}-client-tests%{?_isa} = %{version}-%{release}
Requires: hdf5-%{openmpi}-tests
Requires: hdf5-vol-daos-%{openmpi}-tests
Requires: MACSio-%{openmpi}
Requires: simul-%{openmpi}

%description client-tests-openmpi
This is the package needed to run the DAOS client test suite openmpi tools

%package client-tests-mpich
Summary: The DAOS client test suite - tools which need mpich
BuildArch: noarch
Requires: %{name}-client-tests%{?_isa} = %{version}-%{release}
Requires: mpifileutils-mpich
Requires: testmpio
Requires: mpich
Requires: ior
Requires: hdf5-mpich-tests
Requires: hdf5-vol-daos-mpich-tests
Requires: MACSio-mpich
Requires: simul-mpich
Requires: romio-tests
Requires: python3-mpi4py-tests

%description client-tests-mpich
This is the package needed to run the DAOS client test suite mpich tools

%if %{with server}
%package server-tests
Summary: The DAOS server test suite (server tests)
Requires: %{name}-server%{?_isa} = %{version}-%{release}
Requires: %{name}-admin%{?_isa} = %{version}-%{release}

%description server-tests
This is the package needed to run the DAOS server test suite (server tests)
%endif

%package devel
Summary: The DAOS development libraries and headers
Requires: %{name}-client%{?_isa} = %{version}-%{release}
Requires: libuuid-devel

%description devel
This is the package needed to build software with the DAOS library.

%if %{with server}
%package firmware
Summary: The DAOS firmware management helper
Requires: %{name}-server%{?_isa} = %{version}-%{release}

%description firmware
This is the package needed to manage server storage firmware on DAOS servers.
%endif

%package serialize
Summary: DAOS serialization library that uses HDF5
BuildRequires: hdf5-devel
Requires: hdf5

%description serialize
This is the package needed to use the DAOS serialization and deserialization
tools, as well as the preserve option for the filesystem copy tool.

%package mofed-shim
Summary: A shim to bridge MOFED's openmpi to distribution dependency tags
Provides: libmpi.so.40()(64bit)(openmpi-x86_64)
Requires: libmpi.so.40()(64bit)
Provides: libmpi_cxx.so.40()(64bit)(openmpi-x86_64)
Provides: libmpi_cxx.so.40()(64bit)
BuildArch: noarch

%description mofed-shim
This is the package that bridges the difference between the MOFED openmpi
'Provides' and distribution-openmpi consumers 'Requires'.

%if (0%{?suse_version} > 0)
%global __debug_package 1
%global _debuginfo_subpackages 1
%debug_package
%endif

%prep
%autosetup -p1

%build

%define conf_dir %{_sysconfdir}/daos
%if (0%{?rhel} == 8)
%define scons_exe scons-3
%else
%define scons_exe scons
%endif
%{scons_exe} %{?_smp_mflags} \
      --config=force         \
      --no-rpath             \
      USE_INSTALLED=all      \
      CONF_DIR=%{conf_dir}   \
     %{?daos_build_args}   \
     %{?scons_args}          \
     %{?compiler_args}

%if (%{?compiler_args} == COMPILER=covc)
mv test.cov{,-build}
%endif

%install
%{scons_exe} %{?_smp_mflags}          \
      --config=force                  \
      --no-rpath                      \
      --install-sandbox=%{buildroot}  \
      %{buildroot}%{_prefix}          \
      %{buildroot}%{conf_dir}         \
      USE_INSTALLED=all               \
      CONF_DIR=%{conf_dir}            \
      PREFIX=%{_prefix}               \
     %{?daos_build_args}            \
      %{?scons_args}                  \
      %{?compiler_args}

%if (%{?compiler_args} == COMPILER=covc)
mv test.cov-build %{buildroot}/%{daoshome}/TESTING/ftest/test.cov
%endif
%if %{with server}
mkdir -p %{buildroot}/%{_sysconfdir}/ld.so.conf.d/
echo %{_libdir}/daos_srv > %{buildroot}/%{_sysconfdir}/ld.so.conf.d/daos.conf
mkdir -p %{buildroot}/%{_sysctldir}
install -m 644 utils/rpms/%{sysctl_script_name} %{buildroot}/%{_sysctldir}
%endif
mkdir -p %{buildroot}/%{_unitdir}
%if %{with server}
install -m 644 utils/systemd/%{server_svc_name} %{buildroot}/%{_unitdir}
%endif
install -m 644 utils/systemd/%{agent_svc_name} %{buildroot}/%{_unitdir}
mkdir -p %{buildroot}/%{conf_dir}/certs/clients
mv %{buildroot}/%{conf_dir}/bash_completion.d %{buildroot}/%{_sysconfdir}
# fixup env-script-interpreters
sed -i -e '1s/env //' %{buildroot}%{daoshome}/TESTING/ftest/{cart/cart_logtest,cart/daos_sys_logscan,config_file_gen,launch,slurm_setup,tags,verify_perms}.py
%if %{with server}
sed -i -e '1s/env //' %{buildroot}%{_bindir}/daos_storage_estimator.py
%endif

# shouldn't have source files in a non-devel RPM
rm -f %{buildroot}%{daoshome}/TESTING/ftest/cart/{test_linkage.cpp,utest_{hlc,portnumber,protocol,swim}.c,wrap_cmocka.h}

%if %{with server}
%pre server
getent group daos_metrics >/dev/null || groupadd -r daos_metrics
getent group daos_server >/dev/null || groupadd -r daos_server
getent group daos_daemons >/dev/null || groupadd -r daos_daemons
getent passwd daos_server >/dev/null || useradd -s /sbin/nologin -r -g daos_server -G daos_metrics,daos_daemons daos_server

%post server
%{?run_ldconfig}
%systemd_post %{server_svc_name}
%sysctl_apply %{sysctl_script_name}

%preun server
%systemd_preun %{server_svc_name}

# all of these macros are empty on EL so keep rpmlint happy
%if (0%{?suse_version} > 0)
%postun server
%{?run_ldconfig}
%systemd_postun %{server_svc_name}
%endif
%endif

%pre client
getent group daos_agent >/dev/null || groupadd -r daos_agent
getent group daos_daemons >/dev/null || groupadd -r daos_daemons
getent passwd daos_agent >/dev/null || useradd -s /sbin/nologin -r -g daos_agent -G daos_daemons daos_agent

%post client
%systemd_post %{agent_svc_name}

%preun client
%systemd_preun %{agent_svc_name}

%if (0%{?suse_version} > 0)
%postun client
%systemd_postun %{agent_svc_name}
%endif

%files
%defattr(-, root, root, -)
%doc readme.md
%dir %attr(0755,root,root) %{conf_dir}/certs
%config(noreplace) %{conf_dir}/memcheck-cart.supp
%dir %{conf_dir}
%dir %{_sysconfdir}/bash_completion.d
%{_sysconfdir}/bash_completion.d/daos.bash
# certificate generation files
%dir %{_libdir}/%{name}
%{_libdir}/%{name}/certgen/
%{_libdir}/%{name}/version
%{_libdir}/libcart.so.*
%{_libdir}/libgurt.so.*
%{_libdir}/libdaos_common.so

%if %{with server}
%files server
%doc readme.md
%config(noreplace) %attr(0644,root,root) %{conf_dir}/daos_server.yml
%dir %attr(0700,daos_server,daos_server) %{conf_dir}/certs/clients
# set daos_server_helper to be setuid root in order to perform privileged tasks
%attr(4750,root,daos_server) %{_bindir}/daos_server_helper
# set daos_server to be setgid daos_server in order to invoke daos_server_helper
# and/or daos_firmware_helper
%attr(2755,root,daos_server) %{_bindir}/daos_server
%{_bindir}/daos_engine
%{_bindir}/daos_metrics
%{_bindir}/ddb
%{_sysconfdir}/ld.so.conf.d/daos.conf
%dir %{_libdir}/daos_srv
%{_libdir}/daos_srv/libchk.so
%{_libdir}/daos_srv/libcont.so
%{_libdir}/daos_srv/libddb.so
%{_libdir}/daos_srv/libdtx.so
%{_libdir}/daos_srv/libmgmt.so
%{_libdir}/daos_srv/libobj.so
%{_libdir}/daos_srv/libpool.so
%{_libdir}/daos_srv/librdb.so
%{_libdir}/daos_srv/librdbt.so
%{_libdir}/daos_srv/librebuild.so
%{_libdir}/daos_srv/librsvc.so
%{_libdir}/daos_srv/libsecurity.so
%{_libdir}/daos_srv/libvos_srv.so
%{_libdir}/daos_srv/libvos_size.so
%{_libdir}/daos_srv/libvos.so
%{_libdir}/daos_srv/libbio.so
%{_libdir}/daos_srv/libplacement.so
%{_libdir}/daos_srv/libpipeline.so
%{_libdir}/libdaos_common_pmem.so
%{_libdir}/libdav_v2.so
%config(noreplace) %{conf_dir}/vos_size_input.yaml
%{_bindir}/daos_storage_estimator.py
%{python3_sitearch}/storage_estimator/*.py
%dir %{python3_sitearch}/storage_estimator
%if (0%{?rhel} >= 8)
%dir %{python3_sitearch}/storage_estimator/__pycache__
%{python3_sitearch}/storage_estimator/__pycache__/*.pyc
%endif
%{_datarootdir}/%{name}
%exclude %{_datarootdir}/%{name}/ioil-ld-opts
%{_unitdir}/%{server_svc_name}
%{_sysctldir}/%{sysctl_script_name}
%endif

%files admin
%doc readme.md
%{_bindir}/dmg
%{_mandir}/man8/dmg.8*
%config(noreplace) %{conf_dir}/daos_control.yml

%files client
%doc readme.md
%{_libdir}/libdaos.so.*
%{_bindir}/cart_ctl
%{_bindir}/self_test
%{_bindir}/daos_agent
%{_bindir}/dfuse
%{_bindir}/daos
%{_libdir}/libdaos_cmd_hdlrs.so
%{_libdir}/libdaos_self_test.so
%{_libdir}/libdfs.so
%{_libdir}/libds3.so
%{_libdir}/%{name}/api_version
%{_libdir}/libduns.so
%{_libdir}/libdfuse.so
%{_libdir}/libioil.so
%{_libdir}/libpil4dfs.so
%dir %{python3_sitearch}/pydaos
%{python3_sitearch}/pydaos/*.py
%dir %{python3_sitearch}/pydaos/raw
%{python3_sitearch}/pydaos/raw/*.py
%dir %{python3_sitearch}/pydaos/torch
%{python3_sitearch}/pydaos/torch/*.py
%if (0%{?rhel} >= 8)
%dir %{python3_sitearch}/pydaos/__pycache__
%{python3_sitearch}/pydaos/__pycache__/*.pyc
%dir %{python3_sitearch}/pydaos/raw/__pycache__
%{python3_sitearch}/pydaos/raw/__pycache__/*.pyc
%dir %{python3_sitearch}/pydaos/torch/__pycache__
%{python3_sitearch}/pydaos/torch/__pycache__/*.pyc
%endif
%{python3_sitearch}/pydaos/pydaos_shim.so
%{python3_sitearch}/pydaos/torch/torch_shim.so
%{_datarootdir}/%{name}/ioil-ld-opts
%config(noreplace) %{conf_dir}/daos_agent.yml
%{_unitdir}/%{agent_svc_name}
%{_mandir}/man8/daos.8*

%files client-tests
%doc readme.md
%dir %{daoshome}
%{daoshome}/testing
%exclude %{daoshome}/testing/ftest/avocado_tests.yaml
%{_bindir}/hello_drpc
%{_libdir}/libdaos_tests.so
%{_bindir}/acl_dump_test
%{_bindir}/agent_tests
%{_bindir}/drpc_engine_test
%{_bindir}/drpc_test
%{_bindir}/dfuse_test
%{_bindir}/eq_tests
%{_bindir}/job_tests
%{_bindir}/jump_pl_map
%{_bindir}/pl_bench
%{_bindir}/ring_pl_map
%{_bindir}/security_test
%config(noreplace) %{conf_dir}/fault-inject-cart.yaml
%{_bindir}/fault_status
%{_bindir}/crt_launch
%{_bindir}/daos_perf
%{_bindir}/daos_racer
%{_bindir}/daos_test
%{_bindir}/daos_debug_set_params
%{_bindir}/dfs_test
%{_bindir}/jobtest
%{_bindir}/daos_gen_io_conf
%{_bindir}/daos_run_io_conf
%{_libdir}/libdpar.so

%files client-tests-openmpi
%doc readme.md
%{_libdir}/libdpar_mpi.so

%files client-tests-mpich
%doc readme.md

%if %{with server}
%files server-tests
%doc readme.md
%{_bindir}/dtx_tests
%{_bindir}/dtx_ut
%{_bindir}/evt_ctl
%{_bindir}/rdbt
%{_bindir}/smd_ut
%{_bindir}/bio_ut
%{_bindir}/vea_ut
%{_bindir}/vos_tests
%{_bindir}/vea_stress
%{_bindir}/ddb_tests
%{_bindir}/ddb_ut
%{_bindir}/obj_ctl
%{_bindir}/vos_perf
%endif

%files devel
%doc readme.md
%{_includedir}/*
%{_libdir}/libdaos.so
%{_libdir}/libgurt.so
%{_libdir}/libcart.so
%{_libdir}/*.a
%{daoshome}/python

%if %{with server}
%files firmware
%doc readme.md
# set daos_firmware_helper to be setuid root in order to perform privileged tasks
%attr(4750,root,daos_server) %{_bindir}/daos_firmware_helper
%endif

%files serialize
%doc readme.md
%{_libdir}/libdaos_serialize.so

%files tests
%doc readme.md
# no files in a meta-package

%files tests-internal
%doc readme.md
# no files in a meta-package

%files mofed-shim
%doc readme.md
# no files in a shim package
%endif
"
