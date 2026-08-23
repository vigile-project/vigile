# Vigile — RPM spec file (ISS-048)
#
# Build: rpmbuild -ba vigile.spec (from the repository root)
# Install: dnf install vigile-<version>-<release>.fc44.<arch>.rpm
#
# The RPM installs:
# - /usr/sbin/vigile-agent       (unprivileged agent binary)
# - /usr/sbin/vigile-executor    (privileged executor binary)
# - /usr/sbin/vigile-server      (control plane server binary)
# - /usr/share/vigile/web/       (admin portal, static HTML)
# - /etc/vigile/                 (configuration, trust anchor)
# - systemd units (hardened, see packaging/systemd/HARDENING.md)
# - Creates the 'vigile' system user (no shell, no login)

Name:           vigile
Version:        0.1.0
Release:        1%{?dist}
Summary:        Open-source Zero Trust application control for Linux

License:        AGPL-3.0-or-later
URL:            https://github.com/vigile-project/vigile
Source0:        %{name}-%{version}.tar.gz

# Build dependencies: Rust toolchain + cargo
BuildRequires:  rust-packaging >= 21
BuildRequires:  cargo >= 1.70
BuildRequires:  rust >= 1.70
BuildRequires:  systemd-rpm-macros

# Runtime dependencies
Requires:       systemd
Requires:       fapolicyd >= 2.0
# PostgreSQL client library (for vigile-server)
# Requires:       postgresql-libs

%{?systemd_requires}

# Architecture: wherever Rust compiles (x86_64, aarch64)
ExclusiveArch:  %{rust_arches}

%description
Vigile is an open-source Zero Trust application control platform for
Linux. It provides centralized allowlisting with deny-by-default,
approval workflows, deployment canarying and automatic rollback.

Components:
- vigile-agent: unprivileged agent (inventory, sync, event collection)
- vigile-executor: minimal privileged executor (policy application)
- vigile-server: control plane (HTTP/mTLS API, admin, audit journal)

%prep
%autosetup -n %{name}-%{version}

%build
# Build the Rust workspace in release mode.
cd rust
export CARGO_HOME=${PWD}/.cargo
cargo build --release --workspace
cd ..

%install
# --- Binaries ---
install -Dm755 rust/target/release/vigile-agent \
    %{buildroot}%{_sbindir}/vigile-agent
install -Dm755 rust/target/release/vigile-executor \
    %{buildroot}%{_sbindir}/vigile-executor
install -Dm755 rust/target/release/vigile-server \
    %{buildroot}%{_sbindir}/vigile-server

# --- Web portal ---
install -Dm644 web/index.html \
    %{buildroot}%{_datadir}/vigile/web/index.html

# --- Systemd units ---
install -Dm644 packaging/systemd/vigile-agent.service \
    %{buildroot}%{_unitdir}/vigile-agent.service
install -Dm644 packaging/systemd/vigile-executor.service \
    %{buildroot}%{_unitdir}/vigile-executor.service

# --- Configuration directory (trust anchor placeholder) ---
install -Dm644 /dev/null \
    %{buildroot}%{_sysconfdir}/vigile/.gitkeep

# --- Documentation ---
install -Dm644 README.md %{buildroot}%{_docdir}/%{name}/README.md
install -Dm644 LICENSE %{buildroot}%{_docdir}/%{name}/LICENSE
install -Dm644 packaging/systemd/HARDENING.md \
    %{buildroot}%{_docdir}/%{name}/HARDENING.md

# --- Recovery script (ISS-051) ---
install -Dm755 packaging/recovery/vigile-breakglass \
    %{buildroot}%{_sbindir}/vigile-breakglass

%pre
# Create the vigile system user (no shell, no login, system account).
getent group vigile >/dev/null || groupadd -r vigile
getent passwd vigile >/dev/null || \
    useradd -r -g vigile -d /var/lib/vigile -s /sbin/nologin \
    -c "Vigile security agent" vigile

# Create the vigile-exec group for the IPC socket.
getent group vigile-exec >/dev/null || groupadd -r vigile-exec

%post
%systemd_post vigile-agent.service vigile-executor.service

%preun
%systemd_preun vigile-agent.service vigile-executor.service

%postun
%systemd_postun vigile-agent.service vigile-executor.service
if [ $1 -eq 0 ]; then
    # Package removal: clean up the user/group.
    userdel vigile 2>/dev/null || :
    groupdel vigile-exec 2>/dev/null || :
fi

%files
%defattr(-,root,root,-)
# Binaries
%{_sbindir}/vigile-agent
%{_sbindir}/vigile-executor
%{_sbindir}/vigile-server
%{_sbindir}/vigile-breakglass

# Web portal
%{_datadir}/vigile/web/index.html

# Systemd units
%{_unitdir}/vigile-agent.service
%{_unitdir}/vigile-executor.service

# Configuration
%dir %{_sysconfdir}/vigile

# Documentation
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/HARDENING.md
%license %{_docdir}/%{name}/LICENSE

%changelog
* Sun Aug 23 2026 Vigile Project <vigile@vigile-project.org> - 0.1.0-1
- Initial packaging: agent, executor, server, systemd units, web portal
- 205 tests passing, clippy strict, fapolicyd 2.0 validated in VM
