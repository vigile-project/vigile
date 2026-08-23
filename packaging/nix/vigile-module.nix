# Vigile NixOS module (Phase 9, ADR-0008)
#
# declarative state (in Nix config) vs dynamic state (in /var/lib/vigile):
# - declarative: presence, components, server URL, backend options, hardening
# - dynamic (never in the Nix store): policy cache, LKG, event queues, agent identity
# - secrets: injected via sops-nix/agenix (operator's choice), never in the store
#
# Usage in configuration.nix:
#   imports = [ /path/to/vigile/packaging/nix/vigile-module.nix ];
#   services.vigile = {
#     enable = true;
#     serverUrl = "https://vigile.example.com";
#   };

{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.services.vigile;
in
{
  options.services.vigile = {
    enable = mkEnableOption "Vigile security agent";

    serverUrl = mkOption {
      type = types.str;
      description = "URL of the Vigile control plane server";
      example = "https://vigile.example.com";
    };

    package = mkOption {
      type = types.package;
      description = "Vigile package (built from the flake)";
    };

    # Backends to activate (capability detection happens at runtime,
    # but the operator can force-enable or disable).
    enableFapolicyd = mkOption {
      type = types.bool;
      default = false;
      description = "Enable fapolicyd backend (unavailable on NixOS — see ADR-0008)";
    };

    # Trust anchor: path to the server CA certificate.
    # This file must NOT be in the Nix store (it would be world-readable).
    # Use a runtime secret mechanism (sops-nix, agenix) to place it at
    # /run/vigile/server-ca.pem before the agent starts.
    trustAnchorPath = mkOption {
      type = types.str;
      default = "/run/vigile/server-ca.pem";
      description = "Path to the server CA certificate (must not be in the Nix store)";
    };
  };

  config = mkIf cfg.enable {
    # Warn if fapolicyd is enabled (not available on NixOS).
    warnings = optional cfg.enableFapolicyd
      "fapolicyd is not natively available on NixOS (ADR-0008); the allowlisting backend will report 'unavailable'.";

    # System user for the agent (no shell, system account).
    users.users.vigile = {
      isSystemUser = true;
      group = "vigile";
      home = "/var/lib/vigile";
      createHome = true;
      shell = "/sbin/nologin";
      description = "Vigile security agent";
    };

    users.groups.vigile = {};
    users.groups.vigile-exec = {};

    # Agent service (hardened per packaging/systemd/HARDENING.md).
    systemd.services.vigile-agent = {
      description = "Vigile security agent (unprivileged)";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      serviceConfig = {
        Type = "notify";
        User = "vigile";
        Group = "vigile";
        ExecStart = "${cfg.package}/bin/vigile-agent --server ${cfg.serverUrl} --trust-anchor ${cfg.trustAnchorPath}";

        # Filesystem hardening (mirrors the systemd unit in the RPM).
        ProtectSystem = "strict";
        ReadWritePaths = [ "/var/lib/vigile" ];
        ProtectHome = "yes";
        PrivateTmp = "yes";
        PrivateDevices = "yes";

        # Privilege escalation prevention.
        NoNewPrivileges = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;

        # Kernel protections.
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        ProtectKernelLogs = true;
        ProtectClock = true;

        # Network: agent needs HTTPS + Unix socket for IPC.
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];

        # Memory.
        MemoryDenyWriteExecute = true;
        RestrictRealtime = true;

        # Capabilities: NONE.
        CapabilityBoundingSet = "";

        # Seccomp: deny dangerous syscall groups.
        SystemCallFilter = [ "~@obsolete" "~@mount" "~@debug" "~@swap" ];

        # Resource limits.
        MemoryMax = "150M";
        CPUQuota = "10%";
        LimitNOFILE = 4096;
        LimitCORE = 0;

        # Misc.
        UMask = "0077";
        StateDirectory = "vigile";
        StateDirectoryMode = "0750";
      };
    };

    # Executor service (privileged, minimal).
    systemd.services.vigile-executor = {
      description = "Vigile privileged executor (minimal)";
      wantedBy = [ "multi-user.target" ];
      before = [ "vigile-agent.service" ];

      serviceConfig = {
        Type = "notify";
        User = "root";
        Group = "root";
        ExecStart = "${cfg.package}/bin/vigile-executor --socket /run/vigile/executor.sock";

        # Runtime directory for the IPC socket.
        RuntimeDirectory = "vigile";
        RuntimeDirectoryMode = "0750";

        # Filesystem: strict + minimal write paths.
        ProtectSystem = "strict";
        ReadWritePaths = [
          "/var/lib/vigile/executor"
          "/etc/fapolicyd"  # only if fapolicyd is enabled
          "/run/vigile"
        ];
        ProtectHome = "yes";
        PrivateTmp = "yes";
        PrivateDevices = "yes";

        NoNewPrivileges = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;

        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        ProtectKernelLogs = true;
        ProtectClock = true;

        # NO network for the executor.
        RestrictAddressFamilies = [ "AF_UNIX" ];

        MemoryDenyWriteExecute = true;
        RestrictRealtime = true;

        # Capabilities: minimal (see HARDENING.md).
        CapabilityBoundingSet = "CAP_DAC_OVERRIDE CAP_FOWNER";

        SystemCallFilter = [ "~@network-io" "~@obsolete" "~@mount" "~@debug" "~@swap" ];
        SystemCallArchitectures = "native";

        MemoryMax = "100M";
        CPUQuota = "20%";
        LimitNOFILE = 256;
        LimitCORE = 0;
        TasksMax = 16;

        UMask = "0077";
      };
    };
  };
}
