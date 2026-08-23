// SPDX-License-Identifier: AGPL-3.0-or-later
//! Vigile USBGuard backend (Phase 4): USB device inventory, rule
//! generation, and approval workflow.
//!
//! USBGuard rule format (from usbguard(5)):
//!   <target> [device_id] [device_attributes]
//!
//! Targets: allow, deny, reject, block
//! Device ID: vendor_id:product_id (hex, 4 digits each)
//! Attributes: serial, hash, name, via-port, with-interface, etc.

use serde::{Deserialize, Serialize};
use std::process::Command;

/// One USB device as seen by lsusb.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsbDevice {
    /// Bus number (decimal).
    pub bus: u8,
    /// Device address on the bus (decimal).
    pub device: u8,
    /// Vendor ID (4 hex digits, e.g. "1d6b").
    pub vendor_id: String,
    /// Product ID (4 hex digits, e.g. "0002").
    pub product_id: String,
    /// Human-readable device name.
    pub name: String,
    /// Serial number (if present; used for persistent identification).
    pub serial: Option<String>,
}

/// USBGuard rule target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UsbTarget {
    Allow,
    Deny,
    Reject,
    Block,
}

impl UsbTarget {
    pub fn as_str(&self) -> &'static str {
        match self {
            UsbTarget::Allow => "allow",
            UsbTarget::Deny => "deny",
            UsbTarget::Reject => "reject",
            UsbTarget::Block => "block",
        }
    }
}

/// A generated USBGuard rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UsbRule {
    pub target: UsbTarget,
    /// "all" or "id vendor:product".
    pub device_id: String,
    /// Additional match criteria (serial, name, via-port...).
    pub attributes: Vec<String>,
}

impl UsbRule {
    pub fn to_rule_string(&self) -> String {
        let mut parts = vec![self.target.as_str().to_string()];
        parts.push(self.device_id.clone());
        parts.extend(self.attributes.iter().cloned());
        parts.join(" ")
    }
}

/// Generates a default-deny rule (the baseline for Phase 4).
pub fn default_deny_rule() -> UsbRule {
    UsbRule {
        target: UsbTarget::Deny,
        device_id: "all".to_string(),
        attributes: vec![],
    }
}

/// Generates an allow rule for a specific device.
pub fn allow_device(device: &UsbDevice) -> UsbRule {
    let mut attributes = vec![format!("name \"{}\"", device.name)];
    if let Some(serial) = &device.serial {
        attributes.push(format!("serial \"{serial}\""));
    }
    UsbRule {
        target: UsbTarget::Allow,
        device_id: format!("id {}:{}", device.vendor_id, device.product_id),
        attributes,
    }
}

/// Generates an allow rule for a keyboard or mouse (essential peripherals
/// that must always be allowed — FM-12 decision).
pub fn allow_essential_peripheral(device: &UsbDevice) -> UsbRule {
    let mut rule = allow_device(device);
    rule.attributes.push("with-interface 03:00:01".to_string()); // HID boot keyboard
    rule
}

/// USB device approval (maps to the approval workflow).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum UsbApprovalScope {
    /// This specific serial number.
    Serial { serial: String },
    /// This vendor:product combination.
    DeviceId {
        vendor_id: String,
        product_id: String,
    },
    /// Everything on this USB port.
    Port { port: String },
}

/// Parses `lsusb` output (one device per line).
/// Format: `Bus 001 Device 002: ID 1d6b:0002 Linux Foundation EHCI Host Controller`
pub fn parse_lsusb(output: &str) -> Vec<UsbDevice> {
    let mut devices = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Bus 001 Device 002: ID 1d6b:0002 Linux Foundation EHCI Host Controller
        let Some(rest) = line.strip_prefix("Bus ") else {
            continue;
        };
        let parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        let Ok(bus) = parts[0].parse::<u8>() else {
            continue;
        };
        if parts[1] != "Device" {
            continue;
        }
        let Ok(device) = parts[2].trim_end_matches(':').parse::<u8>() else {
            continue;
        };
        if parts[3] != "ID" {
            continue;
        }
        let Some((vendor_id, product_id)) = parts[4].split_once(':') else {
            continue;
        };
        let name = parts[5..].join(" ");
        devices.push(UsbDevice {
            bus,
            device,
            vendor_id: vendor_id.to_string(),
            product_id: product_id.to_string(),
            name,
            serial: None, // lsusb doesn't show serial by default
        });
    }
    devices
}

/// Runs `lsusb` and returns the parsed devices.
pub fn run_lsusb() -> Result<Vec<UsbDevice>, std::io::Error> {
    let output = Command::new("lsusb").output()?;
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "lsusb failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(parse_lsusb(&String::from_utf8_lossy(&output.stdout)))
}

/// Runs `lsusb -v` for a specific device to get the serial number.
pub fn get_serial(bus: u8, device: u8) -> Option<String> {
    let output = Command::new("lsusb")
        .args(["-v", "-s", &format!("{bus}:{device}")])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("iSerial") {
            let serial = rest.split_whitespace().nth(1)?;
            if serial != "0" {
                return Some(serial.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    #[test]
    fn parse_lsusb_nominal() {
        let output = "\
Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub
Bus 001 Device 002: ID 8087:0024 Intel Corp. Integrated Rate Matching Hub
Bus 002 Device 001: ID 1d6b:0003 Linux Foundation 3.0 root hub
Bus 002 Device 003: ID 046d:c52b Logitech, Inc. Unifying Receiver";
        let devices = parse_lsusb(output);
        assert_eq!(devices.len(), 4);
        assert_eq!(devices[0].vendor_id, "1d6b");
        assert_eq!(devices[0].product_id, "0002");
        assert_eq!(devices[0].name, "Linux Foundation 2.0 root hub");
        assert_eq!(devices[3].vendor_id, "046d");
        assert_eq!(devices[3].product_id, "c52b");
    }

    #[test]
    fn parse_lsusb_hostile() {
        let devices = parse_lsusb("");
        assert!(devices.is_empty());

        let devices = parse_lsusb("not lsusb output\nBus: bad\nrandom text");
        assert!(devices.is_empty());
    }

    #[test]
    fn rule_generation() {
        let deny = default_deny_rule();
        assert_eq!(deny.to_rule_string(), "deny all");

        let device = UsbDevice {
            bus: 1,
            device: 3,
            vendor_id: "046d".into(),
            product_id: "c52b".into(),
            name: "Logitech Unifying Receiver".into(),
            serial: Some("ABC123".into()),
        };
        let rule = allow_device(&device);
        assert!(rule.to_rule_string().contains("allow id 046d:c52b"));
        assert!(rule.to_rule_string().contains("serial \"ABC123\""));
    }

    #[test]
    fn essential_peripheral_has_hid_interface() {
        let device = UsbDevice {
            bus: 1,
            device: 2,
            vendor_id: "046d".into(),
            product_id: "c31c".into(),
            name: "Logitech Keyboard".into(),
            serial: None,
        };
        let rule = allow_essential_peripheral(&device);
        assert!(rule.to_rule_string().contains("with-interface 03:00:01"));
    }
}
