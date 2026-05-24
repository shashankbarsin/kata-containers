// Copyright (C) 2026 Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Virtio-net device snapshot state (planning-repo audit I-003).
//!
//! Phase 1 (this file) captures the per-device **interface spec** —
//! iface_id, host TAP name, guest MAC, queue geometry. This is enough
//! to round-trip the wire format and verify the codec + wiring; it is
//! NOT enough on its own to restore an active virtio-net device because
//! the live queue cursors (`next_avail`, `next_used`, ring GPAs,
//! `ready`, `event_idx_enabled`) live inside the per-device epoll
//! handler and are not yet captured. Phase 2 adds those by clone-sharing
//! the `QueueSync` Arc from `Net::activate` (see planning-repo
//! `docs/audits/I-003-*.md` §3 + §10 Q#1, ADR-0003 "Virtio-net
//! snapshot/restore design").
//!
//! ## Wire format (v7) — single len-prefixed envelope
//!
//! ```text
//! [u32 LE] device_count
//! for each device:
//!     [u32 LE] iface_id_len
//!     [bytes]  iface_id (UTF-8)
//!     [u32 LE] host_dev_name_len
//!     [bytes]  host_dev_name (UTF-8)
//!     [u8]     guest_mac_present (0 or 1)
//!     [6 u8]   guest_mac (zero-filled if !present)
//!     [u8]     num_queues
//!     [u16 LE] queue_size
//! ```
//!
//! An empty envelope (`device_count = 0`) is the back-compat encoding
//! for "no virtio-net devices" and is the read-side encoding when the
//! `virtio-net` feature is disabled. Older v6 snapshots have no v7
//! block at all and the reader supplies a default empty
//! [`VirtioNetState`].

use std::convert::TryInto;

/// Per-device interface spec captured at snapshot time. Phase 1: iface
/// geometry only; Phase 2 will add queue cursors + ring GPAs +
/// negotiated features.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct VirtioNetDeviceState {
    /// Logical interface ID assigned by the substrate
    /// (`VirtioNetDeviceConfigInfo::iface_id`).
    pub iface_id: String,
    /// Host TAP device name backing this virtio-net device.
    pub host_dev_name: String,
    /// Guest-visible MAC address, if one was assigned at create time.
    pub guest_mac: Option<[u8; 6]>,
    /// Number of virtqueues negotiated for this device (rx + tx = 2 in
    /// the Phase-1 single-pair case).
    pub num_queues: u8,
    /// Per-queue size in descriptors.
    pub queue_size: u16,
}

/// All virtio-net device state captured in a single snapshot.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct VirtioNetState {
    /// One entry per registered virtio-net device, in registration
    /// order.
    pub devices: Vec<VirtioNetDeviceState>,
}

/// Encode a [`VirtioNetState`] envelope to the v7 wire format above.
pub fn encode(state: &VirtioNetState) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + state.devices.len() * 32);
    buf.extend_from_slice(&(state.devices.len() as u32).to_le_bytes());
    for dev in &state.devices {
        buf.extend_from_slice(&(dev.iface_id.len() as u32).to_le_bytes());
        buf.extend_from_slice(dev.iface_id.as_bytes());
        buf.extend_from_slice(&(dev.host_dev_name.len() as u32).to_le_bytes());
        buf.extend_from_slice(dev.host_dev_name.as_bytes());
        match dev.guest_mac {
            Some(mac) => {
                buf.push(1);
                buf.extend_from_slice(&mac);
            }
            None => {
                buf.push(0);
                buf.extend_from_slice(&[0u8; 6]);
            }
        }
        buf.push(dev.num_queues);
        buf.extend_from_slice(&dev.queue_size.to_le_bytes());
    }
    buf
}

/// Decode the v7 wire format. Empty input decodes to an empty
/// [`VirtioNetState`] (older snapshots; "no devices captured").
pub fn decode(bytes: &[u8]) -> std::io::Result<VirtioNetState> {
    if bytes.is_empty() {
        return Ok(VirtioNetState::default());
    }
    let mut cur = Cursor { buf: bytes, off: 0 };
    let count = cur.read_u32()? as usize;
    let mut devices = Vec::with_capacity(count);
    for _ in 0..count {
        let iface_len = cur.read_u32()? as usize;
        let iface_id = cur.read_string(iface_len)?;
        let host_len = cur.read_u32()? as usize;
        let host_dev_name = cur.read_string(host_len)?;
        let mac_present = cur.read_u8()?;
        let mac_bytes = cur.read_array::<6>()?;
        let guest_mac = if mac_present == 1 {
            Some(mac_bytes)
        } else {
            None
        };
        let num_queues = cur.read_u8()?;
        let queue_size = cur.read_u16()?;
        devices.push(VirtioNetDeviceState {
            iface_id,
            host_dev_name,
            guest_mac,
            num_queues,
            queue_size,
        });
    }
    Ok(VirtioNetState { devices })
}

struct Cursor<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> Cursor<'a> {
    fn need(&self, n: usize) -> std::io::Result<()> {
        if self.off + n > self.buf.len() {
            return Err(std::io::Error::other(format!(
                "virtio-net state truncated: need {} more bytes at offset {}",
                n, self.off
            )));
        }
        Ok(())
    }
    fn read_u8(&mut self) -> std::io::Result<u8> {
        self.need(1)?;
        let v = self.buf[self.off];
        self.off += 1;
        Ok(v)
    }
    fn read_u16(&mut self) -> std::io::Result<u16> {
        self.need(2)?;
        let v = u16::from_le_bytes(self.buf[self.off..self.off + 2].try_into().unwrap());
        self.off += 2;
        Ok(v)
    }
    fn read_u32(&mut self) -> std::io::Result<u32> {
        self.need(4)?;
        let v = u32::from_le_bytes(self.buf[self.off..self.off + 4].try_into().unwrap());
        self.off += 4;
        Ok(v)
    }
    fn read_array<const N: usize>(&mut self) -> std::io::Result<[u8; N]> {
        self.need(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(&self.buf[self.off..self.off + N]);
        self.off += N;
        Ok(out)
    }
    fn read_string(&mut self, n: usize) -> std::io::Result<String> {
        self.need(n)?;
        let s = std::str::from_utf8(&self.buf[self.off..self.off + n])
            .map_err(|e| std::io::Error::other(format!("non-UTF-8 string: {e}")))?
            .to_string();
        self.off += n;
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_empty() {
        let s = VirtioNetState::default();
        let bytes = encode(&s);
        assert_eq!(bytes, vec![0, 0, 0, 0]); // device_count = 0
        let back = decode(&bytes).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn empty_input_decodes_to_default() {
        let back = decode(&[]).unwrap();
        assert_eq!(back, VirtioNetState::default());
    }

    #[test]
    fn round_trip_single_device_with_mac() {
        let s = VirtioNetState {
            devices: vec![VirtioNetDeviceState {
                iface_id: "eth0".into(),
                host_dev_name: "tap-actor0".into(),
                guest_mac: Some([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]),
                num_queues: 2,
                queue_size: 256,
            }],
        };
        let back = decode(&encode(&s)).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn round_trip_multiple_devices_mixed_mac() {
        let s = VirtioNetState {
            devices: vec![
                VirtioNetDeviceState {
                    iface_id: "eth0".into(),
                    host_dev_name: "tap-a".into(),
                    guest_mac: Some([0xaa; 6]),
                    num_queues: 2,
                    queue_size: 128,
                },
                VirtioNetDeviceState {
                    iface_id: "eth1".into(),
                    host_dev_name: "tap-b".into(),
                    guest_mac: None,
                    num_queues: 2,
                    queue_size: 256,
                },
            ],
        };
        let back = decode(&encode(&s)).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn truncated_input_errors() {
        // Claim 1 device but supply only the count.
        let bytes = vec![1u8, 0, 0, 0];
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn oversize_string_len_errors() {
        // device_count=1, iface_id_len=u32::MAX, no bytes.
        let mut bytes = vec![1u8, 0, 0, 0];
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode(&bytes).is_err());
    }
}
