// Copyright (C) 2026 Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Virtio-net device snapshot state (planning-repo audit I-003).
//!
//! Phase 1 captured the per-device **interface spec** — iface_id, host
//! TAP name, guest MAC, queue geometry. Phase 2 (this version) extends
//! the per-device record with the **live device state** needed for a
//! synthesized post-restore activation:
//!
//! * `acked_features` — negotiated VIRTIO feature bits (so the inner
//!   `Net` honours the same MRG_RXBUF / EVENT_IDX / etc. set on restore
//!   as before the snapshot).
//! * one `QueueState` per virtqueue carrying `next_avail`, `next_used`,
//!   ring GPAs (`desc_table`, `avail_ring`, `used_ring`), `ready`,
//!   `event_idx_enabled`, and the actual `size` the driver programmed.
//!
//! Cursors are read out of `MmioV2DeviceState::queues` (clone-shared
//! `QueueSync`/`Arc<Mutex<Queue>>` with the post-`activate` epoll
//! handler — see ADR-0003), and reapplied via the `QueueT` setters
//! before invoking `MmioV2Device::restore_activate`.
//!
//! ## Wire format (v8) — single len-prefixed envelope
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
//!     [u64 LE] acked_features                   (v8)
//!     [u32 LE] queue_count                      (v8)
//!     for each queue:                           (v8)
//!         [u16 LE] index
//!         [u16 LE] size
//!         [u8]     ready              (0 / 1)
//!         [u8]     event_idx_enabled  (0 / 1)
//!         [u16 LE] next_avail
//!         [u16 LE] next_used
//!         [u64 LE] desc_table
//!         [u64 LE] avail_ring
//!         [u64 LE] used_ring
//! ```
//!
//! An empty envelope (`device_count = 0`) is the back-compat encoding
//! for "no virtio-net devices" and is the read-side encoding when the
//! `virtio-net` feature is disabled. v6 and earlier snapshots have no
//! virtio-net block at all and the reader supplies a default empty
//! [`VirtioNetState`].

use std::convert::TryInto;

/// Per-queue live state captured at snapshot time (audit I-003 Phase 2).
/// Mirrors the `dbs_virtio_devices::mmio::mmio_state::QueueSnapshotState`
/// shape exactly so the device-manager layer can copy fields 1:1
/// without an additional translation step.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct QueueState {
    /// Queue index within the device (0 = rx, 1 = tx for a single-pair
    /// virtio-net device; `2` etc. for ctrl-vq if VIRTIO_NET_F_CTRL_VQ
    /// was negotiated).
    pub index: u16,
    /// Driver-programmed queue size in descriptors (must be <= the
    /// device's max queue size).
    pub size: u16,
    /// Whether the driver has marked the queue ready (i.e. armed for
    /// I/O). On restore we expect `true` for every queue captured.
    pub ready: bool,
    /// Whether VIRTIO_RING_F_EVENT_IDX is in effect for this queue.
    pub event_idx_enabled: bool,
    /// Driver-side cursor into the available ring (next descriptor the
    /// driver will publish).
    pub next_avail: u16,
    /// Device-side cursor into the used ring (next descriptor the
    /// device will publish back).
    pub next_used: u16,
    /// Guest physical address of the descriptor table.
    pub desc_table: u64,
    /// Guest physical address of the available ring.
    pub avail_ring: u64,
    /// Guest physical address of the used ring.
    pub used_ring: u64,
}

/// Per-device interface spec + live device state captured at snapshot
/// time. Phase 1 fields populate the interface spec; Phase 2 adds
/// `acked_features` + `queues`.
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
    /// Per-queue size in descriptors (max — actual size used by the
    /// driver is recorded per-`QueueState`).
    pub queue_size: u16,
    /// Negotiated feature bits (`avail_features & guest_features`),
    /// captured directly from the inner `Net::acked_features()`.
    pub acked_features: u64,
    /// Live queue cursors for each virtqueue. Empty for snapshots taken
    /// before the device was activated; the restore path skips
    /// `restore_activate` in that case.
    pub queues: Vec<QueueState>,
}

/// All virtio-net device state captured in a single snapshot.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct VirtioNetState {
    /// One entry per registered virtio-net device, in registration
    /// order.
    pub devices: Vec<VirtioNetDeviceState>,
}

/// Encode a [`VirtioNetState`] envelope to the v8 wire format above.
pub fn encode(state: &VirtioNetState) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + state.devices.len() * 64);
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
        buf.extend_from_slice(&dev.acked_features.to_le_bytes());
        buf.extend_from_slice(&(dev.queues.len() as u32).to_le_bytes());
        for q in &dev.queues {
            buf.extend_from_slice(&q.index.to_le_bytes());
            buf.extend_from_slice(&q.size.to_le_bytes());
            buf.push(if q.ready { 1 } else { 0 });
            buf.push(if q.event_idx_enabled { 1 } else { 0 });
            buf.extend_from_slice(&q.next_avail.to_le_bytes());
            buf.extend_from_slice(&q.next_used.to_le_bytes());
            buf.extend_from_slice(&q.desc_table.to_le_bytes());
            buf.extend_from_slice(&q.avail_ring.to_le_bytes());
            buf.extend_from_slice(&q.used_ring.to_le_bytes());
        }
    }
    buf
}

/// Decode the v8 wire format. Empty input decodes to an empty
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
        let acked_features = cur.read_u64()?;
        let q_count = cur.read_u32()? as usize;
        let mut queues = Vec::with_capacity(q_count);
        for _ in 0..q_count {
            let index = cur.read_u16()?;
            let size = cur.read_u16()?;
            let ready = cur.read_u8()? != 0;
            let event_idx_enabled = cur.read_u8()? != 0;
            let next_avail = cur.read_u16()?;
            let next_used = cur.read_u16()?;
            let desc_table = cur.read_u64()?;
            let avail_ring = cur.read_u64()?;
            let used_ring = cur.read_u64()?;
            queues.push(QueueState {
                index,
                size,
                ready,
                event_idx_enabled,
                next_avail,
                next_used,
                desc_table,
                avail_ring,
                used_ring,
            });
        }
        devices.push(VirtioNetDeviceState {
            iface_id,
            host_dev_name,
            guest_mac,
            num_queues,
            queue_size,
            acked_features,
            queues,
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
    fn read_u64(&mut self) -> std::io::Result<u64> {
        self.need(8)?;
        let v = u64::from_le_bytes(self.buf[self.off..self.off + 8].try_into().unwrap());
        self.off += 8;
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
                acked_features: 0,
                queues: vec![],
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
                    acked_features: 0,
                    queues: vec![],
                },
                VirtioNetDeviceState {
                    iface_id: "eth1".into(),
                    host_dev_name: "tap-b".into(),
                    guest_mac: None,
                    num_queues: 2,
                    queue_size: 256,
                    acked_features: 0,
                    queues: vec![],
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

    #[test]
    fn round_trip_device_with_active_queues() {
        // Realistic virtio-net Phase 2 capture: rx + tx with EVENT_IDX
        // enabled, partially advanced cursors, distinct ring GPAs.
        let s = VirtioNetState {
            devices: vec![VirtioNetDeviceState {
                iface_id: "eth0".into(),
                host_dev_name: "tap-actor0".into(),
                guest_mac: Some([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]),
                num_queues: 2,
                queue_size: 256,
                acked_features: 0x1_0000_002F,
                queues: vec![
                    QueueState {
                        index: 0,
                        size: 256,
                        ready: true,
                        event_idx_enabled: true,
                        next_avail: 17,
                        next_used: 17,
                        desc_table: 0x1_0000_0000,
                        avail_ring: 0x1_0000_1000,
                        used_ring: 0x1_0000_2000,
                    },
                    QueueState {
                        index: 1,
                        size: 256,
                        ready: true,
                        event_idx_enabled: true,
                        next_avail: 3,
                        next_used: 3,
                        desc_table: 0x1_0000_3000,
                        avail_ring: 0x1_0000_4000,
                        used_ring: 0x1_0000_5000,
                    },
                ],
            }],
        };
        let back = decode(&encode(&s)).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn round_trip_queue_cursor_wrap_boundary() {
        // Cursors are free-running u16s. Verify u16::MAX round-trips
        // cleanly (the restore path will mask down to queue size).
        let s = VirtioNetState {
            devices: vec![VirtioNetDeviceState {
                iface_id: "eth0".into(),
                host_dev_name: "tap-x".into(),
                guest_mac: None,
                num_queues: 2,
                queue_size: 256,
                acked_features: u64::MAX,
                queues: vec![QueueState {
                    index: 0,
                    size: 256,
                    ready: true,
                    event_idx_enabled: false,
                    next_avail: u16::MAX,
                    next_used: u16::MAX - 1,
                    desc_table: u64::MAX - 0x1000,
                    avail_ring: u64::MAX - 0x800,
                    used_ring: u64::MAX - 0x400,
                }],
            }],
        };
        let back = decode(&encode(&s)).unwrap();
        assert_eq!(back, s);
    }
}
