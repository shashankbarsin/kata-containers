// Copyright (C) 2025 Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Legacy-device state snapshot (I-008c serial restore gap).
//!
//! Captures the COM1 / COM2 8250-UART register + RX-FIFO state so that a
//! cold restore can drive host→guest serial traffic without losing the
//! guest-configured IER (which determines whether `raw_input` asserts the
//! COM IRQ). Without this, the kernel UART driver post-restore stays
//! blocked in `read()` even though bytes have been enqueued in the
//! emulated RX FIFO.
//!
//! Wire format (per `SerialState` blob):
//!
//! ```text
//! [u8]  baud_divisor_low
//! [u8]  baud_divisor_high
//! [u8]  interrupt_enable
//! [u8]  interrupt_identification
//! [u8]  line_control
//! [u8]  line_status
//! [u8]  modem_control
//! [u8]  modem_status
//! [u8]  scratch
//! [u32 LE] in_buffer_len
//! [N]   in_buffer bytes
//! ```

use std::convert::TryInto;

use dbs_legacy_devices::SerialState;

/// Per-device serial state blobs. Empty `Vec` means "not captured" and is
/// a no-op on apply — keeps older snapshots round-trippable.
#[derive(Debug, Default, Clone)]
pub struct LegacyDeviceState {
    /// Encoded COM1 `SerialState` (or empty for older snapshots).
    pub com1: Vec<u8>,
    /// Encoded COM2 `SerialState` (or empty for older snapshots).
    pub com2: Vec<u8>,
}

/// On-disk size of a fully-populated `SerialState` with an empty FIFO.
const SERIAL_STATE_HEADER_LEN: usize = 9 + 4;

/// Maximum FIFO size we'll accept on decode (defensive bound — vm_superio's
/// FIFO is 64 bytes, snapshot files we generate will never exceed that).
const MAX_FIFO_LEN: usize = 64 * 1024;

/// Serialize a `SerialState` to the wire format documented above.
pub fn encode_serial_state(state: &SerialState) -> Vec<u8> {
    let mut buf = Vec::with_capacity(SERIAL_STATE_HEADER_LEN + state.in_buffer.len());
    buf.push(state.baud_divisor_low);
    buf.push(state.baud_divisor_high);
    buf.push(state.interrupt_enable);
    buf.push(state.interrupt_identification);
    buf.push(state.line_control);
    buf.push(state.line_status);
    buf.push(state.modem_control);
    buf.push(state.modem_status);
    buf.push(state.scratch);
    buf.extend_from_slice(&(state.in_buffer.len() as u32).to_le_bytes());
    buf.extend_from_slice(&state.in_buffer);
    buf
}

/// Decode a `SerialState` from the wire format. Returns `None` for empty
/// input (older snapshot, "not captured"). Errors on truncation / oversize.
pub fn decode_serial_state(bytes: &[u8]) -> std::io::Result<Option<SerialState>> {
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() < SERIAL_STATE_HEADER_LEN {
        return Err(std::io::Error::other(format!(
            "serial state blob too short: {} bytes",
            bytes.len()
        )));
    }
    let mut state = SerialState::default();
    state.baud_divisor_low = bytes[0];
    state.baud_divisor_high = bytes[1];
    state.interrupt_enable = bytes[2];
    state.interrupt_identification = bytes[3];
    state.line_control = bytes[4];
    state.line_status = bytes[5];
    state.modem_control = bytes[6];
    state.modem_status = bytes[7];
    state.scratch = bytes[8];
    let len = u32::from_le_bytes(bytes[9..13].try_into().unwrap()) as usize;
    if len > MAX_FIFO_LEN {
        return Err(std::io::Error::other(format!(
            "serial state in_buffer too large: {len} bytes"
        )));
    }
    if bytes.len() < SERIAL_STATE_HEADER_LEN + len {
        return Err(std::io::Error::other(format!(
            "serial state truncated: have {}, need {}",
            bytes.len(),
            SERIAL_STATE_HEADER_LEN + len
        )));
    }
    state.in_buffer = bytes[SERIAL_STATE_HEADER_LEN..SERIAL_STATE_HEADER_LEN + len].to_vec();
    Ok(Some(state))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_default_state() {
        let s = SerialState::default();
        let bytes = encode_serial_state(&s);
        let back = decode_serial_state(&bytes).unwrap().unwrap();
        assert_eq!(back.baud_divisor_low, s.baud_divisor_low);
        assert_eq!(back.baud_divisor_high, s.baud_divisor_high);
        assert_eq!(back.interrupt_enable, s.interrupt_enable);
        assert_eq!(back.interrupt_identification, s.interrupt_identification);
        assert_eq!(back.line_control, s.line_control);
        assert_eq!(back.line_status, s.line_status);
        assert_eq!(back.modem_control, s.modem_control);
        assert_eq!(back.modem_status, s.modem_status);
        assert_eq!(back.scratch, s.scratch);
        assert!(back.in_buffer.is_empty());
    }

    #[test]
    fn round_trip_with_fifo() {
        let mut s = SerialState::default();
        s.interrupt_enable = 0x01; // ERBFI
        s.line_control = 0x03;
        s.in_buffer = vec![b'a', b'b', b'c', b'\n'];
        let bytes = encode_serial_state(&s);
        let back = decode_serial_state(&bytes).unwrap().unwrap();
        assert_eq!(back.interrupt_enable, 0x01);
        assert_eq!(back.line_control, 0x03);
        assert_eq!(back.in_buffer, vec![b'a', b'b', b'c', b'\n']);
    }

    #[test]
    fn empty_input_decodes_to_none() {
        assert!(decode_serial_state(&[]).unwrap().is_none());
    }

    #[test]
    fn truncated_input_errors() {
        assert!(decode_serial_state(&[0u8; 5]).is_err());
    }
}
