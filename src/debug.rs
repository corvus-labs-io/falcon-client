// Wire protocol constants for the debug event stream.
//
// Control (client → server on bi-stream send half):
//   byte 0 = 0x00 (control prefix)
//   byte 1 = CONTROL_SUBSCRIBE
//   Closing the send half signals unsubscribe.
//
// Debug events (server → client on bi-stream recv half):
//   repeating frames: [u32 LE length] [event bytes]

pub(crate) const STREAM_PREFIX_CONTROL: u8 = 0x00;

pub(crate) const CONTROL_SUBSCRIBE: u8 = 0x01;

const KIND_VALIDATION_OK: u8 = 0x00;
const KIND_VALIDATION_ERR: u8 = 0x01;
const KIND_FORWARD_OK: u8 = 0x02;
const KIND_FORWARD_ERR: u8 = 0x03;
const KIND_EVENTS_DROPPED: u8 = 0x04;
const KIND_SUBSCRIBED: u8 = 0x05;
const KIND_UNSUBSCRIBED: u8 = 0x06;

pub(crate) const MAX_DEBUG_EVENT_SIZE: usize = 65536;

/// A single debug event from the server.
///
/// Sequence numbers are monotonic per connection — gaps indicate dropped
/// events. Use [`DebugEventKind`] to match on the event type.
#[derive(Debug, Clone)]
pub struct DebugEvent {
    pub sequence: u64,
    pub timestamp_us: u64,
    pub signature: Option<[u8; 64]>,
    pub kind: DebugEventKind,
}

/// The type of debug event.
#[derive(Debug, Clone)]
pub enum DebugEventKind {
    /// Transaction passed server-side validation.
    ValidationOk,
    /// Transaction failed validation.
    ValidationErr { reason: String },
    /// Transaction forwarded to the bridge(s).
    ForwardOk {
        forward_latency_us: u64,
        e2e_latency_us: u64,
        bridges_attempted: u16,
        failover: bool,
    },
    /// Forward attempt failed.
    ForwardErr { reason: String },
    /// Debug channel was full; this many events were lost.
    EventsDropped { count: u64 },
    /// Debug subscription confirmed by server.
    Subscribed,
    /// Debug subscription ended by server.
    Unsubscribed,
}

impl DebugEvent {
    /// Deserializes a debug event from the server's wire format.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 18 {
            return Err("event too short");
        }
        let mut pos = 0;

        let sequence = read_u64(bytes, &mut pos);
        let timestamp_us = read_u64(bytes, &mut pos);
        let kind_tag = bytes[pos];
        pos += 1;

        let has_sig = bytes[pos];
        pos += 1;
        let signature = if has_sig == 1 {
            if pos + 64 > bytes.len() {
                return Err("truncated signature");
            }
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&bytes[pos..pos + 64]);
            pos += 64;
            Some(sig)
        } else {
            None
        };

        let kind = match kind_tag {
            KIND_VALIDATION_OK => DebugEventKind::ValidationOk,
            KIND_VALIDATION_ERR => {
                let reason = read_length_prefixed_string(bytes, &mut pos)?;
                DebugEventKind::ValidationErr { reason }
            }
            KIND_FORWARD_OK => {
                if pos + 19 > bytes.len() {
                    return Err("truncated forward ok");
                }
                let forward_latency_us = read_u64(bytes, &mut pos);
                let e2e_latency_us = read_u64(bytes, &mut pos);
                let bridges_attempted = read_u16(bytes, &mut pos);
                let failover = bytes[pos] != 0;
                let _ = pos;
                DebugEventKind::ForwardOk {
                    forward_latency_us,
                    e2e_latency_us,
                    bridges_attempted,
                    failover,
                }
            }
            KIND_FORWARD_ERR => {
                let reason = read_length_prefixed_string(bytes, &mut pos)?;
                DebugEventKind::ForwardErr { reason }
            }
            KIND_EVENTS_DROPPED => {
                if pos + 8 > bytes.len() {
                    return Err("truncated dropped count");
                }
                let count = read_u64(bytes, &mut pos);
                DebugEventKind::EventsDropped { count }
            }
            KIND_SUBSCRIBED => DebugEventKind::Subscribed,
            KIND_UNSUBSCRIBED => DebugEventKind::Unsubscribed,
            _ => return Err("unknown event kind"),
        };

        Ok(DebugEvent {
            sequence,
            timestamp_us,
            signature,
            kind,
        })
    }

    /// Serializes this event to the wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);

        buf.extend_from_slice(&self.sequence.to_le_bytes());
        buf.extend_from_slice(&self.timestamp_us.to_le_bytes());

        buf.push(kind_tag(&self.kind));

        match &self.signature {
            Some(sig) => {
                buf.push(1);
                buf.extend_from_slice(sig);
            }
            None => buf.push(0),
        }

        write_kind_payload(&mut buf, &self.kind);
        buf
    }
}

fn kind_tag(kind: &DebugEventKind) -> u8 {
    match kind {
        DebugEventKind::ValidationOk => KIND_VALIDATION_OK,
        DebugEventKind::ValidationErr { .. } => KIND_VALIDATION_ERR,
        DebugEventKind::ForwardOk { .. } => KIND_FORWARD_OK,
        DebugEventKind::ForwardErr { .. } => KIND_FORWARD_ERR,
        DebugEventKind::EventsDropped { .. } => KIND_EVENTS_DROPPED,
        DebugEventKind::Subscribed => KIND_SUBSCRIBED,
        DebugEventKind::Unsubscribed => KIND_UNSUBSCRIBED,
    }
}

fn write_kind_payload(buf: &mut Vec<u8>, kind: &DebugEventKind) {
    match kind {
        DebugEventKind::ValidationOk
        | DebugEventKind::Subscribed
        | DebugEventKind::Unsubscribed => {}
        DebugEventKind::ValidationErr { reason } | DebugEventKind::ForwardErr { reason } => {
            write_length_prefixed_string(buf, reason);
        }
        DebugEventKind::ForwardOk {
            forward_latency_us,
            e2e_latency_us,
            bridges_attempted,
            failover,
        } => {
            buf.extend_from_slice(&forward_latency_us.to_le_bytes());
            buf.extend_from_slice(&e2e_latency_us.to_le_bytes());
            buf.extend_from_slice(&bridges_attempted.to_le_bytes());
            buf.push(u8::from(*failover));
        }
        DebugEventKind::EventsDropped { count } => {
            buf.extend_from_slice(&count.to_le_bytes());
        }
    }
}

fn write_length_prefixed_string(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(u16::MAX as usize);
    buf.extend_from_slice(&(len as u16).to_le_bytes());
    buf.extend_from_slice(&bytes[..len]);
}

fn read_u64(bytes: &[u8], pos: &mut usize) -> u64 {
    let val = u64::from_le_bytes(bytes[*pos..*pos + 8].try_into().unwrap());
    *pos += 8;
    val
}

fn read_u16(bytes: &[u8], pos: &mut usize) -> u16 {
    let val = u16::from_le_bytes(bytes[*pos..*pos + 2].try_into().unwrap());
    *pos += 2;
    val
}

fn read_length_prefixed_string(bytes: &[u8], pos: &mut usize) -> Result<String, &'static str> {
    if *pos + 2 > bytes.len() {
        return Err("truncated string length");
    }
    let len = read_u16(bytes, pos) as usize;
    if *pos + len > bytes.len() {
        return Err("truncated string data");
    }
    let s = std::str::from_utf8(&bytes[*pos..*pos + len]).map_err(|_| "invalid utf-8")?;
    *pos += len;
    Ok(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_validation_ok() {
        let event = DebugEvent {
            sequence: 42,
            timestamp_us: 123456,
            signature: Some([0xAB; 64]),
            kind: DebugEventKind::ValidationOk,
        };
        let bytes = event.to_bytes();
        let decoded = DebugEvent::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded.sequence, 42);
        assert_eq!(decoded.timestamp_us, 123456);
        assert_eq!(decoded.signature, Some([0xAB; 64]));
        assert!(matches!(decoded.kind, DebugEventKind::ValidationOk));
    }

    #[test]
    fn roundtrip_validation_err() {
        let event = DebugEvent {
            sequence: 1,
            timestamp_us: 999,
            signature: Some([0x01; 64]),
            kind: DebugEventKind::ValidationErr {
                reason: "missing tip".to_string(),
            },
        };
        let bytes = event.to_bytes();
        let decoded = DebugEvent::from_bytes(&bytes).expect("decode");
        match &decoded.kind {
            DebugEventKind::ValidationErr { reason } => assert_eq!(reason, "missing tip"),
            other => panic!("expected ValidationErr, got {other:?}"),
        }
    }

    #[test]
    fn roundtrip_forward_ok() {
        let event = DebugEvent {
            sequence: 5,
            timestamp_us: 1000,
            signature: None,
            kind: DebugEventKind::ForwardOk {
                forward_latency_us: 150,
                e2e_latency_us: 300,
                bridges_attempted: 3,
                failover: true,
            },
        };
        let bytes = event.to_bytes();
        let decoded = DebugEvent::from_bytes(&bytes).expect("decode");
        assert!(decoded.signature.is_none());
        match &decoded.kind {
            DebugEventKind::ForwardOk {
                forward_latency_us,
                e2e_latency_us,
                bridges_attempted,
                failover,
            } => {
                assert_eq!(*forward_latency_us, 150);
                assert_eq!(*e2e_latency_us, 300);
                assert_eq!(*bridges_attempted, 3);
                assert!(*failover);
            }
            other => panic!("expected ForwardOk, got {other:?}"),
        }
    }

    #[test]
    fn roundtrip_forward_err() {
        let event = DebugEvent {
            sequence: 7,
            timestamp_us: 2000,
            signature: Some([0xFF; 64]),
            kind: DebugEventKind::ForwardErr {
                reason: "bridge unreachable".to_string(),
            },
        };
        let bytes = event.to_bytes();
        let decoded = DebugEvent::from_bytes(&bytes).expect("decode");
        match &decoded.kind {
            DebugEventKind::ForwardErr { reason } => assert_eq!(reason, "bridge unreachable"),
            other => panic!("expected ForwardErr, got {other:?}"),
        }
    }

    #[test]
    fn roundtrip_events_dropped() {
        let event = DebugEvent {
            sequence: 100,
            timestamp_us: 5000,
            signature: None,
            kind: DebugEventKind::EventsDropped { count: 42 },
        };
        let bytes = event.to_bytes();
        let decoded = DebugEvent::from_bytes(&bytes).expect("decode");
        match &decoded.kind {
            DebugEventKind::EventsDropped { count } => assert_eq!(*count, 42),
            other => panic!("expected EventsDropped, got {other:?}"),
        }
    }

    #[test]
    fn roundtrip_subscribed() {
        let event = DebugEvent {
            sequence: 0,
            timestamp_us: 100,
            signature: None,
            kind: DebugEventKind::Subscribed,
        };
        let bytes = event.to_bytes();
        let decoded = DebugEvent::from_bytes(&bytes).expect("decode");
        assert!(matches!(decoded.kind, DebugEventKind::Subscribed));
    }

    #[test]
    fn roundtrip_unsubscribed() {
        let event = DebugEvent {
            sequence: 10,
            timestamp_us: 200,
            signature: None,
            kind: DebugEventKind::Unsubscribed,
        };
        let bytes = event.to_bytes();
        let decoded = DebugEvent::from_bytes(&bytes).expect("decode");
        assert!(matches!(decoded.kind, DebugEventKind::Unsubscribed));
    }

    #[test]
    fn from_bytes_rejects_too_short() {
        assert!(DebugEvent::from_bytes(&[0u8; 10]).is_err());
    }

    #[test]
    fn from_bytes_rejects_unknown_kind() {
        let event = DebugEvent {
            sequence: 0,
            timestamp_us: 0,
            signature: None,
            kind: DebugEventKind::ValidationOk,
        };
        let mut data = event.to_bytes();
        data[16] = 0xFF;
        assert!(DebugEvent::from_bytes(&data).is_err());
    }
}
