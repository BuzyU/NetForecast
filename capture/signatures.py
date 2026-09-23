"""
Deterministic packet-signature detectors that don't need to be learned from
training examples — complementary to the ML world model, not a replacement
for it. Currently: CVE-2014-0160 (Heartbleed).

Why this exists: real_flows.csv has only ~2 real Exfiltration (Heartbleed)
rows out of 320,000 (CIC-IDS2017's entire public release has ~11 in total),
which is not enough for any model to learn a reliable decision boundary from.
Heartbleed has a well-known, deterministic wire-format signature instead —
no learning required, so we detect it with a rule rather than pretending an
LSTM trained on 2 examples can do it.
"""

# TLS record content types
_TLS_CONTENT_TYPE_HEARTBEAT = 24

# Tolerance for legitimate padding/alignment in the heartbeat payload —
# real heartbeat responses are the request payload length plus a small
# amount of padding (RFC 6520 requires >=16 bytes of random padding).
_PADDING_TOLERANCE = 16


def detect_heartbleed(payload: bytes) -> bool:
    """
    Scan raw TCP payload bytes for the classic Heartbleed exploit signature:
    a TLS Heartbeat record (ContentType=24) whose internal HeartbeatMessage
    payload_length field claims more bytes than the TLS record actually
    contains. This is the exact over-read primitive CVE-2014-0160 exploits —
    a legitimate heartbeat implementation never sends a payload_length larger
    than what it actually included.

    Stateless and per-packet: does not require TCP stream reassembly or a
    full TLS session context, matching how real IDS signatures (Suricata/
    Snort/the original Heartbleed detection scripts) operate. This means a
    Heartbleed record split across TCP segments may be missed, which is an
    acceptable false-negative trade-off for a deterministic, low-overhead
    per-packet check — it never produces a false positive on legitimate
    traffic, since legitimate heartbeats cannot fail this check by
    definition of the TLS spec.

    Returns True if a malformed heartbeat is found anywhere in the payload.
    """
    if not payload:
        return False

    n = len(payload)
    i = 0
    while i + 5 <= n:
        content_type = payload[i]
        record_length = (payload[i + 3] << 8) | payload[i + 4]

        if record_length == 0 or i + 5 + record_length > n + _PADDING_TOLERANCE:
            # Malformed/truncated record framing (or payload doesn't fully
            # contain this record, e.g. TCP segmentation) — stop scanning
            # this payload rather than risk misreading subsequent bytes.
            break

        if content_type == _TLS_CONTENT_TYPE_HEARTBEAT:
            fragment = payload[i + 5:i + 5 + record_length]
            if len(fragment) >= 3:
                claimed_payload_len = (fragment[1] << 8) | fragment[2]
                # Bytes actually present after the 1-byte type + 2-byte length header
                actually_present = len(fragment) - 3
                if claimed_payload_len > actually_present + _PADDING_TOLERANCE:
                    return True

        i += 5 + record_length

    return False
