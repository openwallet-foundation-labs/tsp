//! Walking a TSP message into the CESR primitives it is built from.
//!
//! This is a presentation aid, not a parser: it names every code and every run
//! of data in a message so a reader can check the bytes against section 9 of
//! the specification. Decoding a message for use goes through [`super::packet`],
//! which rejects what this walker will happily describe.
//!
//! The walk happens in the text domain. That domain is the base64url of the
//! binary domain and is quadlet aligned, so every primitive starts on a
//! four-character boundary and the two domains map onto each other exactly.
//!
//! Every primitive is emitted as two segments — its code, and the data the code
//! introduces — so nothing is left as an undifferentiated string. Anything the
//! walker does not recognise becomes a single [`SegmentKind::Unparsed`] segment
//! rather than a guess, so a gap shows up instead of being silently mis-drawn.

use base64ct::{Base64UrlUnpadded, Encoding};

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// What a segment is: a code, the data a code introduces, or a run the walker
/// could not identify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentKind {
    Code,
    Data,
    Unparsed,
}

/// One code or one run of data from a TSP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub kind: SegmentKind,
    /// The field name section 9 gives this, or the kind of code it is
    pub label: String,
    /// The segment's own base64url text, a slice of the whole message's text
    pub text: String,
    /// What the code says beyond naming the field
    pub note: String,
    /// The data rendered for a reader, where it has a readable form
    pub value: Option<String>,
}

/// The payload type codes of spec section 9.3, and what each introduces.
fn payload_type(code: &str) -> Option<(&'static str, &'static str)> {
    Some(match code {
        "XSCS" => ("TSP_GEN", "application payload, carried opaquely"),
        "XCTL" => ("TSP_CTL", "upper-layer control payload, carried opaquely"),
        "XPAD" => ("TSP_PAD", "padding message, discarded by the receiver"),
        "XHOP" => (
            "TSP_HOP",
            "nested or routed payload: a hop list, then an inner message",
        ),
        "XRFI" => ("TSP_RFI", "relationship forming invite"),
        "XRFA" => ("TSP_RFA", "relationship forming accept"),
        "XRFD" => ("TSP_RFD", "relationship forming decline or cancel"),
        _ => return None,
    })
}

/// Counted groups: the count gives the quadlets of content that follow, and
/// that content is walked in turn rather than being data of the group's own.
fn group(code: &str) -> Option<(&'static str, &'static str)> {
    Some(match code {
        "-E" => ("frame", "counts the signable content that follows"),
        "-Z" => ("payload", "counts the payload that follows"),
        "-J" => ("hop list", "a list of VIDs"),
        "-A" => ("stream", "a generic CESR stream, carried opaquely"),
        "-C" => ("attachments", "attachment group"),
        "-K" => ("signatures", "indexed signature group"),
        _ => return None,
    })
}

/// Variable-length primitives, by the identifier character of their code.
///
/// `B` is the generic bytes primitive: TSP uses the same code for a VID, for
/// the padding field and for application data — `TSP_VID` and `TSP_PLAINTEXT`
/// are both `B`. The code therefore says nothing about what the data is; only
/// its position does, which is what the slot list and region stack below are
/// for. The ciphertext codes are the exception, and name the suite that
/// produced them: there is no separate field saying which was used (spec 9.2.8).
fn variable(identifier: char) -> Option<(&'static str, Option<&'static str>)> {
    Some(match identifier {
        'B' | 'A' => ("bytes", None),
        'C' => (
            "ciphertext",
            Some("4C/5C/6C: libsodium anonymous sealed box"),
        ),
        'F' => (
            "ciphertext",
            Some("4F/5F/6F: HPKE-Base, including its post-quantum KEM"),
        ),
        _ => return None,
    })
}

/// What the bytes primitives of a payload are, in order, once its type is known.
fn payload_slots(code: &str) -> Option<[&'static str; 2]> {
    payload_type(code).map(|_| ["VID_sndr", "Padding_Field"])
}

fn b64_index(c: u8) -> Option<u32> {
    B64.iter().position(|&x| x == c).map(|i| i as u32)
}

/// Read a base64url run as a big-endian number.
fn count(chars: &str) -> Option<u32> {
    chars
        .bytes()
        .try_fold(0u32, |acc, c| Some(acc * 64 + b64_index(c)?))
}

/// Decode a base64url run, tolerating that it is unpadded.
fn decode(text: &str) -> Option<Vec<u8>> {
    let mut padded = text.to_owned();
    while !padded.len().is_multiple_of(4) {
        padded.push('A');
    }
    Base64UrlUnpadded::decode_vec(&padded).ok()
}

/// The data as text if every character of it is printable, else as hex.
fn readable(data: &[u8]) -> (String, &'static str) {
    match std::str::from_utf8(data) {
        Ok(text) if !text.is_empty() && text.chars().all(|c| !c.is_control()) => {
            (text.to_owned(), "")
        }
        _ => (hex(data), ", shown as hex"),
    }
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn seg(
    kind: SegmentKind,
    label: impl Into<String>,
    text: &str,
    note: impl Into<String>,
    value: Option<String>,
) -> Segment {
    Segment {
        kind,
        label: label.into(),
        text: text.to_owned(),
        note: note.into(),
        value,
    }
}

/// Walk a TSP message into its CESR primitives.
///
/// The `text` fields of the result concatenate back to the base64url of
/// `message`, so a caller can colour or annotate the message in place.
pub fn segments(message: &[u8]) -> Vec<Segment> {
    walk(&Base64UrlUnpadded::encode_string(message))
}

fn walk(text: &str) -> Vec<Segment> {
    let mut out = Vec::new();
    let len = text.len();
    let mut i = 0;
    // field names still expected for this payload's bytes primitives
    let mut slots: Vec<&'static str> = Vec::new();
    // (end index, what every bytes primitive inside it is)
    let mut regions: Vec<(usize, &'static str)> = Vec::new();

    let at = |i: usize, n: usize| -> &str { &text[i..(i + n).min(len)] };

    while i < len {
        while regions.last().is_some_and(|&(end, _)| i >= end) {
            regions.pop();
        }
        let (h1, h2, h4) = (at(i, 1), at(i, 2), at(i, 4));

        // a payload type code, which fixes what the fields after it are
        if let Some((name, note)) = payload_type(h4) {
            out.push(seg(
                SegmentKind::Code,
                "payload type",
                h4,
                note,
                Some(name.into()),
            ));
            slots = payload_slots(h4).map(Vec::from).unwrap_or_default();
            i += 4;
            continue;
        }

        // the TSP genus, then a count code carrying MAJOR, MINOR and PATCH
        if h4 == "YTSP" {
            let version = at(i + 4, 4);
            let value = match (
                version.as_bytes().get(1).copied().and_then(b64_index),
                count(at(i + 6, 2)),
            ) {
                (Some(major), Some(mp)) => Some(format!("{major}.{}.{}", mp >> 6, mp & 0x3F)),
                _ => None,
            };
            out.push(seg(
                SegmentKind::Code,
                "TSP_Version code",
                h4,
                "the TSP genus",
                None,
            ));
            out.push(seg(
                SegmentKind::Data,
                "TSP_Version",
                version,
                "MAJOR in the count code's identifier, then MINOR and PATCH",
                value,
            ));
            i += 8;
            continue;
        }

        // a counted group, in either the short `-X##` or long `--X#####` form
        if h1 == "-" {
            let long = h2 == "--";
            let (code_len, id, quadlets) = if long {
                let hi = b64_index(at(i + 3, 1).as_bytes()[0]);
                let lo = count(at(i + 4, 4));
                let n = match (hi, lo) {
                    (Some(hi), Some(lo)) => Some(hi << 24 | lo),
                    _ => None,
                };
                (8, at(i + 2, 1), n)
            } else {
                (4, at(i + 1, 1), count(at(i + 2, 2)))
            };
            if let (Some((label, note)), Some(quadlets)) = (group(&format!("-{id}")), quadlets) {
                let code = at(i, code_len);
                out.push(seg(
                    SegmentKind::Code,
                    format!("{label} code"),
                    code,
                    note,
                    Some(if quadlets == 0 {
                        "empty".into()
                    } else {
                        format!("{quadlets} quadlets = {} bytes", quadlets * 3)
                    }),
                ));
                // a frame introduces an envelope, whose first two bytes
                // primitives are the sending and receiving VIDs
                if id == "E" {
                    slots = vec!["VID_sndr", "VID_rcvr"];
                }
                // inside a hop list every bytes primitive is a VID; inside a
                // generic stream it is the upper layer's data
                let end = i + code_len + quadlets as usize * 4;
                if quadlets > 0 && end <= len {
                    match id {
                        "J" => regions.push((end, "VID_hop")),
                        "A" => regions.push((end, "Upper_Layer_Data")),
                        _ => {}
                    }
                }
                i += code_len;
                continue;
            }
        }

        // a variable-length primitive, short form `[456]X##` or long `[789]XXX####`
        let lead = "456".find(h1).or_else(|| "789".find(h1));
        if let Some(lead) = lead {
            let long = h1.as_bytes()[0] >= b'7';
            let (code_len, id, quadlets) = if long {
                (8, at(i + 3, 1), count(at(i + 4, 4)))
            } else {
                (4, at(i + 1, 1), count(at(i + 2, 2)))
            };
            let id = id.chars().next().unwrap_or(' ');
            if let (Some((kind, scheme)), Some(quadlets)) = (variable(id), quadlets) {
                let label = if kind == "bytes" {
                    match (regions.last(), slots.is_empty()) {
                        (Some(&(_, name)), _) => name.to_owned(),
                        (None, false) => slots.remove(0).to_owned(),
                        (None, true) => "bytes".to_owned(),
                    }
                } else {
                    kind.to_owned()
                };
                let size = quadlets as usize * 3 - lead;
                let mut note = format!("lead pad {lead}, count {quadlets} quadlets");
                if let Some(scheme) = scheme {
                    note = format!("{scheme}; {note}");
                }
                let code = at(i, code_len);
                out.push(seg(
                    SegmentKind::Code,
                    format!("{label} code"),
                    code,
                    note,
                    Some(if quadlets == 0 {
                        "empty, the NULL value".into()
                    } else {
                        format!("{size} bytes follow")
                    }),
                ));
                let end = i + code_len + quadlets as usize * 4;
                if quadlets > 0 && end <= len {
                    let body = &text[i + code_len..end];
                    let (value, how) = decode(body)
                        .map(|d| readable(&d[lead..]))
                        .unwrap_or_else(|| (String::new(), ""));
                    out.push(seg(
                        SegmentKind::Data,
                        label,
                        body,
                        format!("{size} bytes{how}"),
                        Some(value),
                    ));
                }
                i += code_len + quadlets as usize * 4;
                continue;
            }
        }

        // fixed-length primitives: a code that occupies the leading bits of the
        // quadlet-aligned block, so code and data must be decoded together and
        // the value taken off the end
        let fixed = match h2 {
            "0A" => Some((2, 22, "Nonce", "128 bits", 16)),
            _ => match h1 {
                "I" => Some((1, 43, "Digest", "SHA2-256, 32 bytes", 32)),
                "F" => Some((1, 43, "Digest", "Blake2b-256, 32 bytes", 32)),
                _ => None,
            },
        };
        if let Some((code_len, data_len, label, note, bytes)) = fixed
            && i + code_len + data_len <= len
        {
            let code = at(i, code_len);
            let body = at(i + code_len, data_len);
            let value =
                decode(&text[i..i + code_len + data_len]).map(|d| hex(&d[d.len() - bytes..]));
            out.push(seg(
                SegmentKind::Code,
                format!("{label} code"),
                code,
                note,
                None,
            ));
            out.push(seg(
                SegmentKind::Data,
                label,
                body,
                format!("{data_len} characters"),
                value,
            ));
            i += code_len + data_len;
            continue;
        }

        // an indexed Ed25519 signature: `B`, then the signing key's index
        if h1 == "B" && i + 88 <= len {
            let code = at(i, 2);
            let body = at(i + 2, 86);
            let index = b64_index(code.as_bytes()[1]).unwrap_or_default();
            out.push(seg(
                SegmentKind::Code,
                "signature code",
                code,
                format!("Ed25519, signing key index {index}"),
                None,
            ));
            out.push(seg(
                SegmentKind::Data,
                "signature",
                body,
                "64 bytes",
                decode(&text[i..i + 88]).map(|d| hex(&d[d.len() - 64..])),
            ));
            i += 88;
            continue;
        }

        // an ML-DSA-65 signature, which runs to the end of the message
        if h4 == "1AAQ" {
            let body = &text[i + 4..];
            out.push(seg(
                SegmentKind::Code,
                "signature code",
                h4,
                "ML-DSA-65",
                None,
            ));
            out.push(seg(
                SegmentKind::Data,
                "signature",
                body,
                "3309 bytes",
                decode(body).map(|d| hex(&d[..3309.min(d.len())])),
            ));
            break;
        }

        out.push(seg(
            SegmentKind::Unparsed,
            "unparsed",
            &text[i..],
            "the walker does not know this code",
            None,
        ));
        break;
    }

    out
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::definitions::VerifiedVid;

    /// Every segment's text is a slice of the message, in order, with nothing
    /// dropped and nothing invented.
    fn assert_covers(message: &[u8], segments: &[Segment]) {
        let text = Base64UrlUnpadded::encode_string(message);
        let joined: String = segments.iter().map(|s| s.text.as_str()).collect();
        assert_eq!(joined, text, "segments must cover the whole message");
    }

    #[test]
    fn walks_a_signed_only_message() {
        // built by the SDK rather than pasted, so the two cannot drift
        let (sender, receiver) = (
            crate::OwnedVid::new_did_peer("tsp://".parse().unwrap()),
            crate::OwnedVid::new_did_peer("tsp://".parse().unwrap()),
        );
        let message = crate::crypto::sign(&sender, Some(&receiver), b"hello world").unwrap();

        let segments = segments(&message);
        assert_covers(&message, &segments);
        assert!(
            segments.iter().all(|s| s.kind != SegmentKind::Unparsed),
            "every code in a message this SDK produces must be known: {segments:#?}"
        );

        let labelled = |name: &str| segments.iter().find(|s| s.label == name).cloned();
        assert_eq!(
            labelled("TSP_Version").and_then(|s| s.value).as_deref(),
            Some("0.0.1")
        );
        assert_eq!(
            labelled("VID_sndr").and_then(|s| s.value).as_deref(),
            Some(sender.identifier())
        );
        assert_eq!(
            labelled("VID_rcvr").and_then(|s| s.value).as_deref(),
            Some(receiver.identifier())
        );
        assert!(labelled("signature").is_some());
    }

    #[test]
    fn an_empty_message_yields_nothing_rather_than_a_guess() {
        assert!(segments(&[]).is_empty());
    }

    #[test]
    fn garbage_is_reported_as_unparsed_rather_than_mis_drawn() {
        let segments = segments(b"not a tsp message at all");
        assert_eq!(segments.last().map(|s| s.kind), Some(SegmentKind::Unparsed));
    }
}
