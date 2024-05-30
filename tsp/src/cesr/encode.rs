use super::{bits, selector::*};

/// Encode fixed size data with a known identifier
pub fn encode_fixed_data(
    identifier: u32,
    payload: &[u8],
    stream: &mut impl for<'a> Extend<&'a u8>,
) {
    let total_size = (payload.len() + 1).next_multiple_of(3);
    let hdr_bytes = total_size - payload.len();

    let word = match hdr_bytes {
        1 => bits(identifier, 6) << 18,
        2 => D0 << 18 | bits(identifier, 6) << 12,
        3 => D1 << 18 | bits(identifier, 18),
        _ => unreachable!("integer arithmetic"),
    };

    stream.extend(&u32::to_be_bytes(word)[1..=hdr_bytes]);
    stream.extend(payload);
}

/// Encode indexed fixed size data with a known identifier
#[allow(dead_code)]
pub fn encode_indexed_data(
    identifier: u32,
    index: u16,
    payload: &[u8],
    stream: &mut impl for<'a> Extend<&'a u8>,
) {
    let total_size = (payload.len() + 1).next_multiple_of(3);
    let hdr_bytes = total_size - payload.len();

    let word = match hdr_bytes {
        1 => panic!("an indexed type with 1 lead byte is not possible"),
        2 => bits(identifier, 6) << 18 | bits(index, 6) << 12,
        3 => D0 << 18 | bits(identifier, 6) << 12 | bits(index, 12),
        _ => unreachable!("integer arithmetic"),
    };

    stream.extend(&u32::to_be_bytes(word)[1..=hdr_bytes]);
    stream.extend(payload);
}

/// Encode variable size data with a known identifier
pub fn encode_variable_data(
    identifier: u32,
    payload: &[u8],
    stream: &mut impl for<'a> Extend<&'a u8>,
) {
    let padded_size = payload.len().next_multiple_of(3);
    let lead_bytes = padded_size - payload.len();

    let selector = D4 + lead_bytes as u32;
    let size = (padded_size / 3) as u32;

    if size < 64 * 64 && identifier < 64 {
        let word = bits(selector, 6) << 18 | bits(identifier, 6) << 12 | bits(size, 12);
        stream.extend(&u32::to_be_bytes(word)[1..]);
    } else {
        let word = bits(selector + 3, 6) << 18 | bits(identifier, 18);
        stream.extend(&u32::to_be_bytes(word)[1..]);
        stream.extend(&u32::to_be_bytes(bits(size, 24))[1..]);
    }

    stream.extend(&<[u8; 2]>::default()[0..lead_bytes]);
    stream.extend(payload);
}

/// Encode a frame with known identifier and count code
pub fn encode_count(identifier: u16, count: u16, stream: &mut impl for<'a> Extend<&'a u8>) {
    let word = DASH << 18 | bits(identifier, 6) << 12 | bits(count, 12);

    stream.extend(&u32::to_be_bytes(word)[1..]);
}

/// Encode a genus with known identifier and version
#[allow(dead_code)]
pub fn encode_genus(
    genus: [u8; 3],
    (major, minor, patch): (u8, u8, u8),
    stream: &mut impl for<'a> Extend<&'a u8>,
) {
    let version = bits(major, 6) << 12 | bits(minor, 6) << 6 | bits(patch, 6);
    let word1 = DASH << 18 | DASH << 12 | bits(genus[0], 6) << 6 | bits(genus[1], 6);
    let word2 = bits(genus[2], 6) << 18 | version;

    stream.extend(&u32::to_be_bytes(word1)[1..]);
    stream.extend(&u32::to_be_bytes(word2)[1..]);
}
