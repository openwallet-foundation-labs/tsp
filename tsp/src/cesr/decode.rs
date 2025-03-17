use super::{bits, extract_triplet, header_match, mask, selector::*};

/// Decode fixed size data with a known identifier
fn decode_fixed_data_index<const N: usize>(
    identifier: u32,
    stream: &[u8],
) -> Option<std::ops::Range<usize>> {
    let total_size = (N + 1).next_multiple_of(3);
    let hdr_bytes = total_size - N;

    let word = match hdr_bytes {
        1 => bits(identifier, 6) << 18,
        2 => (D0 << 18) | (bits(identifier, 6) << 12),
        3 => (D1 << 18) | bits(identifier, 18),
        _ => unreachable!("unsigned integer arithmetic is broken"),
    };

    if header_match(
        stream.get(0..hdr_bytes)?,
        &u32::to_be_bytes(word)[1..=hdr_bytes],
    ) {
        // access check: make sure that if this function returns Some(...), that the range is valid
        stream.get(hdr_bytes..total_size)?;

        Some(hdr_bytes..total_size)
    } else {
        None
    }
}

pub fn decode_fixed_data<'a, const N: usize>(
    identifier: u32,
    stream: &mut &'a [u8],
) -> Option<&'a [u8; N]> {
    let range = decode_fixed_data_index::<N>(identifier, stream)?;
    let pos = range.end;
    let slice = &stream[range];
    *stream = &stream[pos..];

    Some(slice.try_into().unwrap())
}

pub fn decode_fixed_data_mut<const N: usize>(
    identifier: u32,
    stream: &mut [u8],
) -> Option<(&mut [u8; N], &mut [u8])> {
    let range = decode_fixed_data_index::<N>(identifier, stream)?;
    let (prefix, stream) = stream.split_at_mut(range.end);
    let slice = &mut prefix[range.start..];

    Some((slice.try_into().unwrap(), stream))
}

/// Decode variable size data with a known identifier
/// Be aware that this function DOES NOT forward the stream (unlike the other functions)
pub fn decode_variable_data_index(
    identifier: u32,
    stream: &[u8],
    pos: &mut usize,
) -> Option<std::ops::Range<usize>> {
    let stream = &stream[*pos..];
    let input = extract_triplet(stream.get(0..=2)?.try_into().unwrap());
    let selector = input >> 18;

    let size;
    let found_id;

    match selector {
        D4 | D5 | D6 => {
            found_id = (input >> 12) & mask(6);
            size = input & mask(12);
        }
        D7 | D8 | D9 => {
            found_id = input & mask(18);
            size = extract_triplet(stream.get(3..6)?.try_into().unwrap());
        }
        _ => return None,
    };

    if found_id == identifier {
        let offset = (selector - D4) as usize;
        let data_begin = offset + 3;
        let data_end = (offset + 1).next_multiple_of(3) + 3 * size as usize;

        // access check: make sure that if this function returns Some(...), that the range is valid
        stream.get(data_begin..data_end)?;

        let origin_range = (data_begin + *pos)..(data_end + *pos);
        *pos = origin_range.end;

        Some(origin_range)
    } else {
        None
    }
}

pub fn decode_variable_data<'a>(identifier: u32, stream: &mut &'a [u8]) -> Option<&'a [u8]> {
    let range = decode_variable_data_index(identifier, stream, &mut 0)?;
    let slice = &stream[range.start..range.end];
    *stream = &stream[range.end..];

    Some(slice)
}

pub fn decode_variable_data_mut(
    identifier: u32,
    stream: &mut [u8],
) -> Option<(&mut [u8], &mut [u8])> {
    let range = decode_variable_data_index(identifier, stream, &mut 0)?;
    let (prefix, stream) = stream.split_at_mut(range.end);
    let slice = &mut prefix[range.start..];

    Some((slice, stream))
}

/// Decode indexed data with a known identifier
#[allow(dead_code)]
pub fn decode_indexed_data<'a, const N: usize>(
    identifier: u32,
    stream: &mut &'a [u8],
) -> Option<(u16, &'a [u8; N])> {
    let total_size = (N + 1).next_multiple_of(3);
    let hdr_bytes = total_size - N;

    let input = extract_triplet(stream.get(0..=2)?.try_into().unwrap());
    let word;
    let index;

    match hdr_bytes {
        1 => panic!("an indexed type can only have 0 or 2 lead bytes"),
        2 => {
            index = (input >> 12) & mask(6);
            word = (bits(identifier, 6) << 18) | (bits(index, 6) << 12);
        }
        3 => {
            index = input & mask(12);
            word = (D0 << 18) | (bits(identifier, 6) << 12) | bits(index, 12);
        }
        _ => unreachable!("unsigned integer arithmetic is broken"),
    };

    if header_match(
        stream.get(0..hdr_bytes)?,
        &u32::to_be_bytes(word)[1..=hdr_bytes],
    ) {
        let slice = stream.get(hdr_bytes..total_size)?;
        *stream = &stream[total_size..];

        Some((index as u16, slice.try_into().unwrap()))
    } else {
        None
    }
}

/// Decode a frame with known identifier and size
pub fn decode_count(identifier: u16, stream: &mut &[u8]) -> Option<u16> {
    let word = extract_triplet(stream.get(0..=2)?.try_into().unwrap());
    let index = word & mask(12);

    let expected = (DASH << 18) | (bits(identifier, 6) << 12) | bits(index, 12);
    if word == expected {
        *stream = &stream[3..];

        Some(index as u16)
    } else {
        None
    }
}

/// Decode a frame with known identifier and size
pub fn decode_count_mut(identifier: u16, stream: &mut [u8]) -> Option<(u16, &mut [u8])> {
    let mut const_stream: &[u8] = stream;
    let count = decode_count(identifier, &mut const_stream)?;
    let offset = stream.len() - const_stream.len();

    Some((count, &mut stream[offset..]))
}

/// Decode a genus with known identifier and version
#[allow(dead_code)]
pub fn decode_genus(
    genus: [u8; 3],
    (major, minor, patch): (u8, u8, u8),
    stream: &mut &[u8],
) -> Option<()> {
    let version = (bits(major, 6) << 12) | (bits(minor, 6) << 6) | bits(patch, 6);
    let word1 = (DASH << 18) | (DASH << 12) | (bits(genus[0], 6) << 6) | bits(genus[1], 6);
    let word2 = (bits(genus[2], 6) << 18) | version;

    (extract_triplet(stream.get(0..3)?.try_into().unwrap()) == word1).then_some(())?;
    (extract_triplet(stream.get(3..6)?.try_into().unwrap()) == word2).then_some(())?;
    *stream = &stream[6..];

    Some(())
}

/// Decode variable size data (intended size >=50mb) that doesn't fit in known CESR encodings.
///
/// Since CESR has no native type for this, we use the convention that "big data"
/// Is announced by encoding the size as a 64bit integer (prefix "N"), which is then
/// followed by the raw data padded in the usual sense for CESR (pre-padding)
/// This is a temporary encoding, depending on how CESR will address this in the future.
pub fn decode_large_blob_index(stream: &[u8]) -> Option<std::ops::Range<usize>> {
    let selector = b'N' - b'A';
    let size = u64::from_be_bytes(*decode_fixed_data(
        selector as u32,
        &mut <_>::clone(&stream),
    )?) as usize;
    let padded_size = size.next_multiple_of(3);
    let lead_bytes = padded_size - size;

    let range = 9 + lead_bytes..9 + padded_size;
    // make sure the range is valid before returning it
    stream.get(range.clone())?;

    Some(range)
}

#[cfg(test)]
pub fn decode_large_blob<'a>(stream: &mut &'a [u8]) -> Option<&'a [u8]> {
    let range = decode_large_blob_index(stream)?;
    let slice = &stream[range.start..range.end];
    *stream = &stream[range.end..];

    Some(slice)
}
