use crate::error::{ApiErr, ApiResult};
use serde_json::Value;

pub(super) fn encode(canonical: &[u8]) -> ApiResult<Vec<u8>> {
    let value: Value = serde_json::from_slice(canonical)
        .map_err(|error| ApiErr::from(anyhow::anyhow!("reparse canonical graph JSON: {error}")))?;
    let mut output = Vec::with_capacity(canonical.len());
    messagepack_value(&value, &mut output)?;
    Ok(output)
}

fn messagepack_value(value: &Value, output: &mut Vec<u8>) -> ApiResult<()> {
    match value {
        Value::Null => output.push(0xc0),
        Value::Bool(false) => output.push(0xc2),
        Value::Bool(true) => output.push(0xc3),
        Value::Number(number) => {
            if let Some(value) = number.as_u64() {
                messagepack_u64(value, output);
            } else if let Some(value) = number.as_i64() {
                messagepack_i64(value, output);
            } else {
                return Err(ApiErr::from(anyhow::anyhow!(
                    "dependency graph contains a non-integer number"
                )));
            }
        }
        Value::String(value) => messagepack_string(value, output)?,
        Value::Array(items) => {
            messagepack_array_len(items.len(), output)?;
            for item in items {
                messagepack_value(item, output)?;
            }
        }
        Value::Object(map) => {
            messagepack_map_len(map.len(), output)?;
            for (key, value) in map {
                messagepack_string(key, output)?;
                messagepack_value(value, output)?;
            }
        }
    }
    Ok(())
}

fn messagepack_u64(value: u64, output: &mut Vec<u8>) {
    match value {
        0..=0x7f => output.push(value as u8),
        0x80..=0xff => output.extend_from_slice(&[0xcc, value as u8]),
        0x100..=0xffff => {
            output.push(0xcd);
            output.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push(0xce);
            output.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            output.push(0xcf);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn messagepack_i64(value: i64, output: &mut Vec<u8>) {
    if value >= 0 {
        messagepack_u64(value as u64, output);
    } else if value >= -32 {
        output.push(value as i8 as u8);
    } else if value >= i8::MIN as i64 {
        output.extend_from_slice(&[0xd0, value as i8 as u8]);
    } else if value >= i16::MIN as i64 {
        output.push(0xd1);
        output.extend_from_slice(&(value as i16).to_be_bytes());
    } else if value >= i32::MIN as i64 {
        output.push(0xd2);
        output.extend_from_slice(&(value as i32).to_be_bytes());
    } else {
        output.push(0xd3);
        output.extend_from_slice(&value.to_be_bytes());
    }
}

fn messagepack_string(value: &str, output: &mut Vec<u8>) -> ApiResult<()> {
    let bytes = value.as_bytes();
    match bytes.len() {
        0..=31 => output.push(0xa0 | bytes.len() as u8),
        32..=0xff => output.extend_from_slice(&[0xd9, bytes.len() as u8]),
        0x100..=0xffff => {
            output.push(0xda);
            output.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        }
        _ => {
            let length = u32::try_from(bytes.len()).map_err(|_| {
                ApiErr::from(anyhow::anyhow!("MessagePack string exceeds u32 length"))
            })?;
            output.push(0xdb);
            output.extend_from_slice(&length.to_be_bytes());
        }
    }
    output.extend_from_slice(bytes);
    Ok(())
}

fn messagepack_array_len(length: usize, output: &mut Vec<u8>) -> ApiResult<()> {
    match length {
        0..=15 => output.push(0x90 | length as u8),
        16..=0xffff => {
            output.push(0xdc);
            output.extend_from_slice(&(length as u16).to_be_bytes());
        }
        _ => {
            let length = u32::try_from(length).map_err(|_| {
                ApiErr::from(anyhow::anyhow!("MessagePack array exceeds u32 length"))
            })?;
            output.push(0xdd);
            output.extend_from_slice(&length.to_be_bytes());
        }
    }
    Ok(())
}

fn messagepack_map_len(length: usize, output: &mut Vec<u8>) -> ApiResult<()> {
    match length {
        0..=15 => output.push(0x80 | length as u8),
        16..=0xffff => {
            output.push(0xde);
            output.extend_from_slice(&(length as u16).to_be_bytes());
        }
        _ => {
            let length = u32::try_from(length)
                .map_err(|_| ApiErr::from(anyhow::anyhow!("MessagePack map exceeds u32 length")))?;
            output.push(0xdf);
            output.extend_from_slice(&length.to_be_bytes());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::sample_document;
    use super::*;

    #[test]
    fn is_a_named_map_with_all_document_keys() {
        let canonical = sample_document().canonical_document_bytes().unwrap();
        let bytes = encode(&canonical).unwrap();
        let first = *bytes.first().unwrap();
        assert!(matches!(first, 0x80..=0x8f | 0xde | 0xdf));
        for key in [
            b"schema".as_slice(),
            b"view".as_slice(),
            b"graph_digest".as_slice(),
        ] {
            assert!(
                bytes.windows(key.len()).any(|window| window == key),
                "missing MessagePack key {}",
                String::from_utf8_lossy(key)
            );
        }
    }

    #[test]
    fn every_golden_graph_round_trips_through_messagepack() {
        for (name, document) in zed_interfaces::golden_fixture_documents() {
            let canonical = document.canonical_document_bytes().unwrap();
            let expected: Value = serde_json::from_slice(&canonical).unwrap();
            let encoded = encode(&canonical).unwrap();
            let mut cursor = 0;
            let decoded = decode_value(&encoded, &mut cursor);
            assert_eq!(cursor, encoded.len(), "trailing bytes for {name}");
            assert_eq!(decoded, expected, "MessagePack mismatch for {name}");
        }
    }

    #[test]
    fn messagepack_length_boundaries_round_trip() {
        for length in [0, 31, 32, 255, 256, 65_535, 65_536] {
            let expected = Value::String("x".repeat(length));
            let canonical = serde_json::to_vec(&expected).unwrap();
            let encoded = encode(&canonical).unwrap();
            let mut cursor = 0;
            assert_eq!(decode_value(&encoded, &mut cursor), expected);
            assert_eq!(cursor, encoded.len());
        }
    }

    fn decode_value(bytes: &[u8], cursor: &mut usize) -> Value {
        let marker = take(bytes, cursor, 1)[0];
        match marker {
            0x00..=0x7f => Value::from(marker),
            0x80..=0x8f => decode_map(bytes, cursor, usize::from(marker & 0x0f)),
            0x90..=0x9f => decode_array(bytes, cursor, usize::from(marker & 0x0f)),
            0xa0..=0xbf => decode_string(bytes, cursor, usize::from(marker & 0x1f)),
            0xc0 => Value::Null,
            0xc2 => Value::Bool(false),
            0xc3 => Value::Bool(true),
            0xcc => Value::from(take(bytes, cursor, 1)[0]),
            0xcd => Value::from(u16::from_be_bytes(read_array(bytes, cursor))),
            0xce => Value::from(u32::from_be_bytes(read_array(bytes, cursor))),
            0xcf => Value::from(u64::from_be_bytes(read_array(bytes, cursor))),
            0xd0 => Value::from(i8::from_be_bytes(read_array(bytes, cursor))),
            0xd1 => Value::from(i16::from_be_bytes(read_array(bytes, cursor))),
            0xd2 => Value::from(i32::from_be_bytes(read_array(bytes, cursor))),
            0xd3 => Value::from(i64::from_be_bytes(read_array(bytes, cursor))),
            0xd9 => {
                let length = usize::from(take(bytes, cursor, 1)[0]);
                decode_string(bytes, cursor, length)
            }
            0xda => {
                let length = usize::from(u16::from_be_bytes(read_array(bytes, cursor)));
                decode_string(bytes, cursor, length)
            }
            0xdb => {
                let length =
                    usize::try_from(u32::from_be_bytes(read_array(bytes, cursor))).unwrap();
                decode_string(bytes, cursor, length)
            }
            0xdc => {
                let length = usize::from(u16::from_be_bytes(read_array(bytes, cursor)));
                decode_array(bytes, cursor, length)
            }
            0xdd => {
                let length =
                    usize::try_from(u32::from_be_bytes(read_array(bytes, cursor))).unwrap();
                decode_array(bytes, cursor, length)
            }
            0xde => {
                let length = usize::from(u16::from_be_bytes(read_array(bytes, cursor)));
                decode_map(bytes, cursor, length)
            }
            0xdf => {
                let length =
                    usize::try_from(u32::from_be_bytes(read_array(bytes, cursor))).unwrap();
                decode_map(bytes, cursor, length)
            }
            0xe0..=0xff => Value::from(marker as i8),
            _ => panic!("unsupported MessagePack marker 0x{marker:02x}"),
        }
    }

    fn decode_array(bytes: &[u8], cursor: &mut usize, length: usize) -> Value {
        Value::Array((0..length).map(|_| decode_value(bytes, cursor)).collect())
    }

    fn decode_map(bytes: &[u8], cursor: &mut usize, length: usize) -> Value {
        let mut map = serde_json::Map::new();
        for _ in 0..length {
            let Value::String(key) = decode_value(bytes, cursor) else {
                panic!("MessagePack map key is not a string");
            };
            let previous = map.insert(key, decode_value(bytes, cursor));
            assert!(previous.is_none(), "duplicate MessagePack map key");
        }
        Value::Object(map)
    }

    fn decode_string(bytes: &[u8], cursor: &mut usize, length: usize) -> Value {
        Value::String(
            std::str::from_utf8(take(bytes, cursor, length))
                .unwrap()
                .to_string(),
        )
    }

    fn read_array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> [u8; N] {
        take(bytes, cursor, N).try_into().unwrap()
    }

    fn take<'a>(bytes: &'a [u8], cursor: &mut usize, length: usize) -> &'a [u8] {
        let end = cursor.checked_add(length).unwrap();
        let value = bytes.get(*cursor..end).expect("truncated MessagePack");
        *cursor = end;
        value
    }
}
