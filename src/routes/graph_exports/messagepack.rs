use serde_json::Value;
use zed_interfaces::DependencyGraphDocument;

use crate::error::{ApiErr, ApiResult};

pub(super) fn encode(document: &DependencyGraphDocument) -> ApiResult<Vec<u8>> {
    let canonical = document
        .canonical_document_bytes()
        .map_err(|error| ApiErr::from(anyhow::anyhow!("graph canonicalization failed: {error}")))?;
    let value: Value = serde_json::from_slice(&canonical).map_err(|error| {
        ApiErr::from(anyhow::anyhow!("reparse canonical graph JSON: {error}"))
    })?;
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
            let length = u32::try_from(length).map_err(|_| {
                ApiErr::from(anyhow::anyhow!("MessagePack map exceeds u32 length"))
            })?;
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
        let bytes = encode(&sample_document()).unwrap();
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
}
