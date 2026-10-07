//! Strict JSON reading: a pack is signed over its RFC 8785 form, so every
//! input that two readers could parse differently is rejected.

use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;

/// Largest integer every JSON reader (and RFC 8785, which formats numbers as
/// IEEE doubles) represents exactly.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Parse a pack document: valid JSON, no duplicate object keys, no integer
/// beyond ±(2^53 − 1).
pub(crate) fn parse(bytes: &[u8]) -> Result<Value, String> {
    serde_json::from_slice::<NoDuplicateKeys>(bytes).map_err(|e| format!("not JSON, or has duplicate keys: {e}"))?;
    let value: Value = serde_json::from_slice(bytes).map_err(|e| format!("not JSON: {e}"))?;
    check_numbers(&value)?;
    Ok(value)
}

/// Reject integers RFC 8785 cannot carry exactly: two such documents could
/// share a digest while differing in a number.
pub(crate) fn check_numbers(value: &Value) -> Result<(), String> {
    fn walk(v: &Value, path: &mut String) -> Result<(), String> {
        match v {
            Value::Number(n) => {
                let too_big = match (n.as_u64(), n.as_i64()) {
                    (Some(u), _) => u > MAX_SAFE_INTEGER,
                    (None, Some(i)) => i.unsigned_abs() > MAX_SAFE_INTEGER,
                    (None, None) => false,
                };
                if too_big {
                    return Err(format!("integer {n} at {path} is beyond 2^53 and has no exact canonical form"));
                }
                Ok(())
            }
            Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    let len = path.len();
                    path.push_str(&format!("[{i}]"));
                    walk(item, path)?;
                    path.truncate(len);
                }
                Ok(())
            }
            Value::Object(map) => {
                for (k, item) in map {
                    let len = path.len();
                    path.push('.');
                    path.push_str(k);
                    walk(item, path)?;
                    path.truncate(len);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
    walk(value, &mut String::from("$"))
}

/// Accepts any JSON document whose objects have no duplicate member names
/// (`serde_json::Value` would silently keep the last one).
struct NoDuplicateKeys;

impl<'de> Deserialize<'de> for NoDuplicateKeys {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(Visitor)
    }
}

struct Visitor;

impl<'de> serde::de::Visitor<'de> for Visitor {
    type Value = NoDuplicateKeys;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("any JSON value")
    }
    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        while seq.next_element::<NoDuplicateKeys>()?.is_some() {}
        Ok(NoDuplicateKeys)
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut seen = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(serde::de::Error::custom(format!("duplicate key {key:?}")));
            }
            map.next_value::<NoDuplicateKeys>()?;
        }
        Ok(NoDuplicateKeys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_duplicates_and_unsafe_integers() {
        assert!(parse(br#"{"a":1,"a":2}"#).unwrap_err().contains("duplicate"));
        assert!(parse(br#"{"a":{"b":[1,{"c":1,"c":1}]}}"#).is_err());
        assert!(parse(br#"{"a":9007199254740992}"#).unwrap_err().contains("$.a"));
        assert!(parse(br#"{"a":-9007199254740992}"#).is_err());
        assert!(parse(br#"{"a":[9007199254740991, -9007199254740991, 1.5e300]}"#).is_ok());
        assert!(parse(b"nope").is_err());
    }
}
