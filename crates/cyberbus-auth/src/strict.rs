//! Recursive duplicate detection, including unknown nested objects and JWT headers.
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use std::fmt;
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("unique JSON")
            }
            fn visit_map<M: MapAccess<'de>>(
                self,
                mut m: M,
            ) -> std::result::Result<Unique, M::Error> {
                let mut out = serde_json::Map::new();
                while let Some(k) = m.next_key::<String>()? {
                    if out.contains_key(&k) {
                        return Err(de::Error::custom("duplicate JSON key"));
                    }
                    out.insert(k, m.next_value::<Unique>()?.0);
                }
                Ok(Unique(Value::Object(out)))
            }
            fn visit_seq<S: SeqAccess<'de>>(
                self,
                mut s: S,
            ) -> std::result::Result<Unique, S::Error> {
                let mut out = Vec::new();
                while let Some(v) = s.next_element::<Unique>()? {
                    out.push(v.0);
                }
                Ok(Unique(Value::Array(out)))
            }
            fn visit_bool<E: de::Error>(self, x: bool) -> std::result::Result<Unique, E> {
                Ok(Unique(x.into()))
            }
            fn visit_i64<E: de::Error>(self, x: i64) -> std::result::Result<Unique, E> {
                Ok(Unique(x.into()))
            }
            fn visit_u64<E: de::Error>(self, x: u64) -> std::result::Result<Unique, E> {
                Ok(Unique(x.into()))
            }
            fn visit_f64<E: de::Error>(self, x: f64) -> std::result::Result<Unique, E> {
                serde_json::Number::from_f64(x)
                    .map(|v| Unique(Value::Number(v)))
                    .ok_or_else(|| de::Error::custom("number"))
            }
            fn visit_str<E: de::Error>(self, x: &str) -> std::result::Result<Unique, E> {
                Ok(Unique(x.into()))
            }
            fn visit_string<E: de::Error>(self, x: String) -> std::result::Result<Unique, E> {
                Ok(Unique(x.into()))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_none<E: de::Error>(self) -> std::result::Result<Unique, E> {
                self.visit_unit()
            }
        }
        d.deserialize_any(V)
    }
}
pub(crate) fn json(bytes: &[u8]) -> crate::Result<Value> {
    serde_json::from_slice::<Unique>(bytes)
        .map(|v| v.0)
        .map_err(|_| crate::Error::InvalidClaims)
}
pub(crate) fn jwt_parts(token: &str) -> crate::Result<(Value, Value)> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    if token.len() > 65536 {
        return Err(crate::Error::InvalidClaims);
    }
    let p: Vec<_> = token.split('.').collect();
    if p.len() != 3 || p.iter().any(|p| p.is_empty()) {
        return Err(crate::Error::InvalidClaims);
    }
    let decode = |s| {
        URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|_| crate::Error::InvalidClaims)
            .and_then(|b| json(&b))
    };
    Ok((decode(p[0])?, decode(p[1])?))
}
