use crate::MtcError;
use std::str::FromStr;

/// ASN.1 `RELATIVE OID`.
///
/// TODO upstream this to the `der` crate.
#[derive(Clone)]
pub struct RelativeOid {
    ber: Vec<u8>,
    arcs: Vec<u32>,
}

impl RelativeOid {
    fn from_arcs(arcs: &[u32]) -> Result<Self, MtcError> {
        let mut ber = Vec::new();
        for arc in arcs {
            for j in (0..=4).rev() {
                #[allow(clippy::cast_possible_truncation)]
                let cur = (arc >> (j * 7)) as u8;

                if cur != 0 || j == 0 {
                    let mut to_write = cur & 0x7f; // lower 7 bits

                    if j != 0 {
                        to_write |= 0x80;
                    }
                    ber.push(to_write);
                }
            }
        }
        if ber.len() > 255 {
            return Err(MtcError::Dynamic("invalid relative OID".into()));
        }
        Ok(Self {
            ber,
            arcs: arcs.to_vec(),
        })
    }

    /// Returns the DER-encoded content bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.ber
    }
}

impl std::fmt::Display for RelativeOid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for arc in self.arcs.iter().take(self.arcs.len() - 1) {
            write!(f, "{arc}.")?;
        }
        write!(f, "{}", self.arcs[self.arcs.len() - 1])
    }
}

impl FromStr for RelativeOid {
    type Err = MtcError;
    /// Parse the [`RelativeOid`] from a decimal-dotted string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = s.split('.');
        let mut arcs = Vec::new();
        for part in parts {
            let i = part.parse::<u32>()?;
            arcs.push(i);
        }
        Self::from_arcs(&arcs)
    }
}

#[cfg(test)]
mod tests {

    use der::{Any, Encode, Tag};

    use super::*;

    #[test]
    fn encode_tagged() {
        let relative_oid = RelativeOid::from_str("13335.2").unwrap();
        let any = Any::new(Tag::RelativeOid, relative_oid.as_bytes()).unwrap();
        assert_eq!(any.to_der().unwrap(), b"\x0d\x03\xe8\x17\x02");
    }

    #[test]
    fn encode_string() {
        let relative_oid = RelativeOid::from_str("13335.2").unwrap();
        assert_eq!(relative_oid.to_string(), "13335.2");
    }

    #[test]
    fn decode_string_encode_bytes() {
        struct TestCase {
            s: &'static str,
            b: &'static [u8],
        }
        for TestCase { s, b } in [
            TestCase {
                s: "237",
                b: &[129, 109],
            },
            TestCase {
                s: "1.2.3.4",
                b: &[1, 2, 3, 4],
            },
            TestCase {
                s: "13335.2",
                b: &[232, 23, 2],
            },
            TestCase {
                s: "44363.48.10",
                b: &[130, 218, 75, 48, 10],
            },
        ] {
            let relative_oid = RelativeOid::from_str(s).unwrap();
            assert_eq!(relative_oid.as_bytes(), b);
        }
    }
}
