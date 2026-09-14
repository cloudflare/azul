use crate::{ID_RDNA_TRUSTANCHOR_ID, MtcError};
use der::{Any, Tag, Tagged};
use std::str::FromStr;
use x509_cert::{
    attr::AttributeTypeAndValue,
    name::{RdnSequence, RelativeDistinguishedName},
};

/// ASN.1 `RELATIVE OID`.
///
/// TODO upstream this to the `der` crate.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

    /// Decode a `RelativeOid` from its BER-encoded bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not valid BER for a relative OID.
    pub fn from_ber_bytes(ber: &[u8]) -> Result<Self, MtcError> {
        if ber.is_empty() {
            return Err(MtcError::Dynamic("invalid relative OID".into()));
        }
        let mut arcs = Vec::new();
        let mut i = 0;
        while i < ber.len() {
            let mut arc: u32 = 0;
            let arc_start = i;
            loop {
                let b = *ber
                    .get(i)
                    .ok_or_else(|| MtcError::Dynamic("truncated OID arc".into()))?;
                i += 1;
                if i == arc_start + 1 && b == 0x80 {
                    return Err(MtcError::Dynamic("non-canonical OID arc".into()));
                }
                arc = arc
                    .checked_mul(128)
                    .and_then(|value| value.checked_add(u32::from(b & 0x7f)))
                    .ok_or_else(|| MtcError::Dynamic("OID arc overflow".into()))?;
                if b & 0x80 == 0 {
                    break;
                }
            }
            arcs.push(arc);
        }
        Ok(Self {
            ber: ber.to_vec(),
            arcs,
        })
    }

    /// Returns the DER-encoded content bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.ber
    }

    /// Derive issuance log `log_number` from this CA ID.
    ///
    /// # Errors
    ///
    /// Returns an error for log number zero.
    pub fn log_id(&self, log_number: u16) -> Result<Self, MtcError> {
        if log_number == 0 {
            return Err(MtcError::Dynamic("log number must be positive".into()));
        }
        let mut arcs = self.arcs.clone();
        arcs.extend([0, u32::from(log_number)]);
        Self::from_arcs(&arcs)
    }

    /// Return the full private-enterprise OID form used by signed-note names.
    #[must_use]
    pub fn oid_name(&self) -> String {
        format!("oid/1.3.6.1.4.1.{self}")
    }

    /// Construct the single-attribute X.509 name for this trust anchor ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the relative OID cannot be represented as an X.509 attribute.
    pub fn to_rdn_sequence(&self) -> Result<RdnSequence, MtcError> {
        let value = Any::new(Tag::RelativeOid, self.as_bytes())?;
        let rdn = RelativeDistinguishedName::try_from(vec![AttributeTypeAndValue {
            oid: ID_RDNA_TRUSTANCHOR_ID,
            value,
        }])?;
        Ok(RdnSequence::from(vec![rdn]))
    }

    /// Parse a trust anchor ID from its single-attribute X.509 name.
    ///
    /// # Errors
    ///
    /// Returns an error if the name has another shape, OID, or value type.
    pub fn from_rdn_sequence(name: &RdnSequence) -> Result<Self, MtcError> {
        let mut rdns = name.iter();
        let rdn = rdns
            .next()
            .filter(|_| rdns.next().is_none())
            .ok_or_else(|| MtcError::Dynamic("trust anchor name must contain one RDN".into()))?;
        let mut attributes = rdn.iter();
        let attribute = attributes
            .next()
            .filter(|_| attributes.next().is_none())
            .ok_or_else(|| {
                MtcError::Dynamic("trust anchor RDN must contain one attribute".into())
            })?;
        if attribute.oid != ID_RDNA_TRUSTANCHOR_ID || attribute.value.tag() != Tag::RelativeOid {
            return Err(MtcError::Dynamic(
                "invalid trust anchor ID attribute".into(),
            ));
        }
        Self::from_ber_bytes(attribute.value.value())
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
        if s.is_empty() {
            return Err(MtcError::Dynamic("invalid relative OID".into()));
        }
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

    use der::{Any, Decode, Encode, Tag};

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

    #[test]
    fn trust_anchor_rdn_uses_relative_oid() {
        let id = RelativeOid::from_str("32473.1").unwrap();
        let name = id.to_rdn_sequence().unwrap();
        assert_eq!(
            name.to_der().unwrap(),
            [
                0x30, 0x16, 0x31, 0x14, 0x30, 0x12, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82,
                0xda, 0x4b, 0x2f, 0x03, 0x0d, 0x04, 0x81, 0xfd, 0x59, 0x01,
            ]
        );
        assert_eq!(RelativeOid::from_rdn_sequence(&name).unwrap(), id);

        let reparsed = RdnSequence::from_der(&name.to_der().unwrap()).unwrap();
        assert_eq!(RelativeOid::from_rdn_sequence(&reparsed).unwrap(), id);
    }
}
