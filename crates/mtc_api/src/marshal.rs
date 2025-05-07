use crate::{
    AbridgedSubject, AbridgedTLSSubject, Assertion, AssertionRequest, ClaimType, Claims, Digest,
    Domain, Error, Evidence, EvidenceList, EvidenceType, IpAddr, LogEntry, Sha256, Subject,
    SubjectType, TLSSubject, UmbilicalEvidence, UnknownClaim, UnknownEvidence, UnknownSubject,
    HASH_LEN,
};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{BufRead, Read, Write};
use std::marker::Sized;

pub trait ReadLengthPrefixedBytesExt: Read {
    /// Read length-prefixed bytes from the reader.
    ///
    /// # Errors
    ///
    /// Returns the same error as [`Read::read_exact`](https://doc.rust-lang.org/std/io/trait.Read.html#method.read_exact).
    ///
    /// # Panics
    ///
    /// `read_uint` requires that `1 <= nbytes <= 8`, and will panic otherwise.
    #[inline]
    fn read_length_prefixed(&mut self, nbytes: usize) -> std::io::Result<Vec<u8>> {
        let length = self.read_uint::<BigEndian>(nbytes)?;
        let mut buffer = vec![0; usize::try_from(length).unwrap()];
        self.read_exact(&mut buffer)?;
        Ok(buffer)
    }
}

/// All types that implement `Read` get methods defined in
/// `ReadLengthPrefixedBytesExt` for free.
impl<R: Read + ?Sized> ReadLengthPrefixedBytesExt for R {}

pub trait WriteLengthPrefixedBytesExt: Write {
    /// Write length-prefixed bytes to the writer.
    ///
    /// # Errors
    ///
    /// This method returns the same errors as
    /// [`Write::write_all`](https://doc.rust-lang.org/std/io/trait.Write.html#method.write_all).
    #[inline]
    fn write_length_prefixed(&mut self, data: &[u8], length_bytes: usize) -> std::io::Result<()> {
        self.write_uint::<BigEndian>(data.len() as u64, length_bytes)?;
        self.write_all(data)
    }
}

/// All types that implement `Write` get methods defined in
/// `WriteLengthPrefixedBytesExt` for free.
impl<W: Write + ?Sized> WriteLengthPrefixedBytesExt for W {}

pub trait Marshal {
    /// Marshal Self to the provider writer.
    ///
    /// # Errors
    ///
    /// Returns an error when the object cannot be marshaled,
    /// for example due to an invalid object state.
    fn marshal<W: Write>(&self, w: &mut W) -> Result<(), Error>;
}

pub trait Unmarshal {
    /// Unmarshal an instance of the object from the input stream.
    ///
    /// # Errors
    ///
    /// Returns an error if the object cannot be unmarshaled
    /// from the input stream, for example due to insufficient data.
    fn unmarshal<R: Read>(r: &mut R) -> Result<Self, Error>
    where
        Self: Sized;
}

/// Unmarshal a single instance of an object from the input stream.
///
/// # Errors
///
/// Returns an error if object cannot be unmarshaled, or if the input
/// is not completely consumed.
pub fn unmarshal_exact<T: Unmarshal, R: BufRead>(r: &mut R) -> Result<T, Error> {
    let result = T::unmarshal(r)?;
    if !r.fill_buf()?.is_empty() {
        return Err(Error::TrailingData);
    }
    Ok(result)
}

impl Marshal for Claims {
    fn marshal<W: Write>(&self, w: &mut W) -> Result<(), Error> {
        let mut buffer = Vec::new();

        let mut marshal_domains =
            |domains: &[Domain], claim_type: ClaimType| -> Result<(), Error> {
                if domains.is_empty() {
                    return Ok(());
                }
                if !domains.is_sorted() {
                    return Err(Error::UnsortedClaim);
                }
                let mut domains_buffer = Vec::new();
                for domain in domains {
                    domains_buffer.write_length_prefixed(domain.0.as_bytes(), 1)?;
                }
                let mut packed = Vec::new();
                packed.write_length_prefixed(&domains_buffer, 2)?;

                buffer.write_u16::<BigEndian>(claim_type.into())?;
                buffer.write_length_prefixed(&packed, 2)?;
                Ok(())
            };
        marshal_domains(&self.dns, ClaimType::Dns)?;
        marshal_domains(&self.dns_wildcard, ClaimType::DnsWildcard)?;

        let mut marshal_ips = |ips: &[IpAddr], claim_type: ClaimType| -> Result<(), Error> {
            if ips.is_empty() {
                return Ok(());
            }
            if !ips.is_sorted() {
                return Err(Error::UnsortedClaim);
            }
            let mut ips_buffer = Vec::new();
            for ip in ips {
                match ip {
                    IpAddr::V4(ipv4) => ips_buffer.write_all(&ipv4.octets())?,
                    IpAddr::V6(ipv6) => ips_buffer.write_all(&ipv6.octets())?,
                }
            }
            let mut packed = Vec::new();
            packed.write_length_prefixed(&ips_buffer, 2)?;

            buffer.write_u16::<BigEndian>(claim_type.into())?;
            buffer.write_length_prefixed(&packed, 2)?;
            Ok(())
        };

        marshal_ips(&self.ipv4, ClaimType::Ipv4)?;
        marshal_ips(&self.ipv6, ClaimType::Ipv6)?;

        let mut previous_typ: Option<ClaimType> = None;
        for claim in &self.unknown {
            match claim.typ {
                ClaimType::Unknown(_) => {
                    if let Some(prev) = previous_typ {
                        if prev >= claim.typ {
                            return Err(Error::MalformedClaims);
                        }
                    }
                    previous_typ = Some(claim.typ);
                }
                _ => return Err(Error::ParseableUnknownClaim),
            }
            buffer.write_u16::<BigEndian>(claim.typ.into())?;
            buffer.write_length_prefixed(&claim.info, 2)?;
        }

        w.write_length_prefixed(&buffer, 2)?;

        Ok(())
    }
}
impl Unmarshal for Claims {
    fn unmarshal<R: Read>(r: &mut R) -> Result<Self, Error> {
        let mut claims = Claims::default();
        let mut previous_type: Option<ClaimType> = None;
        let mut buffer: &[u8] = &r.read_length_prefixed(2)?;

        while !buffer.is_empty() {
            let claim_type = ClaimType::from(buffer.read_u16::<BigEndian>()?);
            let mut claim_info: &[u8] = &buffer.read_length_prefixed(2)?;

            if let Some(t) = previous_type {
                if t >= claim_type {
                    return Err(Error::MalformedClaims);
                }
                previous_type = Some(claim_type);
            }

            match claim_type {
                ClaimType::Dns | ClaimType::DnsWildcard => {
                    let mut domains = Vec::new();
                    let mut packed: &[u8] = &claim_info.read_length_prefixed(2)?;
                    if !claim_info.is_empty() {
                        return Err(Error::TrailingData);
                    }
                    if packed.is_empty() {
                        return Err(Error::EmptyClaim);
                    }
                    while !packed.is_empty() {
                        domains.push(Domain::try_from(
                            packed.read_length_prefixed(1)?.as_slice(),
                        )?);
                    }
                    if !domains.is_sorted() {
                        return Err(Error::UnsortedClaim);
                    }
                    if claim_type == ClaimType::Dns {
                        claims.dns = domains;
                    } else {
                        claims.dns_wildcard = domains;
                    }
                }
                ClaimType::Ipv4 | ClaimType::Ipv6 => {
                    let entry_size = if claim_type == ClaimType::Ipv4 { 4 } else { 16 };
                    let mut ips = Vec::new();
                    let mut packed: &[u8] = &claim_info.read_length_prefixed(2)?;
                    if packed.is_empty() {
                        return Err(Error::EmptyClaim);
                    }
                    while packed.len() >= entry_size {
                        let (entry_bytes, rest) = packed.split_at(entry_size);
                        packed = rest;

                        let ip = if claim_type == ClaimType::Ipv4 {
                            let arr: [u8; 4] = entry_bytes.try_into().unwrap();
                            IpAddr::from(arr)
                        } else {
                            let arr: [u8; 16] = entry_bytes.try_into().unwrap();
                            IpAddr::from(arr)
                        };
                        ips.push(ip);
                    }
                    if !packed.is_empty() {
                        return Err(Error::TrailingData);
                    }
                    if !ips.is_sorted() {
                        return Err(Error::UnsortedClaim);
                    }
                    if claim_type == ClaimType::Ipv4 {
                        claims.ipv4 = ips;
                    } else {
                        claims.ipv6 = ips;
                    };
                }
                ClaimType::Unknown(_) => {
                    claims.unknown.push(UnknownClaim {
                        typ: claim_type,
                        info: claim_info.to_vec(),
                    });
                }
            }
        }

        Ok(claims)
    }
}

impl Marshal for Assertion {
    fn marshal<W: Write>(&self, w: &mut W) -> Result<(), Error> {
        w.write_u16::<BigEndian>(self.subject.typ().into())?;
        w.write_length_prefixed(self.subject.info(), 2)?;
        self.claims.marshal(w)
    }
}

impl Unmarshal for Assertion {
    fn unmarshal<R: Read>(r: &mut R) -> Result<Self, Error> {
        let subject_type = SubjectType::from(r.read_u16::<BigEndian>()?);
        let subject_info = r.read_length_prefixed(2)?;
        let claims = Claims::unmarshal(r)?;
        let subject: Subject = match subject_type {
            SubjectType::TLS => Subject::TLS(TLSSubject {
                packed: subject_info,
            }),
            SubjectType::Unknown(_) => Subject::Unknown(UnknownSubject {
                typ: subject_type,
                info: subject_info,
            }),
        };
        Ok(Self { subject, claims })
    }
}

impl Marshal for LogEntry {
    /// Marshal the bytes to be stored in the data tile.
    fn marshal<W: Write>(&self, w: &mut W) -> Result<(), Error> {
        w.write_u16::<BigEndian>(self.abridged_subject.typ().into())?;
        w.write_length_prefixed(self.abridged_subject.info(), 2)?;
        self.claims.marshal(w)?;
        if self.not_after > i64::MAX.try_into().unwrap() {
            return Err(Error::InvalidTimestamp);
        }
        w.write_u64::<BigEndian>(self.not_after)?;
        w.write_length_prefixed(&self.extra_data, 3)?;
        Ok(())
    }
}

impl Unmarshal for LogEntry {
    fn unmarshal<R: Read>(r: &mut R) -> Result<Self, Error> {
        let subject_type = SubjectType::from(r.read_u16::<BigEndian>()?);
        let subject_info = r.read_length_prefixed(2)?;
        let claims = Claims::unmarshal(r)?;
        let not_after = r.read_u64::<BigEndian>()?;
        if not_after > i64::MAX.try_into().unwrap() {
            return Err(Error::InvalidTimestamp);
        }
        let extra_data = r.read_length_prefixed(3)?;

        let abridged_subject: AbridgedSubject = match subject_type {
            SubjectType::TLS => {
                if subject_info.len() != HASH_LEN + 2 {
                    return Err(Error::MalformedTLSSubject);
                }
                AbridgedSubject::TLS(AbridgedTLSSubject {
                    packed: subject_info.as_slice().try_into()?,
                })
            }
            SubjectType::Unknown(_) => AbridgedSubject::Unknown(UnknownSubject {
                typ: subject_type,
                info: subject_info,
            }),
        };

        Ok(LogEntry {
            abridged_subject,
            claims,
            not_after,
            extra_data,
        })
    }
}

impl Marshal for EvidenceList {
    fn marshal<W: Write>(&self, w: &mut W) -> Result<(), Error> {
        let mut data = Vec::new();

        for evidence in &self.0 {
            data.write_u16::<BigEndian>(evidence.typ().into())?;
            data.write_length_prefixed(evidence.info(), 3)?;
        }

        Ok(w.write_length_prefixed(&data, 3)?)
    }
}

impl Unmarshal for EvidenceList {
    fn unmarshal<R: Read>(r: &mut R) -> Result<Self, Error> {
        let mut evidence_list: Vec<Evidence> = Vec::new();
        let mut data: &[u8] = &r.read_length_prefixed(3)?;
        while !data.is_empty() {
            let evidence_type = EvidenceType::from(data.read_u16::<BigEndian>()?);
            let evidence_info = data.read_length_prefixed(3)?;
            match evidence_type {
                EvidenceType::Umbilical => {
                    evidence_list.push(Evidence::Umbilical(UmbilicalEvidence(evidence_info)));
                }
                EvidenceType::Unknown(_) => {
                    evidence_list.push(Evidence::Unknown(UnknownEvidence {
                        typ: evidence_type,
                        info: evidence_info,
                    }));
                }
            }
        }
        Ok(Self(evidence_list))
    }
}

impl AssertionRequest {
    fn marshal_and_check(&self) -> Result<(Vec<u8>, [u8; 32]), Error> {
        let mut data = Vec::new();
        self.assertion.marshal(&mut data)?;
        self.evidence.marshal(&mut data)?;
        data.write_u64::<BigEndian>(self.not_after)?;

        let checksum = Sha256::digest(&data);
        if let Some(expected) = self.checksum {
            if <[u8; HASH_LEN]>::from(checksum) != expected {
                return Err(Error::ChecksumInvalid);
            }
        }

        Ok((data, checksum.into()))
    }
}

impl Marshal for AssertionRequest {
    fn marshal<W: Write>(&self, w: &mut W) -> Result<(), Error> {
        let (data, checksum) = self.marshal_and_check()?;

        w.write_all(&checksum)?;
        w.write_all(&data)?;

        Ok(())
    }
}

impl Unmarshal for AssertionRequest {
    fn unmarshal<R: Read>(r: &mut R) -> Result<Self, Error> {
        let mut checksum = [0u8; HASH_LEN];
        r.read_exact(&mut checksum)?;
        let assertion = Assertion::unmarshal(r)?;
        let evidence = EvidenceList::unmarshal(r)?;
        let not_after = r.read_u64::<BigEndian>()?;

        let assertion_request = Self {
            checksum: Some(checksum),
            assertion,
            evidence,
            not_after,
        };
        assertion_request.marshal_and_check()?;

        Ok(assertion_request)
    }
}

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use crate::*;

    fn check_marshal_unmarshal<T: Marshal + Unmarshal + PartialEq + Debug>(obj: &T) {
        let mut buffer = Vec::new();
        obj.marshal(&mut buffer).unwrap();
        assert_eq!(obj, &T::unmarshal(&mut buffer.as_slice()).unwrap());
    }

    fn dummy_claim() -> Claims {
        Claims {
            dns: vec![
                Domain("example.com".into()),
                Domain("www.example.com".into()),
            ],
            dns_wildcard: vec![
                Domain("example.com".into()),
                Domain("www.example.com".into()),
            ],
            ipv4: vec![
                IpAddr::from_str("1.2.3.4").unwrap(),
                IpAddr::from_str("1.2.3.5").unwrap(),
            ],
            ipv6: vec![IpAddr::from_str("abcd::0").unwrap()],
            unknown: Vec::new(),
        }
    }

    fn dummy_subject() -> Subject {
        Subject::TLS(TLSSubject {
            packed: vec![0x08, 0x04, 0, 2, 0, 0],
        })
    }

    fn dummy_assertion() -> Assertion {
        Assertion {
            subject: dummy_subject(),
            claims: dummy_claim(),
        }
    }

    fn dummy_evidence() -> EvidenceList {
        EvidenceList(vec![Evidence::Umbilical(UmbilicalEvidence(vec![1, 2, 3]))])
    }

    #[test]
    fn test_claims() {
        let obj = dummy_claim();
        check_marshal_unmarshal(&obj);
    }

    #[test]
    fn test_assertion() {
        let obj = dummy_assertion();
        check_marshal_unmarshal(&obj);
    }

    #[test]
    fn test_tileleaf() {
        let obj = LogEntry {
            abridged_subject: dummy_subject().abridge().unwrap(),
            claims: dummy_claim(),
            not_after: 1234,
            extra_data: vec![1, 2, 3],
        };
        check_marshal_unmarshal(&obj);
    }

    #[test]
    fn test_evidencelist() {
        let obj = dummy_evidence();
        check_marshal_unmarshal(&obj);
    }

    #[test]
    fn test_assertionrequest() {
        let obj = AssertionRequest {
            checksum: None,
            evidence: dummy_evidence(),
            assertion: dummy_assertion(),
            not_after: 1234,
        };
        check_marshal_unmarshal(&obj);

        // Assertion generated with mtc command-line tool.
        let mut bytes: &[u8] = include_bytes!("../tests/google-assertion");
        AssertionRequest::unmarshal(&mut bytes).unwrap();
    }
}
