// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or at https://opensource.org/licenses/BSD-3-Clause

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};
use std::marker::Sized;

pub trait ReadLengthPrefixedBytesExt: Read {
    /// Read big-endian length-prefixed bytes from the reader.
    ///
    /// # Errors
    ///
    /// Returns the same errors as
    /// [`Read::read_exact`](https://doc.rust-lang.org/std/io/trait.Read.html#method.read_exact).
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
    /// Write big-endian length-prefixed bytes to the writer.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::InvalidInput`](std::io::ErrorKind::InvalidInput) if
    /// `data.len()` does not fit in `nbytes` bytes, or if `nbytes` is not in
    /// `1..=8`. Otherwise returns the same errors as
    /// [`Write::write_all`](https://doc.rust-lang.org/std/io/trait.Write.html#method.write_all).
    /// Nothing is written on an `InvalidInput` error.
    #[inline]
    fn write_length_prefixed(&mut self, data: &[u8], nbytes: usize) -> std::io::Result<()> {
        let len = data.len() as u64;
        if !(1..=8).contains(&nbytes) || (nbytes < 8 && len >> (8 * nbytes) != 0) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{len} bytes does not fit in a {nbytes}-byte length prefix"),
            ));
        }
        self.write_uint::<BigEndian>(len, nbytes)?;
        self.write_all(data)
    }
}

/// All types that implement `Write` get methods defined in
/// `WriteLengthPrefixedBytesExt` for free.
impl<W: Write + ?Sized> WriteLengthPrefixedBytesExt for W {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    #[test]
    fn write_at_prefix_limit() {
        for (nbytes, max) in [(1, 0xFF), (2, 0xFFFF)] {
            let mut buf = Vec::new();
            buf.write_length_prefixed(&vec![7; max], nbytes).unwrap();
            assert_eq!(buf.len(), nbytes + max);
            assert_eq!(buf[..nbytes], [0xFF; 2][..nbytes]);
            assert_eq!(
                (&buf[..]).read_length_prefixed(nbytes).unwrap(),
                vec![7; max]
            );
        }
    }

    #[test]
    fn write_over_prefix_limit_is_error() {
        for (nbytes, len) in [(1, 0x100), (2, 0x1_0000), (3, 0x100_0000)] {
            let mut buf = Vec::new();
            let err = buf
                .write_length_prefixed(&vec![0; len], nbytes)
                .unwrap_err();
            assert_eq!(err.kind(), ErrorKind::InvalidInput);
            assert!(buf.is_empty());
        }
    }

    #[test]
    fn write_rejects_invalid_prefix_width() {
        for nbytes in [0, 9] {
            let err = Vec::new().write_length_prefixed(b"x", nbytes).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn write_empty() {
        let mut buf = Vec::new();
        buf.write_length_prefixed(&[], 2).unwrap();
        assert_eq!(buf, [0, 0]);
    }
}
