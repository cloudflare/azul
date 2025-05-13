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
    /// Returns the same errors as
    /// [`Write::write_all`](https://doc.rust-lang.org/std/io/trait.Write.html#method.write_all).
    #[inline]
    fn write_length_prefixed(&mut self, data: &[u8], nbytes: usize) -> std::io::Result<()> {
        self.write_uint::<BigEndian>(data.len() as u64, nbytes)?;
        self.write_all(data)
    }
}

/// All types that implement `Write` get methods defined in
/// `WriteLengthPrefixedBytesExt` for free.
impl<W: Write + ?Sized> WriteLengthPrefixedBytesExt for W {}
