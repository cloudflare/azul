# Signed Note

A Rust implementation of the [C2SP signed-note](https://c2sp.org/signed-note) specification.

## Example

Here is a well-formed signed note:

    If you think cryptography is the answer to your problem,
    then you don't know what your problem is
    — PeterNeumann x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=

It can be constructed and displayed using:

    use note::{Note, StandardSigner};
    let skey = "PRIVATE+KEY+PeterNeumann+c74f20a3+AYEKFALVFGyNhPJEMzD1QIDr+Y7hfZx09iUvxdXHKDFz";
    let text = "If you think cryptography is the answer to your problem,\n\
                then you don't know what your problem is.\n";
    let signer = StandardSigner::new(skey).unwrap();
    let mut n = Note::new(text, &[]).unwrap();
    n.add_sigs(&[&signer]).unwrap();
    let want = "If you think cryptography is the answer to your problem,\n\
                then you don't know what your problem is.\n\
                \n\
                — PeterNeumann x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=\n";
    assert_eq!(&n.to_string(), want);

See documentation for more complete examples.

    cargo doc --open

## Test

    cargo test

## Benchmark

    cargo bench

## Acknowledgements

The project ports code from [note](https://golang.org/x/mod/sumdb/note), which is licensed under the BSD-3-Clause License. See the LICENSE file in the root of this repository for the full license text.