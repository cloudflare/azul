//! This file contains code ported from the original project [note](https://pkg.go.dev/golang.org/x/mod/sumdb/note) ([BSD-3-Clause license](https://pkg.go.dev/golang.org/x/mod/sumdb/note?tab=licenses)).
//! See the LICENSE file in the root of this repository for the full license text.
//!
//! References:
//! - [note_test.go](https://cs.opensource.google/go/x/mod/+/refs/tags/v0.21.0:sumdb/note/note_test.go)

use criterion::{criterion_group, criterion_main, Criterion};
use signed_note::{Note, NoteError, StandardVerifier, VerifierList};
use std::hint::black_box;

fn benchmark_verify(c: &mut Criterion) {
    let vkey = "PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW";
    let msg = "If you think cryptography is the answer to your problem,\n\
               then you don't know what your problem is.\n\
               \n\
               — PeterNeumann x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=\n".as_bytes();

    let verifier = StandardVerifier::new(vkey).unwrap();

    c.bench_function("Sig0", |b| {
        b.iter(|| {
            let err = Note::from_bytes(black_box(msg))
                .unwrap()
                .verify(&VerifierList::new(black_box(vec![])))
                .unwrap_err();
            assert!(matches!(err, NoteError::UnverifiedNote));
        });
    });

    c.bench_function("Sig1", |b| {
        b.iter(|| {
            let (verified_sigs, unverified_sigs) = Note::from_bytes(black_box(msg))
                .unwrap()
                .verify(black_box(&VerifierList::new(vec![Box::new(
                    verifier.clone(),
                )])))
                .unwrap();
            assert_eq!(verified_sigs.len(), 1);
            assert!(unverified_sigs.is_empty());
        });
    });
}

criterion_group!(benches, benchmark_verify);
criterion_main!(benches);
