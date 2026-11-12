//! Fuzzes the vault file parsers with arbitrary bytes (S10, NFR-5,
//! `docs/design.md` §12.1): the header parser, the record parser and the
//! payload decoder. Argon2id is skipped so every input runs fast; the full
//! open path, crypto included, is covered by S2.
//!
//! Besides "never panics", it checks that the encoding is canonical
//! (`docs/vault-format.md` §4.8): anything the parsers accept encodes back to
//! exactly the same bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vaultline::vault::crypto::MAC_LEN;
use vaultline::vault::format;

fuzz_target!(|data: &[u8]| {
    let header = format::parse_header(data);
    let records = format::parse_records(data);
    if let (Ok(header), Ok(records)) = (header, records) {
        let body = format::encode_body(&header, &records).expect("parsed records re-encode");
        assert_eq!(body.as_slice(), &data[..data.len() - MAC_LEN]);
    }
    if let Ok(payload) = format::decode_payload(data) {
        let encoded = format::encode_payload(&payload).expect("a parsed payload re-encodes");
        assert_eq!(encoded.expose(), data);
    }
});
