//! Fuzzes the agent's message decoders with arbitrary bytes (S10, NFR-5,
//! `docs/design.md` §8.1 and §12.1).
//!
//! The same bytes are tried as a frame stream, as a request body, and as a
//! response body to a request of every kind. None of them may panic. Whatever
//! a decoder accepts must encode back to exactly the bytes it came from: the
//! protocol has one spelling for every message, so a message can't be
//! smuggled through in a second one.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vaultline::agent::protocol::{
    Kind, decode_request, decode_response, encode_request, encode_response, read_frame,
};

fuzz_target!(|data: &[u8]| {
    let _ = read_frame(&mut &data[..]);

    if let Ok(request) = decode_request(data) {
        let frame = encode_request(&request).expect("an accepted request can be encoded");
        assert_eq!(&frame[4..], data, "a request has one spelling");
    }

    for kind in Kind::ALL {
        if let Ok(response) = decode_response(kind, data) {
            let frame = encode_response(&response).expect("an accepted response can be encoded");
            assert_eq!(&frame[4..], data, "a response has one spelling");
        }
    }
});
