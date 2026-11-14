//! Unit tests of the wire protocol (`design.md` §8.1).

use super::*;
use proptest::prelude::*;
use static_assertions::assert_not_impl_any;
use std::fmt::{Debug, Display};
use std::io::Cursor as IoCursor;

assert_not_impl_any!(Request: Debug, Display);
assert_not_impl_any!(Reply: Debug, Display);
assert_not_impl_any!(Response: Debug, Display);

fn requests() -> Vec<Request> {
    vec![
        Request::Resolve(vec![]),
        Request::Resolve(vec![
            b"vault://p/i/f".to_vec(),
            b"vault://p/i/g".to_vec(),
            vec![],
        ]),
        Request::Set {
            reference: b"vault://p/i/f".to_vec(),
            value: SecretValue::new(b"fake-value"),
        },
        Request::Set {
            reference: b"p/i/f".to_vec(),
            value: SecretValue::new(&[0xff; MAX_BLOB]),
        },
        Request::Remove(b"vault://p/i/f".to_vec()),
        Request::List(None),
        Request::List(Some(b"proj".to_vec())),
        Request::Unlock(Passphrase::new(b"fake-passphrase-for-tests")),
        Request::Unlock(Passphrase::new(b"")),
        Request::Lock,
        Request::Stop,
        Request::Status,
        Request::AuditVerify(None),
        Request::AuditVerify(Some(b"3:00".to_vec())),
        Request::AuditHead,
    ]
}

fn body_of(frame: &[u8]) -> &[u8] {
    &frame[4..]
}

#[test]
fn every_request_round_trips_byte_for_byte() {
    for request in requests() {
        let frame = encode_request(&request).unwrap();
        assert_eq!(
            u32::from_le_bytes(frame[..4].try_into().unwrap()) as usize,
            frame.len() - 4
        );
        assert_eq!(frame[4], PROTO_VERSION);
        assert_eq!(frame[5], request.kind() as u8);
        let decoded = decode_request(body_of(&frame)).unwrap();
        assert_eq!(decoded.kind(), request.kind());
        assert_eq!(*encode_request(&decoded).unwrap(), *frame);
    }
}

#[test]
fn read_frame_returns_the_body_and_stops_at_the_end_of_the_frame() {
    let frame = encode_request(&Request::Status).unwrap();
    let mut input = frame.to_vec();
    input.extend_from_slice(b"next frame");
    let mut reader = IoCursor::new(input);
    let body = read_frame(&mut reader).unwrap();
    assert_eq!(&*body, body_of(&frame));
    assert_eq!(reader.position() as usize, frame.len());
}

#[test]
fn a_frame_of_length_zero_or_over_1_mib_is_rejected_before_anything_is_read() {
    for len in [0u32, MAX_FRAME as u32 + 1, u32::MAX] {
        let mut reader = IoCursor::new(len.to_le_bytes().to_vec());
        assert!(
            matches!(read_frame(&mut reader), Err(ProtocolError::BadLength)),
            "{len}"
        );
    }
    // The longest allowed frame is accepted when it is all there.
    let mut input = (MAX_FRAME as u32).to_le_bytes().to_vec();
    input.extend(vec![0u8; MAX_FRAME]);
    assert_eq!(
        read_frame(&mut IoCursor::new(input)).unwrap().len(),
        MAX_FRAME
    );
}

#[test]
fn a_frame_that_ends_early_is_an_io_error_not_a_panic() {
    let mut input = 10u32.to_le_bytes().to_vec();
    input.extend_from_slice(&[1, 2, 3]);
    assert!(matches!(
        read_frame(&mut IoCursor::new(input)),
        Err(ProtocolError::Io(_))
    ));
    assert!(matches!(
        read_frame(&mut IoCursor::new(vec![1, 0])),
        Err(ProtocolError::Io(_))
    ));
    assert!(matches!(
        read_frame(&mut IoCursor::new(Vec::new())),
        Err(ProtocolError::Io(_))
    ));
}

#[test]
fn a_request_with_a_wrong_version_or_kind_is_rejected() {
    assert!(matches!(
        decode_request(&[2, 6]),
        Err(ProtocolError::UnsupportedVersion(2))
    ));
    assert!(matches!(
        decode_request(&[0, 6]),
        Err(ProtocolError::UnsupportedVersion(0))
    ));
    for kind in [0u8, 11, 255] {
        assert!(
            matches!(decode_request(&[1, kind]), Err(ProtocolError::UnknownKind(k)) if k == kind)
        );
    }
    assert!(matches!(decode_request(&[]), Err(ProtocolError::Truncated)));
    assert!(matches!(
        decode_request(&[1]),
        Err(ProtocolError::Truncated)
    ));
}

#[test]
fn trailing_bytes_are_rejected_on_every_kind() {
    for request in requests() {
        let frame = encode_request(&request).unwrap();
        let mut body = body_of(&frame).to_vec();
        body.push(0);
        assert!(
            matches!(decode_request(&body), Err(ProtocolError::TrailingBytes)),
            "{:?}",
            request.kind()
        );
    }
}

#[test]
fn every_truncation_of_every_request_is_an_error() {
    for request in requests() {
        let frame = encode_request(&request).unwrap();
        let body = body_of(&frame);
        for cut in 0..body.len() {
            assert!(
                decode_request(&body[..cut]).is_err(),
                "{:?} cut at {cut}",
                request.kind()
            );
        }
    }
}

#[test]
fn a_length_that_overruns_the_frame_is_rejected() {
    // Set with a reference length of 500 but only a few bytes after it.
    let mut body = vec![PROTO_VERSION, Kind::Set as u8];
    body.extend_from_slice(&500u16.to_le_bytes());
    body.extend_from_slice(b"short");
    assert!(matches!(
        decode_request(&body),
        Err(ProtocolError::Truncated)
    ));
    // A value over 64 KiB.
    let mut body = vec![PROTO_VERSION, Kind::Set as u8, 0, 0];
    body.extend_from_slice(&(MAX_BLOB as u32 + 1).to_le_bytes());
    body.extend(vec![0u8; MAX_BLOB + 1]);
    assert!(matches!(
        decode_request(&body),
        Err(ProtocolError::TooLarge)
    ));
    // A Resolve count the frame can't hold doesn't reserve memory for it.
    let mut body = vec![PROTO_VERSION, Kind::Resolve as u8];
    body.extend_from_slice(&u16::MAX.to_le_bytes());
    assert!(matches!(
        decode_request(&body),
        Err(ProtocolError::Truncated)
    ));
}

#[test]
fn a_flag_must_be_zero_or_one() {
    for kind in [Kind::List, Kind::AuditVerify] {
        let body = [PROTO_VERSION, kind as u8, 2];
        assert!(matches!(decode_request(&body), Err(ProtocolError::BadFlag)));
    }
}

#[test]
fn encoding_refuses_what_the_format_cannot_hold() {
    let long = vec![b'a'; usize::from(u16::MAX) + 1];
    assert!(matches!(
        encode_request(&Request::Remove(long)),
        Err(ProtocolError::TooLarge)
    ));
    let big = SecretValue::new(&vec![0u8; MAX_BLOB + 1]);
    let request = Request::Set {
        reference: b"p/i/f".to_vec(),
        value: big,
    };
    assert!(matches!(
        encode_request(&request),
        Err(ProtocolError::TooLarge)
    ));
    let big = Passphrase::new(&vec![0u8; MAX_BLOB + 1]);
    assert!(matches!(
        encode_request(&Request::Unlock(big)),
        Err(ProtocolError::TooLarge)
    ));
}

#[test]
fn a_response_that_would_not_fit_in_a_frame_is_refused() {
    let values: Vec<SecretValue> = (0..20)
        .map(|_| SecretValue::new(&[1u8; MAX_BLOB]))
        .collect();
    assert!(matches!(
        encode_response(&Response::Ok(Reply::Values(values))),
        Err(ProtocolError::TooLarge)
    ));
}

fn responses() -> Vec<(Kind, Response)> {
    vec![
        (Kind::Resolve, Response::Ok(Reply::Values(vec![]))),
        (
            Kind::Resolve,
            Response::Ok(Reply::Values(vec![
                SecretValue::new(b"fake-a"),
                SecretValue::new(b""),
            ])),
        ),
        (Kind::Set, Response::Ok(Reply::Done)),
        (Kind::Remove, Response::Ok(Reply::Done)),
        (Kind::Unlock, Response::Ok(Reply::Done)),
        (Kind::Lock, Response::Ok(Reply::Done)),
        (Kind::Stop, Response::Ok(Reply::Done)),
        (Kind::List, Response::Ok(Reply::Names(vec![]))),
        (
            Kind::List,
            Response::Ok(Reply::Names(vec!["a/b/c".into(), "a/b/d".into()])),
        ),
        (
            Kind::Status,
            Response::Ok(Reply::Status {
                unlocked: true,
                idle_secs: 899,
            }),
        ),
        (
            Kind::Status,
            Response::Ok(Reply::Status {
                unlocked: false,
                idle_secs: 0,
            }),
        ),
        (
            Kind::AuditVerify,
            Response::Ok(Reply::Verdict {
                passed: true,
                report: "fine".into(),
            }),
        ),
        (
            Kind::AuditVerify,
            Response::Ok(Reply::Verdict {
                passed: false,
                report: "".into(),
            }),
        ),
        (Kind::AuditHead, Response::Ok(Reply::Anchor("1:00".into()))),
        (
            Kind::Resolve,
            Response::error(code::NOT_FOUND, "vault://p/i/f"),
        ),
        (
            Kind::Status,
            Response::error(code::LOCKED, "the agent is locked"),
        ),
    ]
}

#[test]
fn every_response_round_trips_byte_for_byte() {
    for (kind, response) in responses() {
        let frame = encode_response(&response).unwrap();
        let decoded = decode_response(kind, body_of(&frame)).unwrap();
        assert_eq!(*encode_response(&decoded).unwrap(), *frame, "{kind:?}");
    }
}

#[test]
fn an_error_response_decodes_for_any_kind() {
    let frame =
        encode_response(&Response::error(code::BUSY, "another vaultline is writing")).unwrap();
    for kind in Kind::ALL {
        match decode_response(kind, body_of(&frame)).unwrap() {
            Response::Err { code: c, message } => {
                assert_eq!(c, code::BUSY);
                assert_eq!(message, "another vaultline is writing");
            }
            Response::Ok(_) => panic!("an error decoded as OK"),
        }
    }
}

#[test]
fn bad_responses_are_rejected() {
    let ok = encode_response(&Response::Ok(Reply::Done)).unwrap();
    let body = body_of(&ok);
    assert!(matches!(
        decode_response(Kind::Lock, &[2, 0]),
        Err(ProtocolError::UnsupportedVersion(2))
    ));
    assert!(matches!(
        decode_response(Kind::Lock, &[1, 2]),
        Err(ProtocolError::UnknownStatus(2))
    ));
    let mut trailing = body.to_vec();
    trailing.push(0);
    assert!(matches!(
        decode_response(Kind::Lock, &trailing),
        Err(ProtocolError::TrailingBytes)
    ));
    // Text that isn't UTF-8.
    let mut bad = vec![PROTO_VERSION, 1, 3, 0, 2, 0, 0xff, 0xfe];
    assert!(matches!(
        decode_response(Kind::Lock, &bad),
        Err(ProtocolError::NotUtf8)
    ));
    bad.truncate(5);
    assert!(decode_response(Kind::Lock, &bad).is_err());
    // A List count that the frame can't hold.
    let mut list = vec![PROTO_VERSION, 0];
    list.extend_from_slice(&u32::MAX.to_le_bytes());
    assert!(decode_response(Kind::List, &list).is_err());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// S10: no input makes a decoder panic, and anything a request decoder
    /// accepts encodes back to the same bytes (the format has one spelling).
    #[test]
    fn decoding_never_panics_and_requests_are_canonical(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
        if let Ok(request) = decode_request(&bytes) {
            let frame = encode_request(&request).unwrap();
            prop_assert_eq!(body_of(&frame), &bytes[..]);
        }
        for kind in Kind::ALL {
            if let Ok(response) = decode_response(kind, &bytes) {
                let frame = encode_response(&response).unwrap();
                prop_assert_eq!(body_of(&frame), &bytes[..]);
            }
        }
        let _ = read_frame(&mut IoCursor::new(bytes));
    }

    /// Bytes that begin like a real message get past the first checks, so the
    /// field decoders see them too.
    #[test]
    fn decoding_a_well_started_message_never_panics(
        kind in 1u8..=10,
        tail in proptest::collection::vec(any::<u8>(), 0..200),
        response_status in 0u8..=1,
    ) {
        let mut request = vec![PROTO_VERSION, kind];
        request.extend_from_slice(&tail);
        let _ = decode_request(&request);
        let mut response = vec![PROTO_VERSION, response_status];
        response.extend_from_slice(&tail);
        for kind in Kind::ALL {
            let _ = decode_response(kind, &response);
        }
    }
}
