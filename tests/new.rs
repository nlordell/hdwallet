mod util;

use hdwallet::mnemonic::Mnemonic;

#[test]
fn generates_random_mnemonic() {
    let mnemonic = util::exec("new", &[]);
    assert!(Mnemonic::from_phrase(mnemonic).is_ok())
}

#[test]
fn errors_on_invalid_language() {
    assert!(util::try_exec("new", &["--language", "klingon"]).is_err());
}

#[test]
fn errors_on_invalid_length() {
    assert!(util::try_exec("new", &["--length", "1"]).is_err());
    assert!(util::try_exec("new", &["--length", "42"]).is_err());
}