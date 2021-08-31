mod util;

use hdwallet::mnemonic::Mnemonic;
use util::Hdwallet;

#[test]
fn generates_random_mnemonic() {
    let mnemonic = Hdwallet::run("new", &[]);
    assert!(Mnemonic::from_phrase(mnemonic).is_ok())
}

#[test]
fn errors_on_invalid_language() {
    assert!(Hdwallet::new("new", &["--language", "klingon"])
        .execute()
        .is_err());
}

#[test]
fn errors_on_invalid_length() {
    assert!(Hdwallet::new("new", &["--length", "1"]).execute().is_err());
    assert!(Hdwallet::new("new", &["--length", "42"]).execute().is_err());
}
