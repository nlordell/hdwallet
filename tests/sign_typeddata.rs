mod util;

use crate::util::Hdwallet;

#[test]
fn signs_typed_data() {
    let signature = Hdwallet::new("sign", &["typeddata", "-"])
        .stdin(
            r#"{
                "types": {
                    "EIP712Domain": [
                        { "name": "name", "type": "string" },
                        { "name": "version", "type": "string" },
                        { "name": "chainId", "type": "uint256" },
                        { "name": "verifyingContract", "type": "address" }
                    ],
                    "Person": [
                        { "name": "name", "type": "string" },
                        { "name": "wallet", "type": "address" }
                    ],
                    "Mail": [
                        { "name": "from", "type": "Person" },
                        { "name": "to", "type": "Person" },
                        { "name": "contents", "type": "string" }
                    ]
                },
                "primaryType": "Mail",
                "domain": {
                    "name": "Ether Mail",
                    "version": "1",
                    "chainId": 1,
                    "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
                },
                "message": {
                    "from": {
                        "name": "Cow",
                        "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
                    },
                    "to": {
                        "name": "Bob",
                        "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
                    },
                    "contents": "Hello, Bob!"
                }
            }"#,
        )
        .execute()
        .unwrap();
    assert_eq!(signature, "0x12bdd486cb42c3b3c414bb04253acfe7d402559e7637562987af6bd78508f38623c1cc09880613762cc913d49fd7d3c091be974c0dee83fb233300b6b58727311c");
}
