use alloy::{
    consensus::{SignableTransaction, TxEip1559},
    primitives::{address, b256, hex, Signature, TxKind, U256},
    rlp::Encodable,
};
use rand::Rng;
use reqwest::{Client, Error};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, SignOnly};
use serde_json::json;
use sha3::{Digest, Keccak256};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // TODO: lazy, just put the port in manually after you start the devnet
    let port = 32793;
    let client = Client::new();
    let signature = Signature::from_scalars_and_parity(
        b256!("840cfc572845f5786e702984c2a582528cad4b49b2a10b9db1be7fca90058565"),
        b256!("25e7109ceb98168d95b09b18bbf6b685130e0562f233877d492b94eee0c5b6d1"),
        false,
    )?;

    let tx = create_tx();
    let raw_tx = convert_to_raw_tx(tx.clone(), signature);

    match send_request(port, &client, raw_tx, tx).await {
        Ok(response) => {
            println!("Response: {:?}", response);
        }
        Err(err) => {
            eprintln!("Request failed: {:?}", err);
        }
    }

    Ok(())
}

async fn send_request(
    port: u64,
    client: &Client,
    raw_tx: String,
    tx: TxEip1559,
) -> Result<serde_json::Value, Error> {
    let slot = 23;
    let digest = message_digest(tx, slot);
    let header = create_header(&digest);

    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "bolt_requestInclusion",
        "params":  vec![json!({
            "txs": vec![raw_tx],
            "slot": slot
        })],
        "id": 1,
    });

    let response = client
        .post(format!("http://127.0.0.1:{}", port))
        .header("X-Bolt-Signature", header)
        .json(&request_body)
        .send()
        .await?;

    let json_response = response.json().await?;
    Ok(json_response)
}

fn create_tx() -> TxEip1559 {
    let mut rng = rand::thread_rng();

    TxEip1559 {
        chain_id: 1,
        nonce: rng.gen_range(1..=u64::MAX),
        gas_limit: rng.gen_range(21000..=100000),
        to: TxKind::Call(address!("6069a6c32cf691f5982febae4faf8a6f3ab2f0f6")),
        value: U256::from(rng.gen_range(1..=100000)),
        max_fee_per_gas: rng.gen_range(1..=100000),
        max_priority_fee_per_gas: rng.gen_range(1..=100000),
        ..Default::default()
    }
}

fn convert_to_raw_tx(tx: TxEip1559, signature: Signature) -> String {
    let mut rlp_encoded = Vec::new();
    let signed_tx = tx.into_signed(signature);
    signed_tx.tx().encode(&mut rlp_encoded);
    format!("0x{}", hex::encode(rlp_encoded))
}

fn message_digest(tx: TxEip1559, target_slot: u64) -> Message {
    let mut rlp_encoded = Vec::new();
    tx.encode(&mut rlp_encoded);
    let tx_hash = Keccak256::digest(rlp_encoded);

    let hash_len = tx_hash.as_slice().len();
    let slot_len = std::mem::size_of::<u64>();

    let mut data = vec![0u8; hash_len + slot_len];
    data[..hash_len].copy_from_slice(tx_hash.as_slice());
    data[hash_len..].copy_from_slice(&target_slot.to_le_bytes());

    let mut hasher = Keccak256::new();
    hasher.update(data);
    let hash = hasher.finalize();

    let mut digest = [0u8; 32];
    digest.copy_from_slice(&hash[..]);

    Message::from_digest(digest)
}

fn create_header(digest: &Message) -> String {
    let secp: Secp256k1<SignOnly> = Secp256k1::gen_new();
    let secret_key = SecretKey::from_slice(&[1u8; 32]).expect("Failed to load secret key");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key).serialize_uncompressed();
    let public_key = &public_key[1..];

    let mut hasher = Keccak256::new();
    hasher.update(public_key);
    let hash = hasher.finalize();

    let address: [u8; 20] = hash[12..].try_into().expect("Failed to get address");
    let address = hex::encode(address);

    let signature = secp.sign_ecdsa_recoverable(digest, &secret_key);
    let (recovery_id, signature) = signature.serialize_compact();

    let mut signature_bytes = Vec::with_capacity(65);
    signature_bytes.extend_from_slice(&signature);
    signature_bytes.push(recovery_id as u8);

    let signature = hex::encode(signature_bytes);

    format!("0x{address}:0x{signature}")
}
