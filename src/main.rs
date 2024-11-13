use alloy::{
    consensus::{SignableTransaction, TxEip1559, TxEnvelope},
    eips::eip2718::{Decodable2718, Encodable2718},
    primitives::{address, hex, keccak256, PrimitiveSignature, TxKind, U256},
    rlp::{BytesMut, Decodable, Encodable},
};
use rand::Rng;
use reqwest::{Client, Error};
use secp256k1::{ecdsa::RecoveryId, All, Message, PublicKey, Secp256k1, SecretKey};
use serde_json::json;
use sha3::{Digest, Keccak256};

const SLOT_DURATION: u64 = 2;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // TODO: lazy, just put the port in manually after you start the devnet
    let port = 32871;
    let client = Client::new();

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_byte_array(&[0xcd; 32]).expect("32 bytes, within curve order");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key).serialize_uncompressed();

    let (tx, raw) = create_tx(secret_key);

    dbg!(&raw);

    // Seems to decode properly
    // raw_decode(raw.clone());

    let slot = calculate_slot(SLOT_DURATION * 16).await?;
    let digest = message_digest(tx, slot);
    let header = create_header(&secret_key, &public_key, &secp, &digest);

    match send_request(port, &client, (raw, slot, header)).await {
        Ok(response) => {
            println!("Response: {:?}", response);
        }
        Err(err) => {
            eprintln!("Request failed: {:?}", err);
        }
    }

    Ok(())
}

async fn calculate_slot(seconds_from_now: u64) -> anyhow::Result<u64> {
    let response = reqwest::get("http://127.0.0.1:32859/eth/v1/beacon/headers/head")
        .await?
        .json::<serde_json::Value>()
        .await?;

    dbg!(&response["data"]["header"]["message"]["slot"]);
    let current_slot: u64 = response["data"]["header"]["message"]["slot"]
        .as_str()
        .expect("Invalid slot data")
        .parse()?;

    dbg!(current_slot);
    let slots_ahead = seconds_from_now / SLOT_DURATION;
    dbg!(slots_ahead);
    let future_slot = current_slot + slots_ahead;
    dbg!(future_slot);

    Ok(future_slot)
}

fn raw_decode(raw: String) {
    let tx = raw.trim_start_matches("0x");
    let tx_bytes = hex::decode(tx).expect("Failed bytes");

    let envelope = TxEnvelope::decode_2718(&mut &tx_bytes[..]).expect("Failed 2718");
    dbg!(envelope);
}

async fn send_request(
    port: u64,
    client: &Client,
    data: (String, u64, String),
) -> Result<serde_json::Value, Error> {
    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "bolt_requestInclusion",
        "params":  [{ "txs": [data.0], "slot": data.1 }],
        "id": 1,
    });

    let response = client
        .post(format!("http://127.0.0.1:{}", port))
        .header("X-Bolt-Signature", data.2)
        .json(&request_body)
        .send()
        .await?;

    let json_response = response.json().await?;
    Ok(json_response)
}

fn create_tx(secret_key: SecretKey) -> (TxEnvelope, String) {
    let mut rng = rand::thread_rng();

    let tx = TxEip1559 {
        chain_id: 3151908,
        nonce: rng.gen_range(1..=u64::MAX),
        gas_limit: rng.gen_range(21000..=100000),
        to: TxKind::Call(address!("6069a6c32cf691f5982febae4faf8a6f3ab2f0f6")),
        value: U256::from(rng.gen_range(1..=10)),
        max_fee_per_gas: rng.gen_range(20..=100),
        max_priority_fee_per_gas: rng.gen_range(1..=2),
        ..Default::default()
    };

    let secp = Secp256k1::new();
    let mut buff = BytesMut::new();
    tx.encode(&mut buff);
    let tx_hash = keccak256(&buff);
    let message = Message::from_digest(tx_hash.0);
    let signature = secp.sign_ecdsa_recoverable(&message, &secret_key);
    let (recovery_id, sig) = signature.serialize_compact();
    let (r, s) = sig.split_at(32);
    let r = U256::from_be_slice(r);
    let s = U256::from_be_slice(s);
    let v = match recovery_id {
        RecoveryId::Zero => true,
        RecoveryId::One => false,
        _ => panic!("Unsupported recovery ID"),
    };

    let signature = PrimitiveSignature::new(r, s, true);

    let signed_tx = tx.into_signed(signature);
    let envelope = TxEnvelope::Eip1559(signed_tx);
    let raw = hex::encode_prefixed(envelope.encoded_2718());

    (envelope, raw)
}

fn message_digest(tx: TxEnvelope, target_slot: u64) -> Message {
    let message_digest = {
        let mut data = Vec::new();

        data.extend_from_slice(tx.tx_hash().as_slice());
        data.extend_from_slice(&target_slot.to_le_bytes());

        Keccak256::digest(data)
    };

    Message::from_digest(message_digest.into())
}

fn create_header(
    secret_key: &SecretKey,
    public_key: &[u8; 65],
    secp: &Secp256k1<All>,
    digest: &Message,
) -> String {
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
