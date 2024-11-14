use std::str::FromStr;

use alloy::{
    consensus::{SignableTransaction, TxEip1559, TxEnvelope},
    eips::eip2718::{Decodable2718, Encodable2718},
    primitives::{address, hex, keccak256, FixedBytes, TxKind, U256},
    rlp::{BytesMut, Decodable, Encodable},
    signers::{local::PrivateKeySigner, Signer},
};
use rand::Rng;
use reqwest::{Client, Error};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};

const SLOT_DURATION: u64 = 12;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // bolt-sidecar-1-lighthouse-geth
    let sidecar_port = 32898;
    // el-1-geth-lighthouse
    let el_rpc = "http://127.0.0.1:32876";

    let client = Client::new();
    let signer = PrivateKeySigner::from_str(
        "bcdf20249abf0ed6d944c0288fad489e33f66b3960d9e6229c1cd214ed3bbe31",
    )?;

    let balance = get_balance(el_rpc, &*signer.address().to_string()).await?;
    dbg!(balance);

    let (tx, raw) = create_tx(&signer, &client, el_rpc).await?;
    dbg!(&raw);

    // // Seems to decode properly
    // // raw_decode(raw.clone());

    let slot = calculate_slot(SLOT_DURATION * 5).await?;
    let digest = message_digest(tx, slot);
    let header = create_header(&signer, &digest).await?;
    dbg!(&header);

    match send_request(sidecar_port, &client, (raw, slot, header)).await {
        Ok(response) => {
            println!("Response: {:?}", response);
        }
        Err(err) => {
            eprintln!("Request failed: {:?}", err);
        }
    }

    Ok(())
}

async fn get_balance(rpc_url: &str, address: &str) -> anyhow::Result<u128> {
    let client = Client::new();

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_getBalance",
        "params": [address, "latest"],
        "id": 1
    });

    let response: Value = client
        .post(rpc_url)
        .json(&request)
        .send()
        .await?
        .json()
        .await?;

    // Parse the balance (which is returned as a hex string)
    if let Some(balance_str) = response.get("result").and_then(|r| r.as_str()) {
        let balance = u128::from_str_radix(balance_str.trim_start_matches("0x"), 16)?;
        Ok(balance)
    } else {
        Err(anyhow::anyhow!("No balance found"))
    }
}

async fn create_tx(
    signer: &PrivateKeySigner,
    client: &Client,
    el_rpc: &str,
) -> anyhow::Result<(TxEnvelope, String)> {
    let mut rng = rand::thread_rng();

    let nonce = query(
        &client,
        el_rpc,
        "eth_getTransactionCount",
        vec![format!("{:?}", signer.address()), "finalized".to_string()],
    )
    .await?;
    dbg!(nonce);
    let min_priority_fee = query(&client, el_rpc, "eth_maxPriorityFeePerGas", vec![]).await?;
    let max_priority_fee_per_gas = min_priority_fee;
    let max_fee_per_gas = max_priority_fee_per_gas + 66_371;

    let tx = TxEip1559 {
        chain_id: 3151908,
        nonce: nonce as u64,
        gas_limit: rng.gen_range(21000..=100000),
        to: TxKind::Call(address!("E25583099BA105D9ec0A67f5Ae86D90e50036425")),
        value: U256::from(rng.gen_range(0.0001..=0.0002)),
        max_fee_per_gas,
        max_priority_fee_per_gas,
        ..Default::default()
    };

    let mut buff = BytesMut::new();
    tx.encode(&mut buff);
    let tx_hash = keccak256(&buff);

    let signature = signer.sign_message(tx_hash.as_ref()).await?;

    let signed_tx = tx.into_signed(signature);
    let envelope = TxEnvelope::Eip1559(signed_tx);
    let raw = hex::encode_prefixed(envelope.encoded_2718());

    Ok((envelope, raw))
}

async fn calculate_slot(seconds_from_now: u64) -> anyhow::Result<u64> {
    let response = reqwest::get("http://127.0.0.1:32886/eth/v1/beacon/headers/head")
        .await?
        .json::<serde_json::Value>()
        .await?;

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

fn message_digest(tx: TxEnvelope, target_slot: u64) -> FixedBytes<32> {
    let mut data = Vec::new();

    data.extend_from_slice(tx.tx_hash().as_slice());
    data.extend_from_slice(&target_slot.to_le_bytes());
    let hash = Keccak256::digest(data);

    FixedBytes::new(hash.into())
}

async fn create_header(
    signer: &PrivateKeySigner,
    digest: &FixedBytes<32>,
) -> anyhow::Result<String> {
    let address = signer.address();
    let signature = signer.sign_hash(digest).await?;
    let encoded_signature = hex::encode(signature.as_bytes());

    Ok(format!("{address}:0x{encoded_signature}"))
}

async fn send_request(
    sidecar_port: u64,
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
        .post(format!("http://127.0.0.1:{}", sidecar_port))
        .header("X-Bolt-Signature", data.2)
        .json(&request_body)
        .send()
        .await?;

    let json_response = response.json().await?;
    Ok(json_response)
}

fn raw_decode(raw: String) {
    let tx = raw.trim_start_matches("0x");
    let tx_bytes = hex::decode(tx).expect("Failed bytes");

    let envelope = TxEnvelope::decode_2718(&mut &tx_bytes[..]).expect("Failed 2718");
    dbg!(envelope);
}

async fn query(
    client: &Client,
    rpc_url: &str,
    method: &str,
    params: Vec<String>,
) -> anyhow::Result<u128> {
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    });

    let response: Value = client
        .post(rpc_url)
        .json(&request)
        .send()
        .await?
        .json()
        .await?;

    if let Some(result) = response.get("result") {
        if let Some(result_str) = result.as_str() {
            match u128::from_str_radix(result_str.trim_start_matches("0x"), 16) {
                Ok(value) => Ok(value),
                Err(e) => Err(anyhow::anyhow!("Failed to parse nonce value: {}", e)),
            }
        } else {
            Err(anyhow::anyhow!("Result is not a valid string"))
        }
    } else {
        Err(anyhow::anyhow!("No 'result' field found in the response"))
    }
}
