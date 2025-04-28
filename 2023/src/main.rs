use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use didkit::ssi::ldp::ProofSuiteType;
use didkit::ssi::vc::URI;
use didkit::{
    generate_proof, get_verification_method, ContextLoader, Error, LinkedDataProofOptions, Source,
    VerifiableCredential, DID_METHODS, JWK,
};

use iso8601_timestamp::Timestamp;
use serde::{Deserialize, Serialize};
use std::{thread, time};
use async_std::task;


#[get("/")]
async fn hello() -> impl Responder {
    task::sleep(time::Duration::from_secs(5)).await;
    HttpResponse::Ok().body("Hello world - from rust!")
}

#[post("/echo")]
async fn echo(req_body: String) -> impl Responder {
    HttpResponse::Ok().body(req_body)
}

async fn manual_hello() -> impl Responder {
    thread::sleep(time::Duration::from_secs(5));
    HttpResponse::Ok().body("Hey there!")
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Stamp {
    pub issuer: String,
    pub issuanceDate: Timestamp,
    pub expirationDate: Timestamp,
    // pub credentialSubject: CredentialSubject,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // let key = JWK::generate_ed25519();
    // jwk.
    let jwk = "{\"kty\":\"EC\",\"crv\":\"secp256k1\",\"x\":\"ZPtNh7BFWk8YzFVBysUJ3kW8lT9RBBS7oQao8SZhsas\",\"y\":\"KTikFckCaj64QnTrKi8QwqCO1oDXAcq4aHnTe3r07os\",\"d\":\"mYFX2Z9HEZseQ89gHbAVF9bZVBV-cSX6mPhjXTyJFeo\"}";

    let key: JWK = serde_json::from_str(jwk).unwrap();
    println!("JWK: {:#?}", key);

    let did_result = DID_METHODS
        .generate(&Source::KeyAndPattern(&key, "ethr"))
        .ok_or(Error::UnableToGenerateDID);
    println!("DID: is error: {:#?}", did_result.is_err());
    let did = did_result.unwrap();
    
    println!("DID: {:#?}", did);

    // let verification_method = didkit.key_to_verification_method("ethr", JWK)
    // print("verification_method:", verification_method)

    let did_resolver = DID_METHODS.to_resolver();

    let verification_method = get_verification_method(&did, did_resolver)
        .await
        .ok_or(Error::UnableToGetVerificationMethod)
        .unwrap();
    println!("Verification method: {:#?}", verification_method);

    let credential_str = r#"
    {
        "type": ["VerifiableCredential"],
        "issuer": "did:ethr:0x0e65d9769849f9b692afdf7c71f41eeb28360bbf",
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/vc/status-list/2021/v1"
        ],
        "issuanceDate": "2022-07-19T10:42:24.883Z",
        "expirationDate": "2022-10-17T10:42:24.883Z",
        "credentialSubject": {
            "@context": {
                "hash": "https://schema.org/Text",
                "provider": "https://schema.org/Text",
                "metaPointer": "https://schema.org/URL",
                "customInfo": "https://schema.org/Thing"
            },
            "id": "did:pkh:eip155:1:0x12FeD9f987bc340c6bE43fD80aD641E8cD740682",
            "hash": "v0.0.0:AjcRjxx7Hp3PKPSNwPeBJjR21pLyA14CVeQ1XijzxUc=",
            "provider": "Twitter",
            "metaPointer": "https://gitcoin.co/docs.html",
            "customInfo": {
                "field1": "value"
            }
        },
        "credentialStatus": {
            "id": "https://example.edu/credentials/status/3#94567",
            "type": "StatusList2021Entry",
            "statusPurpose": "revocation",
            "statusListIndex": "94567",
            "statusListCredential": "https://example.edu/credentials/status/3"
        }
    }"#;
    let mut credential: VerifiableCredential = serde_json::from_str(credential_str).unwrap();
    let mut options = LinkedDataProofOptions::default();

    options.type_ = Some(ProofSuiteType::EthereumEip712Signature2021); // "EthereumEip712Signature2021"
    options.verification_method = Some(URI::String(verification_method));
    options.created = None;
    options.challenge = None;
    options.domain = None;
    options.checks = None;
    options.eip712_domain = None;
    options.cryptosuite = None;

    let jwk_opt = Some(key);
    let mut context_loader = ContextLoader::default();
    println!("geri -> ProofFormat::LDP");
    println!("geri -> credential {:#?}", credential);
    println!("geri -> jwk_opt {:#?}", jwk_opt);
    println!("geri -> options {:#?}", options);
    // println!("geri -> options {:#?}", did_resolver);

    let proof_result = generate_proof(
        &credential,
        jwk_opt.as_ref(),
        options,
        did_resolver,
        &mut context_loader,
        None,
    )
    .await;

    if (proof_result.is_err()) {
        println!("Proof error: {:#?}", proof_result.err());
    } else {
        let proof = proof_result.unwrap();
        println!("Proof: {:#?}", proof);

        credential.add_proof(proof);
        let cred = serde_json::to_string_pretty(&credential)?;
        println!("Credential: {cred}");
    }

    // options = {
    //     # "proofPurpose": "assertionMethod",
    //     "type": "EthereumEip712Signature2021",
    //     "verificationMethod": verification_method,
    // }

    // let did = key_to_did("dewkhwio").await;
    // key.
    // DIDMethod .key_to_did(&JWK::generate_ed25519()).unwrap();

    HttpServer::new(|| {
        App::new()
            .service(hello)
            .service(echo)
            .route("/hey", web::get().to(manual_hello))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
