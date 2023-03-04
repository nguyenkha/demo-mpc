use std::iter;

use curv::arithmetic::Converter;
use neon::prelude::*;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use curv::cryptographic_primitives::proofs::sigma_valid_pedersen::PedersenProof;
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof;
use curv::BigInt;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::*;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::LocalKey;
use multi_party_ecdsa::utilities::mta::{MessageA, MessageB};
use multi_party_ecdsa::utilities::zk_pdl_with_slack::PDLwSlackProof;
use sha2::Sha256;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secp256k1KeyGenStage1Input {
    pub index: u16,
    pub use_safe_prime: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secp256k1KeyGenStage1Output {
    pub key: Keys,
    pub bc1: KeyGenBroadcastMessage1,
    pub decom1: KeyGenDecommitMessage1,
}

fn secp256k1_keygen_stage1(mut cx: FunctionContext) -> JsResult<JsString> {
    let json: String = cx.argument::<JsString>(0)?.value(&mut cx);
    let input: Secp256k1KeyGenStage1Input = serde_json::from_str(&json).unwrap();
    let key = if input.use_safe_prime {
        Keys::create_safe_prime(usize::from(input.index))
    } else {
        Keys::create(usize::from(input.index))
    };
    let (bc1, decom1) =
        key.phase1_broadcast_phase3_proof_of_correct_key_proof_of_correct_h1h2();
    Ok(cx.string(&serde_json::to_string(&Secp256k1KeyGenStage1Output {
        key,
        bc1,
        decom1,
    }).unwrap()))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secp256k1KeyGenStage2Input {
    pub key: Keys,
    pub bc1s: Vec<KeyGenBroadcastMessage1>,
    pub decom1s: Vec<KeyGenDecommitMessage1>,
    pub threshold: u16,
    pub share_count: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secp256k1KeyGenStage2Output {
    pub vss: (VerifiableSS<Secp256k1>, Vec<Scalar<Secp256k1>>, usize),
}

fn secp256k1_keygen_stage2(mut cx: FunctionContext) -> JsResult<JsString> {
    let json: String = cx.argument::<JsString>(0)?.value(&mut cx);
    let input: Secp256k1KeyGenStage2Input = serde_json::from_str(&json).unwrap();
    let params = Parameters {
        threshold: input.threshold,
        share_count: input.share_count,
    };
    let vss = 
        input.key.phase1_verify_com_phase3_verify_correct_key_verify_dlog_phase2_distribute(&params, &input.decom1s, &input.bc1s).unwrap();
    Ok(cx.string(&serde_json::to_string(&Secp256k1KeyGenStage2Output {
        vss,
    }).unwrap()))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secp256k1KeyGenStage3Input {
    pub key: Keys,
    pub ys: Vec<Point<Secp256k1>>,
    pub vss_schemes: Vec<VerifiableSS<Secp256k1>>,
    pub party_shares: Vec<Scalar<Secp256k1>>,
    pub threshold: u16,
    pub share_count: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secp256k1KeyGenStage3Output {
    pub shared_key: SharedKeys,
    pub dlog_proof: DLogProof<Secp256k1, Sha256>,
}

fn secp256k1_keygen_stage3(mut cx: FunctionContext) -> JsResult<JsString> {
    let json: String = cx.argument::<JsString>(0)?.value(&mut cx);
    let input: Secp256k1KeyGenStage3Input = serde_json::from_str(&json).unwrap();
    let params = Parameters {
        threshold: input.threshold,
        share_count: input.share_count,
    };
    let (shared_key, dlog_proof) = 
        input.key.phase2_verify_vss_construct_keypair_phase3_pok_dlog(&params, &input.ys, &input.party_shares, &input.vss_schemes, input.key.party_index).unwrap();
    Ok(cx.string(&serde_json::to_string(&Secp256k1KeyGenStage3Output {
        shared_key,
        dlog_proof,
    }).unwrap()))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secp256k1KeyGenStage4Input {
    pub ys: Vec<Point<Secp256k1>>,
    pub vss_schemes: Vec<VerifiableSS<Secp256k1>>,
    pub dlog_proofs: Vec<DLogProof<Secp256k1, Sha256>>,
    pub threshold: u16,
    pub share_count: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secp256k1KeyGenStage4Output {}

fn secp256k1_keygen_stage4(mut cx: FunctionContext) -> JsResult<JsString> {
    let json: String = cx.argument::<JsString>(0)?.value(&mut cx);
    let input: Secp256k1KeyGenStage4Input = serde_json::from_str(&json).unwrap();
    let params = Parameters {
        threshold: input.threshold,
        share_count: input.share_count,
    };
    Keys::verify_dlog_proofs_check_against_vss(
        &params,
        &input.dlog_proofs,
        &input.ys,
        &input.vss_schemes,
    ).unwrap();
    Ok(cx.string(&serde_json::to_string(&Secp256k1KeyGenStage4Output {}).unwrap()))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secp256k1ConstructPrivateKeyInput {
    pub vss_scheme: VerifiableSS<Secp256k1>,
    pub parties: Vec<u16>,
    pub xs: Vec<Scalar<Secp256k1>>,
}

fn secp256k1_construct_private_key(mut cx: FunctionContext) -> JsResult<JsString> {
    let json: String = cx.argument::<JsString>(0)?.value(&mut cx);
    let input: Secp256k1ConstructPrivateKeyInput = serde_json::from_str(&json).unwrap();
    let parties: Vec<u16> = input.parties.iter().map(|&i| i - 1).collect();
    let x = input.vss_scheme.reconstruct(&parties, &input.xs);
    Ok(cx.string(&serde_json::to_string(&x).unwrap()))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secp256k1SignStage1Input {
    pub index: u16,
    pub parties: Vec<u16>,
    pub local_key: LocalKey<Secp256k1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secp256k1SignStage1Output {
    pub m_a: (MessageA, BigInt),
    pub sign_key: SignKeys,
    pub bc1: SignBroadcastPhase1,
    pub decom1: SignDecommitPhase1,
}

fn secp256k1_sign_stage1(mut cx: FunctionContext) -> JsResult<JsString> {
    let json: String = cx.argument::<JsString>(0)?.value(&mut cx);
    let input: Secp256k1SignStage1Input = serde_json::from_str(&json).unwrap();
    let parties: Vec<usize> = input.parties.iter().map(|&i|usize::from(i) - 1).collect();
    let sign_key = SignKeys::create(
        &input.local_key.keys_linear.x_i,
        &input.local_key.vss_scheme,
        usize::from(input.parties[usize::from(input.index - 1)]) - 1,
        &parties,
    );
    let (bc1, decom1) = sign_key.phase1_broadcast();

    let party_ek = &input.local_key.paillier_key_vec[usize::from(input.local_key.i - 1)].clone();
    let m_a = MessageA::a(&sign_key.k_i, &party_ek, &input.local_key.h1_h2_n_tilde_vec);

    Ok(cx.string(&serde_json::to_string(&Secp256k1SignStage1Output {
        sign_key,
        m_a,
        bc1,
        decom1,
    }).unwrap()))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secp256k1SignStage2Input {
    pub index: u16,
    pub parties: Vec<u16>,
    pub local_key: LocalKey<Secp256k1>,
    pub m_as: Vec<MessageA>,
    pub sign_key: SignKeys,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secp256k1SignStage2Output {
    pub betas: Vec<Scalar<Secp256k1>>,
    pub nis: Vec<Scalar<Secp256k1>>,
    pub m_b_gammas: Vec<MessageB>,
    pub m_b_ws: Vec<MessageB>,
}

fn secp256k1_sign_stage2(mut cx: FunctionContext) -> JsResult<JsString> {
    let json: String = cx.argument::<JsString>(0)?.value(&mut cx);
    let input: Secp256k1SignStage2Input = serde_json::from_str(&json).unwrap();

    let mut m_b_gammas = Vec::new();
    let mut betas = Vec::new();
    let mut m_b_ws = Vec::new();
    let mut nis = Vec::new();

    let ttag = input.parties.len();
    let l_s: Vec<_> = input
        .parties
        .iter()
        .cloned()
        .map(|i| usize::from(i) - 1)
        .collect();
    let i = usize::from(input.index - 1);
    for j in 0..ttag - 1 {
        let ind = if j < i { j } else { j + 1 };

        let (m_b_gamma, beta_gamma, _beta_randomness, _beta_tag) = MessageB::b(
            &input.sign_key.gamma_i,
            &input.local_key.paillier_key_vec[l_s[ind]],
            input.m_as[ind].clone(),
            &input.local_key.h1_h2_n_tilde_vec,
        ).unwrap();

        let (m_b_w, beta_wi, _, _) = MessageB::b(
            &input.sign_key.w_i,
            &input.local_key.paillier_key_vec[l_s[ind]],
            input.m_as[ind].clone(),
            &input.local_key.h1_h2_n_tilde_vec,
        ).unwrap();

        m_b_gammas.push(m_b_gamma);
        betas.push(beta_gamma);
        m_b_ws.push(m_b_w);
        nis.push(beta_wi);
    }

    Ok(cx.string(&serde_json::to_string(&Secp256k1SignStage2Output {
        nis,
        betas,
        // Send P2P
        m_b_gammas,
        m_b_ws,
    }).unwrap()))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secp256k1SignStage3Input {
    pub index: u16,
    pub parties: Vec<u16>,
    pub local_key: LocalKey<Secp256k1>,
    pub sign_key: SignKeys,
    pub nis: Vec<Scalar<Secp256k1>>,
    pub betas: Vec<Scalar<Secp256k1>>,
    pub m_b_gammas: Vec<MessageB>,
    pub m_b_ws: Vec<MessageB>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secp256k1SignStage3Output {
    pub delta_i: Scalar<Secp256k1>,
    pub t_i: Point<Secp256k1>,
    pub l_i: Scalar<Secp256k1>,
    pub sigma_i: Scalar<Secp256k1>,
    pub t_i_proof: PedersenProof<Secp256k1, Sha256>,
}

fn secp256k1_sign_stage3(mut cx: FunctionContext) -> JsResult<JsString> {
    let json: String = cx.argument::<JsString>(0)?.value(&mut cx);
    let input: Secp256k1SignStage3Input = serde_json::from_str(&json).unwrap();

    let mut alpha_vec = Vec::new();
    let mut miu_vec = Vec::new();

    let ttag = input.parties.len();
    let index = usize::from(input.index) - 1;
    let l_s: Vec<_> = input
        .parties
        .iter()
        .cloned()
        .map(|i| usize::from(i) - 1)
        .collect();
    let g_w_vec = SignKeys::g_w_vec(
        &input.local_key.pk_vec[..],
        &l_s[..],
        &input.local_key.vss_scheme,
    );
    for j in 0..ttag - 1 {
        let ind = if j < index { j } else { j + 1 };
        let m_b = input.m_b_gammas[j].clone();

        let alpha_ij_gamma = m_b
            .verify_proofs_get_alpha(&input.local_key.paillier_dk, &input.sign_key.k_i)
            .unwrap();
        let m_b = input.m_b_ws[j].clone();
        let alpha_ij_wi = m_b
            .verify_proofs_get_alpha(&input.local_key.paillier_dk, &input.sign_key.k_i)
            .unwrap();
        // How to add BIP32
        assert_eq!(m_b.b_proof.pk, g_w_vec[ind]); //TODO: return error

        alpha_vec.push(alpha_ij_gamma.0);
        miu_vec.push(alpha_ij_wi.0);
    }

    let delta_i = input.sign_key.phase2_delta_i(&alpha_vec, &input.betas);

    let sigma_i = input.sign_key.phase2_sigma_i(&miu_vec, &input.nis);
    let (t_i, l_i, t_i_proof) = SignKeys::phase3_compute_t_i(&sigma_i);

    Ok(cx.string(&serde_json::to_string(&Secp256k1SignStage3Output {
        delta_i,
        t_i,
        l_i,
        sigma_i,
        t_i_proof,
    }).unwrap()))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secp256k1SignStage4Input {
    pub parties: Vec<u16>,
    pub deltas: Vec<Scalar<Secp256k1>>,
    pub ts: Vec<Point<Secp256k1>>,
    pub t_proofs: Vec<PedersenProof<Secp256k1, Sha256>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secp256k1SignStage4Output {
    pub delta_inv: Scalar<Secp256k1>,
}

fn secp256k1_sign_stage4(mut cx: FunctionContext) -> JsResult<JsString> {
    let json: String = cx.argument::<JsString>(0)?.value(&mut cx);
    let input: Secp256k1SignStage4Input = serde_json::from_str(&json).unwrap();

    for i in 0..input.ts.len() {
        assert_eq!(input.ts[i], input.t_proofs[i].com);
    }

    let delta_inv = SignKeys::phase3_reconstruct_delta(&input.deltas);
    let ttag = input.parties.len();
    for proof in input.t_proofs.iter().take(ttag) {
        PedersenProof::verify(proof).unwrap();
    }

    Ok(cx.string(&serde_json::to_string(&Secp256k1SignStage4Output {
        delta_inv,
    }).unwrap()))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secp256k1SignStage5Input {
    pub index: u16,
    pub parties: Vec<u16>,
    pub local_key: LocalKey<Secp256k1>,
    pub sign_key: SignKeys,
    pub m_a: (MessageA, BigInt),
    pub m_b_gammas: Vec<MessageB>,
    pub bc1s: Vec<SignBroadcastPhase1>,
    pub delta_inv: Scalar<Secp256k1>,
    pub decom1s: Vec<SignDecommitPhase1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secp256k1SignStage5Output {
    pub r: Point<Secp256k1>,
    pub r_dash: Point<Secp256k1>,
    pub phase5_proofs: Vec<PDLwSlackProof>,
}

fn secp256k1_sign_stage5(mut cx: FunctionContext) -> JsResult<JsString> {
    let json: String = cx.argument::<JsString>(0)?.value(&mut cx);
    let input: Secp256k1SignStage5Input = serde_json::from_str(&json).unwrap();

    let ttag = input.parties.len();
    let b_proof_vec: Vec<_> = (0..ttag - 1).map(|i| &input.m_b_gammas[i].b_proof).collect();
    let r = SignKeys::phase4(
        &input.delta_inv,
        &b_proof_vec[..],
        input.decom1s.clone(),
        &input.bc1s,
        usize::from(input.index - 1),
    ).unwrap();

    let r_dash = &r * &input.sign_key.k_i;

    // each party sends first message to all other parties
    let mut phase5_proofs = Vec::new();
    let l_s: Vec<_> = input
        .parties
        .iter()
        .cloned()
        .map(|i| usize::from(i) - 1)
        .collect();
    let index = usize::from(input.index - 1);
    for j in 0..ttag - 1 {
        let ind = if j < index { j } else { j + 1 };
        let proof = LocalSignature::phase5_proof_pdl(
            &r_dash,
            &r,
            &input.m_a.0.c,
            &input.local_key.paillier_key_vec[l_s[index]],
            &input.sign_key.k_i,
            &input.m_a.1,
            &input.local_key.h1_h2_n_tilde_vec[l_s[ind]],
        );

        phase5_proofs.push(proof);
    }

    Ok(cx.string(&serde_json::to_string(&Secp256k1SignStage5Output {
        r,
        r_dash,
        phase5_proofs,
    }).unwrap()))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secp256k1SignStage6Input {
    pub index: u16,
    pub parties: Vec<u16>,
    pub local_key: LocalKey<Secp256k1>,
    pub m_as: Vec<MessageA>,
    pub t_i: Point<Secp256k1>,
    pub l_i: Scalar<Secp256k1>,
    pub sigma_i: Scalar<Secp256k1>,
    pub r: Point<Secp256k1>,
    pub r_dashes: Vec<Point<Secp256k1>>,
    pub phase5_proofss: Vec<Vec<PDLwSlackProof>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secp256k1SignStage6Output {
    pub s_i:Point<Secp256k1>,
    pub homo_elgamal_proof: HomoELGamalProof<Secp256k1, Sha256>,
}

fn secp256k1_sign_stage6(mut cx: FunctionContext) -> JsResult<JsString> {
    let json: String = cx.argument::<JsString>(0)?.value(&mut cx);
    let input: Secp256k1SignStage6Input = serde_json::from_str(&json).unwrap();

    let l_s: Vec<_> = input
        .parties
        .iter()
        .cloned()
        .map(|i| usize::from(i) - 1)
        .collect();
    let ttag = input.parties.len();
    for i in 0..ttag {
        LocalSignature::phase5_verify_pdl(
            &input.phase5_proofss[i],
            &input.r_dashes[i],
            &input.r,
            &input.m_as[i].c,
            &input.local_key.paillier_key_vec[l_s[i]],
            &input.local_key.h1_h2_n_tilde_vec,
            &l_s,
            i,
        ).unwrap();
    }
    LocalSignature::phase5_check_R_dash_sum(&input.r_dashes).unwrap();

    let (s_i, homo_elgamal_proof) = LocalSignature::phase6_compute_S_i_and_proof_of_consistency(
        &input.r,
        &input.t_i,
        &input.sigma_i,
        &input.l_i,
    );

    Ok(cx.string(&serde_json::to_string(&Secp256k1SignStage6Output {
        s_i,
        homo_elgamal_proof,
    }).unwrap()))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompletedOfflineStage {
    index: u16,
    local_key: LocalKey<Secp256k1>,
    sign_key: SignKeys,
    ts: Vec<Point<Secp256k1>>,
    r: Point<Secp256k1>,
    sigma_i: Scalar<Secp256k1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secp256k1SignStage7Input {
    pub ss: Vec<Point<Secp256k1>>,
    pub homo_elgamal_proofs: Vec<HomoELGamalProof<Secp256k1, Sha256>>,
    pub parties: Vec<u16>,
    pub completed_offline_stage: CompletedOfflineStage,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secp256k1SignStage7Output {}

fn secp256k1_sign_stage7(mut cx: FunctionContext) -> JsResult<JsString> {
    let json: String = cx.argument::<JsString>(0)?.value(&mut cx);
    let input: Secp256k1SignStage7Input = serde_json::from_str(&json).unwrap();

    let r_vec: Vec<_> = iter::repeat(input.completed_offline_stage.r.clone())
        .take(input.parties.len())
        .collect();

    LocalSignature::phase6_verify_proof(
        &input.ss,
        &input.homo_elgamal_proofs,
        &r_vec,
        &input.completed_offline_stage.ts,
    ).unwrap();
    // TODO: BIP32 check
    LocalSignature::phase6_check_S_i_sum(&input.completed_offline_stage.local_key.y_sum_s, &input.ss).unwrap();

    Ok(cx.string(&serde_json::to_string(&Secp256k1SignStage7Output {}).unwrap()))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secp256k1SignStage8Input {
    pub completed_offline_stage: CompletedOfflineStage,
    pub message: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secp256k1SignStage8Output {
    pub local_signature: LocalSignature,
    pub partial_signature: Scalar<Secp256k1>,
}

fn secp256k1_sign_stage8(mut cx: FunctionContext) -> JsResult<JsString> {
    let json: String = cx.argument::<JsString>(0)?.value(&mut cx);
    let input: Secp256k1SignStage8Input = serde_json::from_str(&json).unwrap();

    let local_signature = LocalSignature::phase7_local_sig(
        &input.completed_offline_stage.sign_key.k_i,
        &BigInt::from_bytes(&input.message),
        &input.completed_offline_stage.r,
        &input.completed_offline_stage.sigma_i,
        &input.completed_offline_stage.local_key.y_sum_s,
    );
    let partial_signature = local_signature.s_i.clone();
    
    Ok(cx.string(&serde_json::to_string(&Secp256k1SignStage8Output {
        local_signature,
        partial_signature,
    }).unwrap()))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secp256k1SignStage9Input {
    pub local_signature: LocalSignature,
    pub partial_signatures: Vec<Scalar<Secp256k1>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secp256k1SignStage9Output {
    pub signature: SignatureRecid,
}

fn secp256k1_sign_stage9(mut cx: FunctionContext) -> JsResult<JsString> {
    let json: String = cx.argument::<JsString>(0)?.value(&mut cx);
    let input: Secp256k1SignStage9Input = serde_json::from_str(&json).unwrap();
    let signature = input.local_signature.output_signature(&input.partial_signatures).unwrap();
    Ok(cx.string(&serde_json::to_string(&Secp256k1SignStage9Output {
        signature,
    }).unwrap()))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secp256k1TweakKeyInput {
    pub index: u16,
    pub local_key: LocalKey<Secp256k1>,
    pub il: Scalar<Secp256k1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Secp256k1TweakKeyOutput {
    pub new_local_key: LocalKey<Secp256k1>,
}

fn secp256k1_tweak_key(mut cx: FunctionContext) -> JsResult<JsString> {
    let json: String = cx.argument::<JsString>(0)?.value(&mut cx);
    let input: Secp256k1TweakKeyInput = serde_json::from_str(&json).unwrap();
    let mut new_local_key = input.local_key.clone();
    let il_point = Point::generator() * input.il.clone();
    if input.index == 1 {
        new_local_key.keys_linear.x_i = new_local_key.keys_linear.x_i.clone() + input.il.clone();
    }
    new_local_key.keys_linear.y = new_local_key.keys_linear.y.clone() + il_point.clone();
    new_local_key.vss_scheme.commitments[0] = new_local_key.vss_scheme.commitments[0].clone() + il_point.clone();
    new_local_key.pk_vec[0] = new_local_key.pk_vec[0].clone() + il_point.clone();
    new_local_key.y_sum_s = new_local_key.y_sum_s.clone() + il_point.clone();
    Ok(cx.string(&serde_json::to_string(&Secp256k1TweakKeyOutput {
        new_local_key,
    }).unwrap()))
}

fn hello(mut cx: FunctionContext) -> JsResult<JsString> {
    let data = cx.argument::<JsString>(0)?;
    let s = &data.value(&mut cx);
    Ok(cx.string(&s))
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("hello", hello)?;
    cx.export_function("secp256k1_keygen_stage1", secp256k1_keygen_stage1)?;
    cx.export_function("secp256k1_keygen_stage2", secp256k1_keygen_stage2)?;
    cx.export_function("secp256k1_keygen_stage3", secp256k1_keygen_stage3)?;
    cx.export_function("secp256k1_keygen_stage4", secp256k1_keygen_stage4)?;
    cx.export_function("secp256k1_construct_private_key", secp256k1_construct_private_key)?;
    cx.export_function("secp256k1_sign_stage1", secp256k1_sign_stage1)?;
    cx.export_function("secp256k1_sign_stage2", secp256k1_sign_stage2)?;
    cx.export_function("secp256k1_sign_stage3", secp256k1_sign_stage3)?;
    cx.export_function("secp256k1_sign_stage4", secp256k1_sign_stage4)?;
    cx.export_function("secp256k1_sign_stage5", secp256k1_sign_stage5)?;
    cx.export_function("secp256k1_sign_stage6", secp256k1_sign_stage6)?;
    cx.export_function("secp256k1_sign_stage7", secp256k1_sign_stage7)?;
    cx.export_function("secp256k1_sign_stage8", secp256k1_sign_stage8)?;
    cx.export_function("secp256k1_sign_stage9", secp256k1_sign_stage9)?;
    cx.export_function("secp256k1_tweak_key", secp256k1_tweak_key)?;
    Ok(())
}
