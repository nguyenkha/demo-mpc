const EC = require('elliptic').ec;
const ec = new EC('secp256k1');
const Signature = require('elliptic/lib/elliptic/ec/signature');
const ecc = require('tiny-secp256k1')
const { BIP32Factory } = require('bip32');
const bip32 = BIP32Factory(ecc);
const BN = require('bn.js');
const native = require('./bindings.node');

function secp256k1_keygen_stage1(index, useSafePrime) {
  return JSON.parse(native.secp256k1_keygen_stage1(JSON.stringify({
    index,
    use_safe_prime: !!useSafePrime,
  })));
}

function secp256k1_keygen_stage2(key, bc1s, decom1s, threshold, share_count) {
  return JSON.parse(native.secp256k1_keygen_stage2(JSON.stringify({
    key,
    bc1s,
    decom1s,
    threshold,
    share_count,
  })));
}

function secp256k1_keygen_stage3(key, ys, vss_schemes, party_shares, threshold, share_count) {
  return JSON.parse(native.secp256k1_keygen_stage3(JSON.stringify({
    key,
    ys,
    vss_schemes,
    party_shares,
    threshold,
    share_count,
  })));
}

function secp256k1_keygen_stage4(ys, vss_schemes, dlog_proofs, threshold, share_count) {
  return JSON.parse(native.secp256k1_keygen_stage4(JSON.stringify({
    ys,
    vss_schemes,
    dlog_proofs,
    threshold,
    share_count: share_count,
  })));
}

function secp256k1_construct_private_key(vss_scheme, parties, xs) {
  return JSON.parse(native.secp256k1_construct_private_key(JSON.stringify({
    vss_scheme,
    parties,
    xs,
  })));
}

function secp256k1_sign_stage1(index, parties, local_key) {
  return JSON.parse(native.secp256k1_sign_stage1(JSON.stringify({
    index,
    parties,
    local_key,
  })));
}

function secp256k1_sign_stage2(index, parties, local_key, m_as, sign_key) {
  return JSON.parse(native.secp256k1_sign_stage2(JSON.stringify({
    index,
    parties,
    local_key,
    m_as,
    sign_key,
  })));
}

function secp256k1_sign_stage3(index, parties, local_key, sign_key, nis, betas, m_b_gammas, m_b_ws) {
  return JSON.parse(native.secp256k1_sign_stage3(JSON.stringify({
    index,
    parties,
    local_key,
    sign_key,
    nis, 
    betas,
    m_b_gammas,
    m_b_ws,
  })));
}

function secp256k1_sign_stage4(parties, deltas, ts, t_proofs) {
  return JSON.parse(native.secp256k1_sign_stage4(JSON.stringify({
    parties,
    deltas,
    ts,
    t_proofs,
  })));
}

function secp256k1_sign_stage5(index, parties, local_key, sign_key, m_a, m_b_gammas, bc1s, delta_inv, decom1s) {
  return JSON.parse(native.secp256k1_sign_stage5(JSON.stringify({
    index,
    parties,
    local_key,
    sign_key,
    m_a,
    m_b_gammas,
    bc1s,
    delta_inv,
    decom1s,
  })));
}

function secp256k1_sign_stage6(index, parties, local_key, m_as, t_i, l_i, sigma_i, r, r_dashes, phase5_proofss) {
  return JSON.parse(native.secp256k1_sign_stage6(JSON.stringify({
    index,
    parties,
    local_key,
    m_as,
    t_i,
    l_i,
    sigma_i,
    r,
    r_dashes,
    phase5_proofss,
  })));
}

function secp256k1_sign_stage7(ss, homo_elgamal_proofs, parties, completed_offline_stage) {
  return JSON.parse(native.secp256k1_sign_stage7(JSON.stringify({
    ss,
    homo_elgamal_proofs,
    parties,
    completed_offline_stage,
  })));
}

function secp256k1_sign_stage8(completed_offline_stage, message) {
  return JSON.parse(native.secp256k1_sign_stage8(JSON.stringify({
    completed_offline_stage,
    // To array of number
    message: [...message],
  })));
}

function secp256k1_sign_stage9(local_signature, partial_signatures) {
  return JSON.parse(native.secp256k1_sign_stage9(JSON.stringify({
    local_signature,
    partial_signatures,
  })));
}

function secp256k1_tweak_key(index, local_key, il) {
  return JSON.parse(native.secp256k1_tweak_key(JSON.stringify({
    index,
    local_key,
    il,
  })));
}

module.exports = {
  // Wrap object function
  secp256k1_keygen_stage1,
  secp256k1_keygen_stage2,
  secp256k1_keygen_stage3,
  secp256k1_keygen_stage4,
  secp256k1_construct_private_key,
  secp256k1_sign_stage1,
  secp256k1_sign_stage2,
  secp256k1_sign_stage3,
  secp256k1_sign_stage4,
  secp256k1_sign_stage5,
  secp256k1_sign_stage6,
  secp256k1_sign_stage7,
  secp256k1_sign_stage8,
  secp256k1_sign_stage9,
  secp256k1_tweak_key,
};

const { createHash, createHmac } = require('crypto');
const { writeFileSync, readFileSync, write } = require('fs');
const { toASCII } = require('punycode');

// const parties = [1, 2, 3, 4];
// const shareCount = parties.length;
// const threshold = 2;

// console.log('Generate key...');
// const stage1 = parties.map(secp256k1_keygen_stage1);
// const bc1s = stage1.map(s => s.bc1);
// const decom1s = stage1.map(s => s.decom1);
// const keys = stage1.map(s => s.key);
// const ys = decom1s.map(d => d.y_i);

// console.log('Getting vss...');
// const stage2 = keys.map(k => secp256k1_keygen_stage2(k, bc1s, decom1s, threshold, shareCount));
// const vssSchemes = stage2.map(s => s.vss[0]);
// const partySharess = parties.map((_, i) => stage2.map(s => s.vss[1][i]));

// console.log('Contruct keypair...');
// const stage3 = keys.map((k, i) => secp256k1_keygen_stage3(k, ys, vssSchemes, partySharess[i], threshold, shareCount));

// console.log('Get public key...');
// const dlogProofs = stage3.map(s => s.dlog_proof);
// const shareKeys = stage3.map(s => s.shared_key)
// secp256k1_keygen_stage4(ys, vssSchemes, dlogProofs, threshold, shareCount);
// parties.forEach((i, index) => {
//   const publicKey = ec.keyFromPublic(stage3[index].shared_key.y.point).getPublic(true, 'hex');
//   console.log(`From share ${i}: ${publicKey}`);
// });

// console.log('Construct private key...');
// const xs = stage3.map(s => s.shared_key.x_i);
// const result = secp256k1_construct_private_key(vssSchemes[0], parties, xs);
// const privateKey = ec.keyFromPrivate(result.scalar);
// // console.log(result, privateKey);
// const publicKey = privateKey.getPublic(true, 'hex');
// console.log(`To public key key: ${publicKey}`);

// // Save key
// const localKeys = parties.map((i, index) => ({
//   paillier_dk: keys[index].dk,
//   pk_vec: dlogProofs.map(d => d.pk),
//   keys_linear: shareKeys[index],
//   paillier_key_vec: bc1s.map(b => b.e),
//   y_sum_s: shareKeys[index].y,
//   h1_h2_n_tilde_vec: bc1s.map(b => b.dlog_statement),
//   vss_scheme: vssSchemes[index],
//   i,
//   t: threshold,
//   n: shareCount,
// }));

// writeFileSync('keys-3-4.json', JSON.stringify(localKeys));

const keys = JSON.parse(readFileSync('keys-3-4.json', 'utf-8'));
const masterLocalKeys = [keys[0], keys[1], keys[2]];
const parties = masterLocalKeys.map(k => k.i); // [2, 3, 4] // [1, 2, 3]
console.log(parties);

masterLocalKeys.forEach(k => {
  const publicKey = ec.keyFromPublic(k.keys_linear.y.point).getPublic(true, 'hex');
  console.log(`From share ${k.i}: ${publicKey}`);
});

console.log('Construct private key...');
const xs = masterLocalKeys.map(k => k.keys_linear.x_i);
const result = secp256k1_construct_private_key(masterLocalKeys[0].vss_scheme, parties, xs);
const privateKey = ec.keyFromPrivate(result.scalar);
const publicKey = privateKey.getPublic(true, 'hex');
console.log(`To private key: ${privateKey.getPrivate('hex')}`);
console.log(`To public key: ${publicKey}`);

// const il = {
//   curve: 'secp256k1',
//   scalar: [...Buffer.from('52a2b4ac5024276cfbf98c82098aa332a6c7b941f33631f477ab2ca25ac58087', 'hex')],
// };

// const localKeys = masterLocalKeys.map((k, i) => {
//   const { new_local_key } = secp256k1_tweak_key(i, k, il);
//   return new_local_key;
// });

// console.log('PK before', Buffer.from(masterLocalKeys[0].y_sum_s.point).toString('hex'));
// console.log('PK after', Buffer.from(localKeys[0].y_sum_s.point).toString('hex'));

// const xs2 = localKeys.map(k => k.keys_linear.x_i);
// const result2 = secp256k1_construct_private_key(localKeys[0].vss_scheme, parties, xs2);
// const privateKey2 = ec.keyFromPrivate(result2.scalar);
// const publicKey2 = privateKey2.getPublic(true, 'hex');
// console.log('SK construct:', privateKey2.getPrivate('hex'));
// console.log('PK construct:', publicKey2);
// console.log(Buffer.from(localKeys[0].keys_linear.y.point).toString('hex'));

const localKeys = masterLocalKeys;
console.log('Stage 1...');
const stage1 = localKeys.map((k, i) => secp256k1_sign_stage1(i + 1, parties, k));
const mAs = stage1.map(s => s.m_a[0]);
const bc1s = stage1.map(s => s.bc1);
const decom1s = stage1.map(s => s.decom1);
const signKeys = stage1.map(s => s.sign_key);
console.log('Stage 2...');
const stage2 = signKeys.map((k, i) => secp256k1_sign_stage2(i + 1, parties, localKeys[i], mAs, k));
const mBs = parties.map((_, i) => {
  const mBs = stage2[i].m_b_gammas.map((g, j) => [g, stage2[i].m_b_ws[j]]);
  mBs.splice(i, 0, undefined);
  return mBs;
});
const mBss = mBs.map((_, i) => {
  return mBs.map(m => m[i]).filter(m => m);
});
const mBGammass = mBss.map(m => m.map(m => m[0]));
const mBWss = mBss.map(m => m.map(m => m[1]));

console.log('Stage 3...');
const stage3 = signKeys.map((k, i) => secp256k1_sign_stage3(i + 1, parties, localKeys[i], k, stage2[i].nis, stage2[i].betas, mBGammass[i], mBWss[i]));
const deltas = stage3.map(s => s.delta_i);
const ts = stage3.map(s => s.t_i);
const tProofs = stage3.map(s => s.t_i_proof);

console.log('Stage 4...');
const stage4 = parties.map((_, i) => secp256k1_sign_stage4(parties, deltas, ts, tProofs));

console.log('Stage 5...');
const stage5 = signKeys.map((k, i) => secp256k1_sign_stage5(i + 1, parties, localKeys[i], k, stage1[i].m_a, mBGammass[i], bc1s, stage4[i].delta_inv, decom1s));
const rDashes = stage5.map(s => s.r_dash);
const phase5Proofss = stage5.map(s => s.phase5_proofs);

console.log('Stage 6...');
const stage6 = localKeys.map((k, i) => secp256k1_sign_stage6(i + 1, parties, k, mAs, stage3[i].t_i, stage3[i].l_i, stage3[i].sigma_i, stage5[i].r, rDashes, phase5Proofss));
const ss = stage6.map(s => s.s_i);
const homoElgamalProofs = stage6.map(s => s.homo_elgamal_proof);
const completedOfflineStages = parties.map((index, i) => ({
  index,
  local_key: localKeys[i],
  sign_key: signKeys[i],
  ts,
  r: stage5[i].r,
  sigma_i: stage3[i].sigma_i,
}));

console.log('Stage 7...');
completedOfflineStages.map(c => secp256k1_sign_stage7(ss, homoElgamalProofs, parties, c));

console.log('Stage 8...');
const message = createHash('SHA256').update(Buffer.from('Hello world')).digest();
const stage8 = completedOfflineStages.map(c => secp256k1_sign_stage8(c, message));
const partialSignaturess = stage8.map((s, i) => {
  return stage8.filter((_, j) => j !== i).map(s => s.partial_signature);
});

console.log('Stage 9...');
const stage9 = stage8.map((s, i) => secp256k1_sign_stage9(s.local_signature, partialSignaturess[i]));
localKeys.forEach((k, i) => {
  const signature = new Signature({
    r: stage9[i].signature.r.scalar,
    s: stage9[i].signature.s.scalar,
    recoveryParam: stage9[i].signature.recid,
  });
  console.log(`Verify signature ${k.i}: ${privateKey.verify(message, signature) }`);
});

// Generate random root chain code

// const seed = Buffer.from(ec.genKeyPair().getPrivate('hex'), 'hex');
// const chainCode = bip32.fromSeed(seed).chainCode;
// writeFileSync('chain-code', chainCode);
// const chainCode = readFileSync('chain-code');
// const rootPrivateKey = Buffer.from(privateKey.getPrivate('hex'), 'hex');
// const rootPublicKey = Buffer.from(privateKey.getPublic(true, 'hex'), 'hex');
// const masterPublicKey = bip32.fromPublicKey(rootPublicKey, chainCode);
// const masterPrivateKey = bip32.fromPrivateKey(rootPrivateKey, chainCode)
// console.log(masterPublicKey.toBase58());
// console.log(masterPrivateKey.toBase58());
// const childPublicKey = masterPublicKey.derivePath('m/0/0/123');
// const childPrivateKey = masterPrivateKey.derivePath('m/0/0/123');
// console.log('Lib derive', childPublicKey.publicKey.toString('hex'));

// const ILs = [
//   '4d23a99a43595b11c8e84f0943c9d7bc6a082dabe3dce502ed9dde5a2e59d782',
//   '3b473d4c15de91a216cba71963023c80b3b21b521d030c66ecc9eb621abd8529',
//   'ca37cdc5f6ec3ab91c45965f62be8ef443bc4d2aa19ee0c65d15c172e1e4651d',
// ].map(h => Buffer.from(h, 'hex'));

// const c1 = Buffer.from(ecc.pointAddScalar(rootPublicKey, ILs[0]));
// const c2 = Buffer.from(ecc.pointAddScalar(c1, ILs[1]));
// const c3 = Buffer.from(ecc.pointAddScalar(c2, ILs[2]));
// const sum = new BN(ILs[0]).add(new BN(ILs[1])).add(new BN(ILs[2])).mod(ec.n).toBuffer();
// console.log('Sum:', sum.toString('hex'));
// console.log('Step derive:', c3.toString('hex'));
// console.log('Sum derive:', Buffer.from(ecc.pointAddScalar(rootPublicKey, sum)).toString('hex'));
// console.log('Lib derive private key:', childPrivateKey.privateKey.toString('hex'));
// console.log('Sum derive private key:', Buffer.from(ecc.privateAdd(rootPrivateKey, sum)).toString('hex'));

// const c33 = Buffer.from(ecc.pointAddScalar(rootPublicKey, c1));
// console.log(c3.toString('hex'));
// console.log(c33.toString('hex'));

// const data = Buffer.alloc(37);
// rootPublicKey.copy(data, 0);
// data.writeUInt32BE(1, 33);
// const I = createHmac('sha512', chainCode).update(data).digest();
// const IL = I.subarray(0, 32);
// const IR = I.subarray(32);
// console.log('IR:', IR.toString('hex'));
// console.log('Child chain code:', childPublicKey.chainCode.toString('hex'));

// IL, IR = hmac(chain code, public key + index)
// P = G(x)
// P = G(x + IL)
// P = G(x + IL + IL2)
// P child level 1 = P + G(IL)
// P child level 2 = P child level 1 + G(IL1) = P + G(IL1) + G(IL) = P + G(IL1 + IL)
