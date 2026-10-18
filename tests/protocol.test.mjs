import test from 'node:test';
import assert from 'node:assert/strict';
import {
  BN254_FIELD_MODULUS_Q,
  BN254_SCALAR_MODULUS_R,
  G1_POINT_BYTE_LENGTH,
  G2_POINT_BYTE_LENGTH,
  GROTH16_PROOF_BYTE_LENGTH,
  serializeG1Point,
  deserializeG1Point,
  serializeG2Point,
  deserializeG2Point,
  serializeProof,
  deserializeProof,
  proofToCalldata,
  validateScalarFieldElement
} from '../dist/index.js';

test('Groth16 Protocol: BN254 Curve Constants Invariants', () => {
  assert.equal(G1_POINT_BYTE_LENGTH, 64);
  assert.equal(G2_POINT_BYTE_LENGTH, 128);
  assert.equal(GROTH16_PROOF_BYTE_LENGTH, 256);
  assert.equal(
    BN254_FIELD_MODULUS_Q,
    21888242871839275222246405745257275088696311157297823662689037894645226208583n
  );
  assert.equal(
    BN254_SCALAR_MODULUS_R,
    21888242871839275222246405745257275088548364400416034343698204186575808495617n
  );
});

test('Groth16 Protocol: G1 & G2 Point Wire Serialization Round-Trip', () => {
  const g1 = { x: 1n, y: 2n };
  const g1Bytes = serializeG1Point(g1);
  assert.equal(g1Bytes.length, 64);
  const g1Decoded = deserializeG1Point(g1Bytes);
  assert.equal(g1Decoded.x, 1n);
  assert.equal(g1Decoded.y, 2n);

  const g2 = {
    x: [10n, 20n],
    y: [30n, 40n]
  };
  const g2Bytes = serializeG2Point(g2);
  assert.equal(g2Bytes.length, 128);
  const g2Decoded = deserializeG2Point(g2Bytes);
  assert.equal(g2Decoded.x[0], 10n);
  assert.equal(g2Decoded.x[1], 20n);
  assert.equal(g2Decoded.y[0], 30n);
  assert.equal(g2Decoded.y[1], 40n);
});

test('Groth16 Protocol: Full Proof Serialization & Calldata Generation', () => {
  const proof = {
    a: { x: 100n, y: 200n },
    b: { x: [300n, 400n], y: [500n, 600n] },
    c: { x: 700n, y: 800n }
  };
  const proofBytes = serializeProof(proof);
  assert.equal(proofBytes.length, 256);

  const proofDecoded = deserializeProof(proofBytes);
  assert.equal(proofDecoded.a.x, 100n);
  assert.equal(proofDecoded.b.x[1], 400n);
  assert.equal(proofDecoded.c.y, 800n);

  const publicInputs = [42n, 1337n];
  const calldata = proofToCalldata(proof, publicInputs);

  assert.equal(calldata.a.length, 2);
  assert.equal(calldata.b.length, 2);
  assert.equal(calldata.c.length, 2);
  assert.equal(calldata.input.length, 2);

  // Check snarkjs/EIP-197 G2 coordinate ordering: b[0] is [X1, X0]
  assert.equal(calldata.b[0][0], '0x' + (400n).toString(16).padStart(64, '0'));
  assert.equal(calldata.b[0][1], '0x' + (300n).toString(16).padStart(64, '0'));
});

test('Groth16 Protocol: Adversarial Negative Control - Scalar Overflow Rejection', () => {
  const invalidScalar = BN254_SCALAR_MODULUS_R + 1n;
  assert.throws(
    () => validateScalarFieldElement(invalidScalar),
    /SCALAR_FIELD_OVERFLOW/
  );
});

test('Groth16 Protocol: Adversarial Negative Control - Truncated Wire Bytes Rejection', () => {
  const truncated = new Uint8Array(100);
  assert.throws(
    () => deserializeProof(truncated),
    /INVALID_PROOF_LENGTH/
  );
});
