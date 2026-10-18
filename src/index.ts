/**
 * QMOOSA Zero-Knowledge Cryptography Specification
 * Groth16 Verification Circuits & BN254 (alt_bn128) Protocol Specification
 *
 * Implements standard types, curve parameters, field arithmetic constants,
 * binary wire serialization, and calldata formatting compatible with EIP-197.
 */

import { timingSafeEqual } from 'node:crypto';

/**
 * BN254 / Alt-bn128 Curve Field Constants
 * Curve equation: y^2 = x^3 + 3 over F_q
 */
export const BN254_FIELD_MODULUS_Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
export const BN254_SCALAR_MODULUS_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export const G1_POINT_BYTE_LENGTH = 64;   // 32B X + 32B Y
export const G2_POINT_BYTE_LENGTH = 128;  // 32B X0 + 32B X1 + 32B Y0 + 32B Y1
export const GROTH16_PROOF_BYTE_LENGTH = 256; // G1(64) + G2(128) + G1(64)

export interface G1Point {
  readonly x: bigint;
  readonly y: bigint;
}

export interface G2Point {
  readonly x: readonly [bigint, bigint]; // [c0, c1] in F_q^2
  readonly y: readonly [bigint, bigint]; // [c0, c1] in F_q^2
}

export interface Groth16Proof {
  readonly a: G1Point;
  readonly b: G2Point;
  readonly c: G1Point;
}

export interface Groth16VerifyingKey {
  readonly alpha1: G1Point;
  readonly beta2: G2Point;
  readonly gamma2: G2Point;
  readonly delta2: G2Point;
  readonly ic: readonly G1Point[];
}

export interface Groth16Calldata {
  readonly a: readonly [string, string];
  readonly b: readonly [readonly [string, string], readonly [string, string]];
  readonly c: readonly [string, string];
  readonly input: readonly string[];
}

/**
 * Formats a bigint into a 32-byte 0x-prefixed hex string for EVM calldata.
 */
export function toUint256Hex(val: bigint): string {
  if (val < 0n || val >= BN254_FIELD_MODULUS_Q) {
    throw new Error(`FIELD_ELEMENT_OUT_OF_BOUNDS: ${val.toString()} exceeds BN254 base field modulus`);
  }
  return '0x' + val.toString(16).padStart(64, '0');
}

/**
 * Validates that a public input scalar is strictly less than the scalar field order r.
 */
export function validateScalarFieldElement(scalar: bigint): void {
  if (scalar < 0n || scalar >= BN254_SCALAR_MODULUS_R) {
    throw new Error(`SCALAR_FIELD_OVERFLOW: Scalar ${scalar.toString()} exceeds BN254 scalar field order r`);
  }
}

/**
 * Encodes a bigint into a big-endian 32-byte buffer.
 */
export function bigintTo32Bytes(val: bigint): Uint8Array {
  if (val < 0n || val >= BN254_FIELD_MODULUS_Q) {
    throw new Error(`FIELD_ELEMENT_OVERFLOW: ${val.toString()}`);
  }
  const hex = val.toString(16).padStart(64, '0');
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

/**
 * Decodes a 32-byte big-endian buffer into a bigint.
 */
export function bytes32ToBigint(bytes: Uint8Array): bigint {
  if (bytes.length !== 32) {
    throw new Error(`INVALID_BYTE_LENGTH: Expected 32 bytes, got ${bytes.length}`);
  }
  return BigInt('0x' + Buffer.from(bytes).toString('hex'));
}

/**
 * Serializes a G1 point into uncompressed 64-byte wire representation (32B X || 32B Y).
 */
export function serializeG1Point(pt: G1Point): Uint8Array {
  const out = new Uint8Array(G1_POINT_BYTE_LENGTH);
  out.set(bigintTo32Bytes(pt.x), 0);
  out.set(bigintTo32Bytes(pt.y), 32);
  return out;
}

/**
 * Deserializes an uncompressed 64-byte wire representation into a G1 point.
 */
export function deserializeG1Point(bytes: Uint8Array): G1Point {
  if (!(bytes instanceof Uint8Array) || bytes.length !== G1_POINT_BYTE_LENGTH) {
    throw new Error(`INVALID_G1_LENGTH: Expected ${G1_POINT_BYTE_LENGTH} bytes, got ${bytes?.length}`);
  }
  const x = bytes32ToBigint(bytes.subarray(0, 32));
  const y = bytes32ToBigint(bytes.subarray(32, 64));
  return { x, y };
}

/**
 * Serializes a G2 point into uncompressed 128-byte wire representation (X0 || X1 || Y0 || Y1).
 */
export function serializeG2Point(pt: G2Point): Uint8Array {
  const out = new Uint8Array(G2_POINT_BYTE_LENGTH);
  out.set(bigintTo32Bytes(pt.x[0]), 0);
  out.set(bigintTo32Bytes(pt.x[1]), 32);
  out.set(bigintTo32Bytes(pt.y[0]), 64);
  out.set(bigintTo32Bytes(pt.y[1]), 96);
  return out;
}

/**
 * Deserializes an uncompressed 128-byte wire representation into a G2 point.
 */
export function deserializeG2Point(bytes: Uint8Array): G2Point {
  if (!(bytes instanceof Uint8Array) || bytes.length !== G2_POINT_BYTE_LENGTH) {
    throw new Error(`INVALID_G2_LENGTH: Expected ${G2_POINT_BYTE_LENGTH} bytes, got ${bytes?.length}`);
  }
  const x0 = bytes32ToBigint(bytes.subarray(0, 32));
  const x1 = bytes32ToBigint(bytes.subarray(32, 64));
  const y0 = bytes32ToBigint(bytes.subarray(64, 96));
  const y1 = bytes32ToBigint(bytes.subarray(96, 128));
  return { x: [x0, x1], y: [y0, y1] };
}

/**
 * Serializes a Groth16 proof into 256-byte binary format (A || B || C).
 */
export function serializeProof(proof: Groth16Proof): Uint8Array {
  const out = new Uint8Array(GROTH16_PROOF_BYTE_LENGTH);
  out.set(serializeG1Point(proof.a), 0);
  out.set(serializeG2Point(proof.b), 64);
  out.set(serializeG1Point(proof.c), 192);
  return out;
}

/**
 * Deserializes binary bytes into a Groth16 proof.
 */
export function deserializeProof(bytes: Uint8Array): Groth16Proof {
  if (!(bytes instanceof Uint8Array) || bytes.length !== GROTH16_PROOF_BYTE_LENGTH) {
    throw new Error(`INVALID_PROOF_LENGTH: Expected ${GROTH16_PROOF_BYTE_LENGTH} bytes, got ${bytes?.length}`);
  }
  const a = deserializeG1Point(bytes.subarray(0, 64));
  const b = deserializeG2Point(bytes.subarray(64, 192));
  const c = deserializeG1Point(bytes.subarray(192, 256));
  return { a, b, c };
}

/**
 * Converts a Groth16 proof and public inputs to standard Ethereum calldata.
 * Follows EIP-197 and snarkjs coordinate ordering for G2: [ [X1, X0], [Y1, Y0] ].
 */
export function proofToCalldata(proof: Groth16Proof, publicInputs: readonly bigint[]): Groth16Calldata {
  for (const input of publicInputs) {
    validateScalarFieldElement(input);
  }

  return {
    a: [toUint256Hex(proof.a.x), toUint256Hex(proof.a.y)],
    b: [
      [toUint256Hex(proof.b.x[1]), toUint256Hex(proof.b.x[0])],
      [toUint256Hex(proof.b.y[1]), toUint256Hex(proof.b.y[0])]
    ],
    c: [toUint256Hex(proof.c.x), toUint256Hex(proof.c.y)],
    input: publicInputs.map(toUint256Hex)
  };
}

/**
 * Constant-time byte array comparison.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
