const std = @import("std");
const crypto = std.crypto;
const Hash = std.crypto.hash.sha2.Sha256;
const RndGen = std.rand.DefaultPrng;

const Proof = struct {
    h: u256,
    s: u256,
};

var rnd = RndGen.init(0);

/// Perform modular exponentiation using the square-and-multiply algorithm.
/// This function computes (base^exp) % mod.
///
/// The square-and-multiply algorithm is used over the naive (base^exp) % mod approach
/// for several reasons:
///
/// 1. Handling Large Numbers: In cryptographic computations, base, exp, and mod are often
///    very large numbers. The naive approach involves first computing base^exp, which can
///    result in an extremely large number before the modulo operation is applied. This can
///    lead to overflow issues and is computationally infeasible.
///
/// 2. Computational Efficiency: The square-and-multiply algorithm is much more efficient.
///    It reduces the problem of computing large exponents into a series of squarings and
///    multiplications, which are much more manageable. This method grows logarithmically
///    with the size of the exponent, making it suitable for large exponents typical in
///    cryptographic applications.
///
/// Arguments:
///     - `base`: The base of the exponentiation.
///     - `exp`: The exponent.
///     - `mod`: The modulus.
///
/// Returns:
///     - The result of (base^exp) % mod.
///
/// Example usage:
///     const result = powMod(u128, 2, 10, 1000); // Computes 2^10 mod 1000
fn powMod(comptime T: type, base: T, exp: T, mod: T) T {
    var result: T = 1; // Initialize result to 1, the identity for multiplication
    var x: T = base % mod; // Initialize x as base mod mod
    var y: T = exp; // Copy of the exponent

    // Loop through each bit of the exponent
    while (y > 0) {
        // If the least significant bit of y is 1, multiply result with x
        if (y & 1 == 1) {
            result = (result * x) % mod;
        }

        // Right shift y by one bit (dividing by 2)
        // This moves to the next bit of the exponent
        y >>= 1;

        // Square x and reduce it modulo mod
        x = (x * x) % mod;
    }

    // Return the accumulated result
    return result;
}

// assignment via: https://hackmd.io/@gubsheep/Hy57lluOs
// implement a non-interactive zkp for discrete log in code!

// u will need to read and understand the first section of the handout, as well as the fiat-shamir heuristic

// implement

// a function dlogProof(x, g, p) that returns
// (1) a resude y, evaluated as g^x(mod p)
// (2) a proof of knowledge that u know x that is the discrete log of y

// a function verify(y, g, p, pf) that
// evaluates to true if
// pf is a valid proof of knowledge, otherwise FALSE

// the prover should only be able to compute a valid proof with non-negligible probability if they do indeed know valid x

// me transcribing this https://people.eecs.berkeley.edu/~jfc/cs174/lecs/lec24/lec24.pdf

// suppose u want to prove yr identity to someone
// in order to cash a check
// or pick up a package

// most forms of id can be copied or forged
// but there is a zk method that cannot!

//at least it cant, assumig discrete logs are hard to compute

/// Computes the discrete logarithm proof using the Fiat-Shamir heuristic.
/// This function generates a non-interactive zero-knowledge proof for knowing
/// the discrete logarithm `x` of `y` to the base `g` modulo `p`.
///
/// Arguments:
///     - `x`: The discrete logarithm that the prover knows.
///     - `g`: The base of the discrete logarithm.
///     - `p`: The modulus, a large prime number.
///
/// Returns:
///     - A struct containing `y` (g^x mod p) and the zero-knowledge proof.
fn discreteLog(x: u64, g: u64, p: u256) struct { y: u256, proof: Proof } {
    // Imagine Rainicorn's quest as a cryptographic puzzle where she must prove she holds a secret key (x)
    // without revealing it, akin to solving a riddle without giving away the answer.

    // Step 1: Compute y = g^x mod p
    // Here, `y` is like a sealed envelope containing a coded message derived from `x`.
    // The operation g^x mod p is easy to perform but hard to reverse, akin to encrypting a message:
    // anyone can lock the envelope (compute `y`), but only someone with the key (`x`) can unlock it (compute the discrete log).
    const y = powMod(u256, g, x, p);

    // Step 2: Choose a random r
    // `r` is a random number, a diversion akin to a magician's sleight of hand. It's used to create a diversion (`h`)
    // that is related to `x` but doesn't compromise its secrecy.
    const r = rnd.random().int(u64) % (p - 1);

    // Step 3: Compute h = g^r mod p
    // `h` is a commitment, like a publicly shown but indecipherable part of the magician's trick.
    // It's related to the secret `x` (through the mathematical structure of the problem) but reveals nothing about `x` itself.
    const h = powMod(u256, g, r, p);

    // Step 4: Generate b using a hash function (Fiat-Shamir transformation)
    // The hash function creates a challenge `b` from `h`, akin to a riddle based on the magician's displayed trick.
    // It's a transformation that ensures the response (in Step 5) will be inherently tied to the structure of `x` and `r`,
    // but without direct communication or external influence, maintaining the non-interactive nature of the proof.
    var hasher = Hash.init(.{});
    hasher.update(std.mem.asBytes(&h));
    const hash = hasher.finalResult();
    const b: u8 = hash[0] & 1;

    // naive single bit for challenge to try to build intuition
    // Step 5: Compute s = (r + bx) mod (p-1)
    // In this crucial step, `s` is calculated in a way that only someone who knows `x` could achieve.
    // Here's how it works:
    // - The value `s` is a combination of the random `r` and the secret `x`, altered by the challenge `b`.
    // - If `b` is 0, `s` equals `r`, which corresponds to the commitment `h` (as `h = g^r mod p` from Step 3).
    // - If `b` is 1, `s` becomes `r + x`. This is where the alignment occurs:
    //   - The verifier will check if `g^s mod p` equals `h * y^b mod p`.
    //   - Since `y` is `g^x mod p`, and `h` is `g^r mod p`, the right side of the equation becomes `g^r * g^x mod p`.
    //   - This simplifies to `g^(r + x) mod p`, which is exactly what `g^s` is when `b` is 1.
    // - Therefore, only someone who knows `x` can construct an `s` that aligns `g^s` with `h * y^b`, regardless of `b`'s value.
    // - This alignment convincingly demonstrates knowledge of `x` without revealing it, as `s` cleverly encapsulates the secret.

    const s = (r + b * x) % (p - 1);

    return .{ .y = y, .proof = Proof{ .h = h, .s = s } };
    // With `y` and `proof`, Rainicorn can confidently validate her identity, akin to a magician concluding a trick.
    // The proof is a cryptographic performance that convinces the verifier of her knowledge of `x`, while keeping the secret secure.
}

fn verify(y: u256, g: u64, p: u256, proof: Proof) bool {
    // The verifier (like the bouncer at the party) re-generates the challenge b using the same hash function.
    // This ensures consistency in the verification process, as the same input (h) should yield the same challenge (b).
    var hasher = Hash.init(.{});
    hasher.update(std.mem.asBytes(&proof.h));
    const hash = hasher.finalResult();
    const b: u8 = hash[0] & 1; // The challenge bit, derived from the commitment h.

    // The verifier then checks if the equation g^s ≡ h * y^b mod p holds true.
    // This equation is the heart of the verification process:
    // - g^s is the prover's claimed knowledge transformed by the challenge b.
    // - h * y^b mod p is the combination of the commitment (h) and the public ID (y), altered by the challenge b.
    // If the prover knows the secret x, they can construct an s such that this equation holds true for any b.
    // If the equation holds, it strongly suggests that the prover knows x without the verifier learning what x is.
    const leftSide = powMod(u256, g, proof.s, p);
    const rightSide = (proof.h * powMod(u256, y, b, p)) % p;
    // The equation g^s ≡ h * y^b mod p can only be satisfied if s is calculated as r + bx mod (p-1).
    // This is because:
    // 1. When b = 0, s must equal r to satisfy g^s = g^r = h. Only the prover who chose r can know this value.
    // 2. When b = 1, the equation transforms to g^s = g^(r + x) = g^r * g^x = h * y. For this to hold, s must be r + x.
    //    Since y = g^x, this shows that the prover can correctly adjust their response s based on their knowledge of x.
    // In both cases, the correctness of s hinges on the prover's knowledge of x. Any arbitrary choice of s without knowing x
    // would not align consistently with both h and y under the varying challenges (b values), due to the properties of modular arithmetic.
    // Hence, a successful verification of this equation strongly indicates that the prover knows x. It leverages the mathematical
    // characteristics of exponentiation and modular arithmetic to create a scenario where knowledge of x is essential to formulating
    // a correct and verifiable response.

    return leftSide == rightSide;
}

const testing = std.testing;

test "zk discrete log" {
    // Initialize parameters
    const p: u256 = 273389558745553615023177755634264971227;
    const g: u64 = 1300135;
    const x: u64 = 42; // Secret x

    // Generate proof
    const proofResult = discreteLog(x, g, p);

    // Verify proof
    const isProofValid = verify(proofResult.y, g, p, proofResult.proof);

    // Check if the verification is successful
    try std.testing.expect(isProofValid);
}
