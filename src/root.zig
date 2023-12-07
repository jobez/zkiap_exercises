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

fn discreteLog(x: u64, g: u64, p: u256) struct { y: u256, proof: Proof } {

    // step 1: compute y = g^x mod p
    const y = powMod(u256, g, x, p);

    // step 2: choose a random r
    const r = rnd.random().int(u64) % (p - 1); // Ensure r is in the correct range

    // step 3: compute h = g^r mod p
    const h = powMod(u256, g, r, p);

    // step 4: generate b using hash function
    // ~* fiat shamir xformation *~
    var hasher = Hash.init(.{});
    hasher.update(std.mem.asBytes(&h));
    const hash = hasher.finalResult();
    const b: u8 = hash[0] & 1; // Using the first bit of the hash as b
    std.debug.print("b {}", .{b});

    // Step 5: Compute s = (r + bx) mod (p-1)
    const s = (r + b * x) % (p - 1);

    return .{ .y = y, .proof = Proof{ .h = h, .s = s } };

    // u can safely pubilsh A, B, and p
    // b/c an eavesdropper cannot compute x from data if discrete log is hard

    // suppose u want to get into a unicorn cosplay party
    // yr spot on the guestlist could be

    // Rainicorn, discrete log key (A, B, p)

    // now, if u show up at the post office to collect a package, you could produce x and anyone could verify that B = A^x(mod p)

    // but then  any eavesdrooper could catch x and impersonate yr unicornass later

    // it is better to keep x secret and only answer certain questions about it

    // SPECIFICALLY

    // 1. prover (you) chooses a random number
    //// 0 less than greater than r less than p - 1
    //// and sends the verifier h = A^r(mod p)
    // 2. verifier sends back a random bit b
    // 3. prover sends s = (r + bx)(mod (p-1)) to verifier
    // 4. verifier computes A^s(mod p) which should equal hB^b(mod p)

    // the basic idea here is that
    // if b = 1
    // the prover gives a number to the verifier (V)
    // that looks random
    // s = r + x (mod p-1)
    // but Verifier already hows that
    // h = A^r and B = A^x and can multiply these and compare to A^s

    // we should be careful what is proved by that
    // what V actually sees are h and s
    // and so what V knows is that
    // s = discreteLog(h) + x(mod (p - 1)) where
    // discreteLog(h) is
    // the discrete log relative to A

    // the verifier knows s and so do u, the prover

    // now if u also know discreteLog(h)
    // then
    // it is clear that you know x

    // so it remains for you to convince the verifier that
    // you know discreteLog(h)

    // thats where the random bit comes in
    // if b = 0
    // you the Prover just sent s = r back to Verifier
    // Verifier then checks h - A^r(mod p)
    // i.e. that r is the discrete log of h

    // so
    // depending on the random bit
    // Verifier gets s or r but never both
    // because their difference is x

    // thus Verifier gets no information about x

    // you, the prover
    // can try to cheat in one of two ways

    // if u dont know x
    // u can still pick a random r
    // and send
    // h = A^r(mod p) to V at the first step

    // if V picks b = 0
    // you are OK
    // because you can just send s = r at step 4
    // and V will be able to check that
    // A^s = h(mod p)

    // but
    // if V picks
    // b = 1
    // you are stuck because you dont know x
    // and you cant easily compute an s that will satisfy
    // A^s = hB(mod p)

    // because that would be equiv to finding the discrete log of hB

    // on the other hand
    // u the prover might CHEAT
    // by sending V a h
    // whose discrete log u dont know
    // at step 1

    // a good candidate is h = A^sB^-1 for some random s

    // if the verifier picks b = 1
    // you send this s and it will satisify
    // A^s=hB^b(mod p)
    // but if the verifier picks b = 0
    // you are stuck b/c
    // you dont know an r such that
    // A^r = h(mod p)

    // in either case, the verifier will discovered that u cheated
    // with 50% probability
    // so after k trials
    // the xpected number of bits that were 0
    // is k/2
    // and if the verifier found that h=A^r on all of these
    // the virifier would know that the probability of you cheating on a given round is less than 2^-k/2

    // the prob of u hceating on the rounds where b = 1
    // is the same as
    // the rounds where
    // b = 0
    // because u have no control over the random bit

    // on the first round where b = 1,
    // the verifier confirms that
    // s = discreteLog(h) + x

    // since the verifier almost certainly knows
    // discreteLog(h)
    // he almost certainly knows x

    // we can make that probability
    // arbitrarily high by
    // increasing
    // k

}

fn verify(y: u256, g: u64, p: u256, proof: Proof) bool {
    // Re-generate b using the same hash function
    var hasher = Hash.init(.{});
    hasher.update(std.mem.asBytes(&proof.h));
    const hash = hasher.finalResult();
    const b: u8 = hash[0] & 1; // First bit of hash as b

    // Check if g^s ≡ h * y^b mod p
    const leftSide = powMod(u256, g, proof.s, p);
    const rightSide = (proof.h * powMod(u256, y, b, p)) % p;

    return leftSide == rightSide;
}

const testing = std.testing;

test "zk discrete log" {
    // Initialize parameters
    const p: u128 = 273389558745553615023177755634264971227;
    const g: u64 = 1300135;
    const x: u64 = 42; // Secret x

    // Generate proof
    const proofResult = discreteLog(x, g, p);

    // Verify proof
    const isProofValid = verify(proofResult.y, g, p, proofResult.proof);

    // Check if the verification is successful
    try std.testing.expect(isProofValid);
}
