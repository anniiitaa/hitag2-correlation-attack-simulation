#!/usr/bin/env python3
"""
HiTag2 Correlation Attack Simulation
=====================================
Implements the HiTag2 cipher and generates test data compatible with
the ht2crack4 fast correlation attack tool from Garcia et al.

"Lock It and Still Lose It - On the (In)Security of Automotive Remote
Keyless Entry Systems" (USENIX Security 2016)

This simulation:
  1. Implements the HiTag2 stream cipher (48-bit LFSR + nonlinear filter)
  2. Generates encrypted nonce / challenge-response pairs
  3. Outputs them in the exact byte-order encoding expected by ht2crack4
  4. Verifies correctness against the MIKRON test vector

Usage:
  python3 hitag2_simulation.py                     # generate with defaults
  python3 hitag2_simulation.py --key 4F4E4D494B52 --uid AABBCCDD -n 16
  python3 hitag2_simulation.py --verify            # run MIKRON test only

Key format: 12 hex chars in the same format ht2crack4 displays.
  e.g. the MIKRON key is 4F4E4D494B52 (ASCII "ONMIKR")
UID format: 8 hex chars, same as the -u argument to ht2crack4.
"""

import argparse
import os
import random
import sys

# =====================================================================
# Byte-order encoding functions (from util.h / util.c)
# =====================================================================

def rev8(x):
    """Reverse bits within a single byte (util.h macro)"""
    x = x & 0xFF
    return (((x >> 7) & 1) + ((x >> 5) & 2) + ((x >> 3) & 4) +
            ((x >> 1) & 8) + ((x << 1) & 16) + ((x << 3) & 32) +
            ((x << 5) & 64) + ((x << 7) & 128))

def rev16(x):
    x = x & 0xFFFF
    return rev8(x) + (rev8(x >> 8) << 8)

def rev32(x):
    """Reverse bits within each byte of a 32-bit value"""
    x = x & 0xFFFFFFFF
    return rev16(x) + (rev16(x >> 16) << 16)

def rev64(x):
    """Reverse bits within each byte of a 64-bit value"""
    x = x & 0xFFFFFFFFFFFFFFFF
    return rev32(x) + (rev32(x >> 32) << 32)

def byte_swap_6(val):
    """Reverse byte order of a 6-byte (48-bit) value.
    Matches ht2crack4's key display transformation."""
    val = val & 0xFFFFFFFFFFFF
    return (((val >> 40) & 0xFF) | ((val >> 24) & 0xFF00) |
            ((val >> 8) & 0xFF0000) | ((val << 8) & 0xFF000000) |
            ((val << 24) & 0xFF00000000) | ((val << 40) & 0xFF0000000000))

def hexreversetoulong(hex_str):
    """
    Convert byte-reversed 8-char hex string to uint32 (util.c).
    Reads byte pairs LSB-first: "12345678" -> 0x78563412
    """
    assert len(hex_str) == 8, f"Expected 8 hex chars, got {len(hex_str)}"
    ret = 0
    for i in range(4):
        ret += int(hex_str[i*2:i*2+2], 16) << (i * 8)
    return ret & 0xFFFFFFFF

def internal32_to_file_hex(val):
    """
    Convert internal 32-bit value to the hex string that ht2crack4 expects.
    Inverse of rev32(hexreversetoulong(s)).
    """
    val = val & 0xFFFFFFFF
    x = rev32(val)  # undo the rev32
    # undo hexreversetoulong: write bytes LSB-first
    return "%02X%02X%02X%02X" % (x & 0xFF, (x >> 8) & 0xFF,
                                  (x >> 16) & 0xFF, (x >> 24) & 0xFF)

def reverse_bits32(x):
    """Reverse all 32 bits of a value (NOT the same as rev32 which reverses within bytes)."""
    x = x & 0xFFFFFFFF
    result = 0
    for _ in range(32):
        result = (result << 1) | (x & 1)
        x >>= 1
    return result

def user_key_to_internal(key_str):
    """
    Convert a key from ht2crack4 display format to internal form.

    ht2crack4 displays keys as: byte_swap_6(rev64(internal_key))
    So the inverse is: rev64(byte_swap_6(display_key))
    """
    key_val = int(key_str, 16)
    return rev64(byte_swap_6(key_val)) & 0xFFFFFFFFFFFF

def internal_key_to_display(key_int):
    """
    Convert an internal key to ht2crack4 display format.

    ht2crack4 display code (lines 852-855):
      revkey = rev64(guesses[i].key);
      foundkey = byte_swap_6(revkey);
    """
    return byte_swap_6(rev64(key_int) & 0xFFFFFFFFFFFF)

# =====================================================================
# HiTag2 Cipher Core (from hitagcrypto.c lines 220-373)
# =====================================================================

HT2_FUNCTION4A = 0x2C79
HT2_FUNCTION4B = 0x6671
HT2_FUNCTION5C = 0x7907287B

def hitag2_crypt(s):
    """
    Nonlinear filter function (hitagcrypto.c lines 232-247).
    Maps 48-bit LFSR state to 1-bit output via boolean function tables.
    """
    # pickbits2_2(s, 1, 4)
    bits = ((s >> 1) & 3) | ((s >> 2) & 0xC)
    bitindex = (HT2_FUNCTION4A >> bits) & 1

    # pickbits1_1_2(s, 7, 11, 13)
    bits = ((s >> 7) & 1) | ((s >> 10) & 2) | ((s >> 11) & 0xC)
    bitindex |= ((HT2_FUNCTION4B << 1) >> bits) & 0x02

    # pickbits1x4(s, 16, 20, 22, 25)
    bits = ((s >> 16) & 1) | ((s >> 19) & 2) | ((s >> 20) & 4) | ((s >> 22) & 8)
    bitindex |= ((HT2_FUNCTION4B << 2) >> bits) & 0x04

    # pickbits2_1_1(s, 27, 30, 32)
    bits = ((s >> 27) & 3) | ((s >> 28) & 4) | ((s >> 29) & 8)
    bitindex |= ((HT2_FUNCTION4B << 3) >> bits) & 0x08

    # pickbits1_2_1(s, 33, 42, 45)
    bits = ((s >> 33) & 1) | ((s >> 41) & 6) | ((s >> 42) & 8)
    bitindex |= ((HT2_FUNCTION4A << 4) >> bits) & 0x10

    return (HT2_FUNCTION5C >> bitindex) & 1


def hitag2_init(sharedkey, serialnum, initvector):
    """
    Initialize the HiTag2 cipher state (hitagcrypto.c lines 256-327).

    Parameters:
        sharedkey:  48-bit shared key (internal form)
        serialnum:  32-bit tag serial number (internal form)
        initvector: 32-bit initialization vector (internal form)

    Returns:
        (shiftreg, lfsr) tuple for use with hitag2_nstep
    """
    # Init state from serial number and lowest 16 bits of shared key
    state = ((sharedkey & 0xFFFF) << 32) | (serialnum & 0xFFFFFFFF)

    # Mix IV with upper 32 bits of shared key
    initvector = (initvector ^ ((sharedkey >> 16) & 0xFFFFFFFF)) & 0xFFFFFFFF

    # Move lower 16 bits of (IV xor key) to top of state
    state |= (initvector & 0xFFFF) << 48
    initvector >>= 16

    # Initial right shift
    state >>= 1

    # 16 iterations: shift right, XOR crypto bit at position 46
    for _ in range(16):
        state = (state >> 1) ^ (hitag2_crypt(state) << 46)

    # OR upper 16 bits of (IV xor key) at position 47
    state |= (initvector & 0xFFFF) << 47

    # 15 more iterations (NOT 16!)
    for _ in range(15):
        state = (state >> 1) ^ (hitag2_crypt(state) << 46)

    # Final special step: XOR at bit 47, NO shift
    state ^= hitag2_crypt(state) << 47

    # Mask to 48 bits
    state &= 0xFFFFFFFFFFFF

    # Compute LFSR register (optimized Galois form)
    temp = state ^ (state >> 1)
    lfsr = (state ^ (state >> 6) ^ (state >> 16) ^
            (state >> 26) ^ (state >> 30) ^ (state >> 41) ^
            (temp >> 2) ^ (temp >> 7) ^ (temp >> 22) ^
            (temp >> 42) ^ (temp >> 46))
    lfsr &= 0xFFFFFFFFFFFF

    return (state, lfsr)


def hitag2_nstep(state, lfsr, steps):
    """
    Generate keystream bits (hitagcrypto.c lines 341-373).

    Uses Galois LFSR form for efficiency (identical output to Fibonacci form).
    Returns up to 32 bits of keystream, MSB first (last bit in LSB).
    """
    LFSR_POLY = 0xB38083220073  # Galois feedback polynomial
    result = 0

    for _ in range(steps):
        if lfsr & 1:
            state = (state >> 1) | 0x800000000000
            lfsr = (lfsr >> 1) ^ LFSR_POLY
        else:
            state >>= 1
            lfsr >>= 1

        result = (result << 1) | hitag2_crypt(state)

    return result, state, lfsr


# =====================================================================
# Verification against MIKRON test vector
# =====================================================================

def verify_mikron():
    """
    Test against the MIKRON test vector from hitagcrypto.c lines 379-395.

    Key:    4F 4E 4D 49 4B 52  ("ONMIKR" in ASCII)
    Serial: 49 43 57 69
    IV:     65 6E 45 72
    Expected keystream: D7 23 7F CE 8C D0 37 A9 57 49 C1 E6 48 00 8A B6

    In hitagcrypto.c test code:
      key    = rev64(0x524B494D4E4F)  -> internal 0x4AD292B272F2
      serial = rev32(0x69574349)      -> internal 0x96EAC292
      iv     = rev32(0x72456E65)      -> internal 0x4EA276A6
    """
    # The MIKRON key in display format is "4F4E4D494B52"
    key = user_key_to_internal("4F4E4D494B52")  # = 0x4AD292B272F2
    serial = rev32(0x69574349)                    # = 0x96EAC292
    iv = rev32(0x72456E65)                        # = 0x4EA276A6

    state, lfsr = hitag2_init(key, serial, iv)

    # Expected state after init
    expected_state = 0x1AA0AFDA72F2
    if state != expected_state:
        print(f"FAIL: init state = 0x{state:012X}, expected 0x{expected_state:012X}")
        return False

    # Get 128 bits of keystream (4 x 32)
    ks32, state, lfsr = hitag2_nstep(state, lfsr, 32)
    next32, state, lfsr = hitag2_nstep(state, lfsr, 32)
    next32b, state, lfsr = hitag2_nstep(state, lfsr, 32)
    next32c, state, lfsr = hitag2_nstep(state, lfsr, 32)
    full_ks = (ks32 << 96) | (next32 << 64) | (next32b << 32) | next32c

    # Expected: D7 23 7F CE 8C D0 37 A9 57 49 C1 E6 48 00 8A B6
    expected_full = 0xD7237FCE8CD037A95749C1E648008AB6
    if full_ks != expected_full:
        print(f"FAIL: full ks = 0x{full_ks:032X}")
        print(f"  expected     0x{expected_full:032X}")
        return False

    # Verify key display round-trip
    display = internal_key_to_display(key)
    if display != 0x4F4E4D494B52:
        print(f"FAIL: key display = 0x{display:012X}, expected 0x4F4E4D494B52")
        return False

    print("MIKRON test vector: PASS")
    return True


# =====================================================================
# ht2crack4-compatible check_key (for self-verification)
# =====================================================================

def check_key(key, uid, enc_nR, ks):
    """
    Verify a key against an encrypted nonce and keystream pair.
    Replicates ht2crack4's check_key() function (lines 783-798).

    IMPORTANT: ht2crack4 accumulates keystream as (bits >> 1) | (bit << 31),
    which puts the first keystream bit at bit 0 (LSB). hitag2_nstep(32) puts
    it at bit 31 (MSB), so we must reverse the bits.

    All values are in INTERNAL form (after rev32/hexreversetoulong parsing).
    """
    state, lfsr = hitag2_init(key, uid, enc_nR)
    bits, _, _ = hitag2_nstep(state, lfsr, 32)
    # Reverse bits to match C check_key's (bits >> 1) | (nstep(1) << 31) pattern
    bits = reverse_bits32(bits)
    return bits == ks


# =====================================================================
# Nonce/keystream pair generation
# =====================================================================

def generate_nonces(key, uid, num_nonces=16, seed=None):
    """
    Generate encrypted nonce and challenge-response pairs.

    Parameters:
        key: 48-bit key (internal form)
        uid: 32-bit UID (internal form)
        num_nonces: number of pairs to generate
        seed: random seed for reproducibility

    Returns:
        list of (enc_nR, ks) tuples in internal form
    """
    if seed is not None:
        rng = random.Random(seed)
    else:
        rng = random.Random()

    pairs = []
    for _ in range(num_nonces):
        # Generate random 32-bit encrypted nonce
        enc_nR = rng.randint(0, 0xFFFFFFFF)

        # Initialize cipher and get keystream
        state, lfsr = hitag2_init(key, uid, enc_nR)
        ks_raw, _, _ = hitag2_nstep(state, lfsr, 32)
        # Reverse bits to match C check_key convention:
        # first keystream bit at bit 0 (LSB)
        ks = reverse_bits32(ks_raw)

        pairs.append((enc_nR, ks))

    return pairs


def write_nonce_file(pairs, filename):
    """
    Write nonce pairs to file in ht2crack4's expected format.

    ht2crack4 reads each line as: "XXXXXXXX YYYYYYYY"
    and parses:
        enc_nR = rev32(hexreversetoulong(X))
        ks     = rev32(hexreversetoulong(Y)) ^ 0xFFFFFFFF

    So the file contains ~ks (the authenticator = inverted keystream).
    """
    with open(filename, 'w') as f:
        for enc_nR, ks in pairs:
            nR_str = internal32_to_file_hex(enc_nR)
            # File contains ~ks (authenticator = inverted keystream)
            aR_str = internal32_to_file_hex(ks ^ 0xFFFFFFFF)
            f.write(f"{nR_str} {aR_str}\n")


# =====================================================================
# Self-tests
# =====================================================================

def verify_encoding_roundtrip():
    """Verify that encoding/decoding is reversible."""
    test_values = [0x00000000, 0xFFFFFFFF, 0x12345678, 0xDEADBEEF,
                   0xAABBCCDD, 0x01020304]
    for val in test_values:
        file_str = internal32_to_file_hex(val)
        decoded = rev32(hexreversetoulong(file_str))
        assert decoded == val, \
            f"Round-trip failed: 0x{val:08X} -> '{file_str}' -> 0x{decoded:08X}"
    print("Encoding round-trip: PASS")
    return True


def verify_key_format_roundtrip():
    """Verify key format conversion is reversible."""
    test_keys = ["4F4E4D494B52", "AABBCCDDEEFF", "112233445566", "000000000001"]
    for key_str in test_keys:
        internal = user_key_to_internal(key_str)
        display = internal_key_to_display(internal)
        back_str = f"{display:012X}"
        assert back_str == key_str, \
            f"Key round-trip failed: '{key_str}' -> 0x{internal:012X} -> '{back_str}'"
    print("Key format round-trip: PASS")
    return True


def verify_generated_pairs(key, uid, pairs):
    """Verify each generated pair with check_key."""
    for i, (enc_nR, ks) in enumerate(pairs):
        if not check_key(key, uid, enc_nR, ks):
            print(f"FAIL: pair {i} failed check_key verification")
            return False
    print(f"All {len(pairs)} nonce pairs verified with check_key: PASS")
    return True


def verify_file_roundtrip(key_str, uid_str, filename):
    """
    Read back a nonce file and verify using the same parsing as ht2crack4.
    """
    key_int = user_key_to_internal(key_str)
    uid_int = rev32(hexreversetoulong(uid_str.rjust(8, '0')))

    with open(filename, 'r') as f:
        for line_num, line in enumerate(f, 1):
            parts = line.strip().split()
            if len(parts) != 2:
                print(f"FAIL: invalid line {line_num}")
                return False

            enc_nR = rev32(hexreversetoulong(parts[0]))
            ks = rev32(hexreversetoulong(parts[1])) ^ 0xFFFFFFFF

            if not check_key(key_int, uid_int, enc_nR, ks):
                print(f"FAIL: line {line_num} failed ht2crack4-style verification")
                return False

    print(f"File round-trip verification ({filename}): PASS")
    return True


# =====================================================================
# Main
# =====================================================================

def main():
    parser = argparse.ArgumentParser(
        description="HiTag2 Correlation Attack Simulation (Garcia et al.)",
        epilog=("Key is specified in ht2crack4 display format (byte-order). "
                "Example: the MIKRON test key is 4F4E4D494B52."))
    parser.add_argument('--key', default='4F4E4D494B52',
                        help='48-bit key, 12 hex chars in ht2crack4 display format '
                             '(default: 4F4E4D494B52 = MIKRON test key)')
    parser.add_argument('--uid', default='AABBCCDD',
                        help='32-bit UID as 8 hex chars (default: AABBCCDD)')
    parser.add_argument('-n', '--num-nonces', type=int, default=16,
                        help='Number of nonce pairs to generate (default: 16)')
    parser.add_argument('-o', '--output', default='nonces.txt',
                        help='Output filename (default: nonces.txt)')
    parser.add_argument('--seed', type=int, default=42,
                        help='Random seed for reproducibility (default: 42)')
    parser.add_argument('--verify', action='store_true',
                        help='Run MIKRON test vector only')
    args = parser.parse_args()

    print("=" * 60)
    print("HiTag2 Correlation Attack Simulation")
    print("Based on Garcia, Oswald, Kasper, Pavlides (2016)")
    print("=" * 60)
    print()

    # Always run verification tests
    ok = True
    ok &= verify_mikron()
    ok &= verify_encoding_roundtrip()
    ok &= verify_key_format_roundtrip()

    if not ok:
        print("\nSelf-tests FAILED! Aborting.")
        sys.exit(1)

    if args.verify:
        print("\nAll verification tests passed.")
        return

    # Parse user-supplied key and UID into internal form
    key_str = args.key.upper()
    uid_str = args.uid.upper()

    assert len(key_str) == 12, "Key must be 12 hex characters (48 bits)"
    assert len(uid_str) == 8, "UID must be 8 hex characters (32 bits)"

    # Convert to internal representation
    key_int = user_key_to_internal(key_str)
    uid_int = rev32(hexreversetoulong(uid_str))

    # Verify display round-trip
    assert f"{internal_key_to_display(key_int):012X}" == key_str, \
        "Key display round-trip failed!"

    print(f"\nConfiguration:")
    print(f"  Key (display):  {key_str}")
    print(f"  Key (internal): 0x{key_int:012X}")
    print(f"  UID:            {uid_str}")
    print(f"  UID (internal): 0x{uid_int:08X}")
    print(f"  Num nonces:     {args.num_nonces}")
    print(f"  Output file:    {args.output}")
    print(f"  Random seed:    {args.seed}")

    # Generate nonce pairs
    print(f"\nGenerating {args.num_nonces} encrypted nonce/response pairs...")
    pairs = generate_nonces(key_int, uid_int, args.num_nonces, seed=args.seed)

    # Verify all pairs
    ok = verify_generated_pairs(key_int, uid_int, pairs)
    if not ok:
        print("Generated pairs failed verification! Aborting.")
        sys.exit(1)

    # Write to file
    write_nonce_file(pairs, args.output)
    print(f"Written {args.num_nonces} pairs to {args.output}")

    # Verify the file can be read back correctly
    ok = verify_file_roundtrip(key_str, uid_str, args.output)
    if not ok:
        print("File round-trip verification FAILED! Aborting.")
        sys.exit(1)

    # Print ht2crack4 command line
    print(f"\n{'=' * 60}")
    print(f"To crack with ht2crack4:")
    print(f"  ./ht2crack4 -u {uid_str} -n {args.output} -N {args.num_nonces} -t 2000000")
    print(f"\nExpected recovered key: {key_str}")
    print(f"{'=' * 60}")


if __name__ == '__main__':
    main()
