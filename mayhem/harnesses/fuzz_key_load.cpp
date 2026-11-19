// PublicKey::load / SecretKey::load (+ unsafe_load), then the loaded key is used:
// Encryptor(ctx, pk).encrypt, or KeyGenerator(ctx, sk) regenerating public and relinearization keys
// and a symmetric encryption + decryption.
// Input: byte 0 = scheme (bits 0-1, mod 3), bit 2 secret vs public, bit 7 unsafe_load; rest = serialized key.
#include "seal_fuzz_common.h"

using namespace seal;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
    if (size < 1)
    {
        return -1;
    }
    const auto scheme = sealfuzz::pick_scheme(data[0] & 0x03);
    const auto &e = sealfuzz::env(scheme);
    const bool unsafe = data[0] & 0x80;
    const bool secret = data[0] & 0x04;
    const seal_byte *in = sealfuzz::as_bytes(data + 1);
    const std::size_t n = size - 1;
    SecretKey sk;
    PublicKey pk;
    try
    {
        if (secret)
            unsafe ? (void)sk.unsafe_load(e.ctx, in, n) : (void)sk.load(e.ctx, in, n);
        else
            unsafe ? (void)pk.unsafe_load(e.ctx, in, n) : (void)pk.load(e.ctx, in, n);
    }
    catch (const std::exception &)
    {
        return -1; // the library refused to parse the input
    }
    try
    {
        Plaintext p("2x^1 + 5");
        if (scheme == scheme_type::ckks)
        {
            CKKSEncoder(e.ctx).encode(3.0, std::pow(2.0, 30), p);
        }
        Ciphertext c;
        if (secret)
        {
            KeyGenerator kg(e.ctx, sk);
            PublicKey new_pk;
            kg.create_public_key(new_pk);
            RelinKeys rk;
            kg.create_relin_keys(rk);
            Encryptor(e.ctx, sk).encrypt_symmetric(p, c);
            Plaintext q;
            Decryptor(e.ctx, sk).decrypt(c, q);
        }
        else
        {
            Encryptor(e.ctx, pk).encrypt(p, c);
            Plaintext q;
            Decryptor(e.ctx, e.sk).decrypt(c, q);
        }
    }
    catch (const std::exception &)
    {
    }
    return 0;
}
