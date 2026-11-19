// EncryptionParameters::load + SEALContext construction: load_members, Modulus loads, then
// SEALContext::validate, NTT tables, RNSTool, Galois tool and the modulus-switching chain.
// Input: a serialized EncryptionParameters.
#include "seal_fuzz_common.h"
#include <cmath>

using namespace seal;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
    EncryptionParameters parms;
    try
    {
        parms.load(sealfuzz::as_bytes(data), size);
    }
    catch (const std::exception &)
    {
        return -1; // the library refused to parse the input
    }
    try
    {
        SEALContext ctx(parms, true, sec_level_type::none);
        if (!ctx.parameters_set())
        {
            return 0;
        }
        for (auto cd = ctx.first_context_data(); cd; cd = cd->next_context_data())
        {
            (void)cd->total_coeff_modulus_bit_count();
        }
        // Exercise the context: keys, one encryption and decryption. Key generation is the slow part
        // at the large degrees the format allows (up to 131072), so it runs only for degrees up to
        // 8192; the context itself is always built.
        if (parms.poly_modulus_degree() > 8192)
        {
            return 0;
        }
        KeyGenerator kg(ctx);
        Encryptor enc(ctx, kg.secret_key());
        Decryptor dec(ctx, kg.secret_key());
        Plaintext p;
        if (parms.scheme() == scheme_type::ckks)
        {
            CKKSEncoder encoder(ctx);
            encoder.encode(1.5, std::pow(2.0, 20), p);
        }
        else
        {
            p = Plaintext("1x^1 + 1");
        }
        Ciphertext c;
        enc.encrypt_symmetric(p, c);
        Plaintext q;
        dec.decrypt(c, q);
    }
    catch (const std::exception &)
    {
    }
    return 0;
}
