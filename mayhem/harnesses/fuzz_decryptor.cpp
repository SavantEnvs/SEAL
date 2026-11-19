// Decryptor::decrypt / invariant_noise_budget on a loaded ciphertext of any size and level
// (dot_product_ct_sk_array with secret-key powers for size > 2, RNSTool decrypt_scale_and_round /
// decrypt_modt), then decode of the result.
// Input: byte 0 = scheme (mod 3); rest = serialized Ciphertext.
#include "seal_fuzz_common.h"
#include <complex>

using namespace seal;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
    if (size < 1)
    {
        return -1;
    }
    const auto scheme = sealfuzz::pick_scheme(data[0]);
    const auto &e = sealfuzz::env(scheme);
    Ciphertext c;
    try
    {
        c.load(e.ctx, sealfuzz::as_bytes(data + 1), size - 1);
    }
    catch (const std::exception &)
    {
        return -1; // the library refused to parse the input
    }
    try
    {
        Decryptor dec(e.ctx, e.sk);
        if (scheme != scheme_type::ckks)
        {
            (void)dec.invariant_noise_budget(c);
        }
        Plaintext p;
        dec.decrypt(c, p);
        if (scheme == scheme_type::ckks)
        {
            std::vector<std::complex<double>> out;
            CKKSEncoder(e.ctx).decode(p, out);
        }
        else
        {
            std::vector<std::uint64_t> out;
            BatchEncoder(e.ctx).decode(p, out);
        }
    }
    catch (const std::exception &)
    {
    }
    return 0;
}
