// RelinKeys / GaloisKeys / KSwitchKeys ::load and unsafe_load (kswitchkeys.cpp load_members: nested
// vectors of PublicKey with size fields, valcheck), then the loaded keys drive relinearize /
// apply_galois on a fresh ciphertext.
// Input: byte 0 = scheme (bits 0-1, mod 3), bits 2-3 key kind, bit 7 unsafe_load; rest = serialized keys.
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
    const int kind = (data[0] >> 2) % 3;
    const seal_byte *in = sealfuzz::as_bytes(data + 1);
    const std::size_t n = size - 1;
    RelinKeys rk;
    GaloisKeys gk;
    KSwitchKeys kk;
    try
    {
        KSwitchKeys &k = kind == 0 ? static_cast<KSwitchKeys &>(rk) : kind == 1 ? static_cast<KSwitchKeys &>(gk) : kk;
        unsafe ? (void)k.unsafe_load(e.ctx, in, n) : (void)k.load(e.ctx, in, n);
    }
    catch (const std::exception &)
    {
        return -1; // the library refused to parse the input
    }
    try
    {
        Encryptor encryptor(e.ctx, e.pk);
        Evaluator ev(e.ctx);
        Plaintext p("3x^2 + 1");
        if (scheme == scheme_type::ckks)
        {
            CKKSEncoder(e.ctx).encode(2.0, std::pow(2.0, 30), p);
        }
        Ciphertext c;
        encryptor.encrypt(p, c);
        if (kind == 0)
        {
            ev.square_inplace(c);
            ev.relinearize_inplace(c, rk);
        }
        else if (kind == 1)
        {
            if (scheme == scheme_type::ckks)
            {
                ev.rotate_vector_inplace(c, 1, gk);
            }
            else
            {
                ev.rotate_rows_inplace(c, 1, gk);
                ev.rotate_columns_inplace(c, gk);
            }
        }
        else
        {
            (void)is_valid_for(kk, e.ctx);
            std::vector<seal_byte> buf(static_cast<std::size_t>(kk.save_size(compr_mode_type::none)));
            kk.save(buf.data(), buf.size(), compr_mode_type::none);
        }
    }
    catch (const std::exception &)
    {
    }
    return 0;
}
