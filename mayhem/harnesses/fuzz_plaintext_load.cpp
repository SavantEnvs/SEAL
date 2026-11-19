// Plaintext::load / unsafe_load, then BatchEncoder::decode (BFV/BGV) or CKKSEncoder::decode (CKKS),
// Plaintext::to_string and mod_switch of the plaintext.
// Input: byte 0 = scheme (bits 0-1, mod 3) + bit 7 unsafe_load; rest = serialized Plaintext.
#include "seal_fuzz_common.h"
#include <complex>

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
    Plaintext p;
    try
    {
        if (unsafe)
        {
            p.unsafe_load(e.ctx, sealfuzz::as_bytes(data + 1), size - 1);
            if (!is_valid_for(p, e.ctx))
            {
                return -1;
            }
        }
        else
        {
            p.load(e.ctx, sealfuzz::as_bytes(data + 1), size - 1);
        }
    }
    catch (const std::exception &)
    {
        return -1; // the library refused to parse the input
    }
    try
    {
        if (!p.is_ntt_form())
        {
            (void)p.to_string();
        }
        if (scheme == scheme_type::ckks)
        {
            CKKSEncoder enc(e.ctx);
            std::vector<std::complex<double>> out;
            enc.decode(p, out);
        }
        else
        {
            BatchEncoder enc(e.ctx);
            std::vector<std::uint64_t> out;
            enc.decode(p, out);
            std::vector<std::int64_t> sout;
            enc.decode(p, sout);
        }
        Evaluator ev(e.ctx);
        ev.mod_switch_to_next_inplace(p);
    }
    catch (const std::exception &)
    {
    }
    return 0;
}
