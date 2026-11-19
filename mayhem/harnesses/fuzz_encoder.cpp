// BatchEncoder::encode / CKKSEncoder::encode with fuzzed values, scale and level (ckks.h
// encode_internal for double, complex, int64 and single-value overloads; batchencoder.cpp), then
// encrypt -> decrypt -> decode.
// Input: FuzzedDataProvider stream: scheme, overload, level, scale, values.
#include "seal_fuzz_common.h"
#include <complex>
#include <fuzzer/FuzzedDataProvider.h>

using namespace seal;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
    FuzzedDataProvider fdp(data, size);
    const auto scheme = sealfuzz::pick_scheme(fdp.ConsumeIntegral<std::uint8_t>());
    const auto &e = sealfuzz::env(scheme);
    const std::uint8_t mode = fdp.ConsumeIntegral<std::uint8_t>();
    // Pick a level along the modulus chain.
    auto cd = e.ctx.first_context_data();
    for (std::uint8_t lvl = fdp.ConsumeIntegralInRange<std::uint8_t>(0, 3); lvl && cd->next_context_data(); lvl--)
    {
        cd = cd->next_context_data();
    }
    const parms_id_type pid = cd->parms_id();
    try
    {
        Plaintext p;
        if (scheme == scheme_type::ckks)
        {
            CKKSEncoder enc(e.ctx);
            const double scale = fdp.ConsumeFloatingPoint<double>();
            const std::size_t k = fdp.ConsumeIntegralInRange<std::size_t>(0, enc.slot_count() + 1);
            switch (mode % 4)
            {
            case 0:
            {
                std::vector<double> v;
                for (std::size_t i = 0; i < k && fdp.remaining_bytes(); i++)
                    v.push_back(fdp.ConsumeFloatingPoint<double>());
                enc.encode(v, pid, scale, p);
                break;
            }
            case 1:
            {
                std::vector<std::complex<double>> v;
                for (std::size_t i = 0; i < k && fdp.remaining_bytes(); i++)
                    v.emplace_back(fdp.ConsumeFloatingPoint<double>(), fdp.ConsumeFloatingPoint<double>());
                enc.encode(v, pid, scale, p);
                break;
            }
            case 2:
                enc.encode(fdp.ConsumeFloatingPoint<double>(), pid, scale, p);
                break;
            default:
                enc.encode(fdp.ConsumeIntegral<std::int64_t>(), pid, p);
                break;
            }
            Ciphertext c;
            Encryptor(e.ctx, e.pk).encrypt(p, c);
            Plaintext q;
            Decryptor(e.ctx, e.sk).decrypt(c, q);
            std::vector<std::complex<double>> out;
            enc.decode(q, out);
        }
        else
        {
            BatchEncoder enc(e.ctx);
            const std::size_t k = fdp.ConsumeIntegralInRange<std::size_t>(0, enc.slot_count() + 1);
            if (mode & 1)
            {
                std::vector<std::int64_t> v;
                for (std::size_t i = 0; i < k && fdp.remaining_bytes(); i++)
                    v.push_back(fdp.ConsumeIntegral<std::int64_t>());
                enc.encode(v, p);
            }
            else
            {
                std::vector<std::uint64_t> v;
                for (std::size_t i = 0; i < k && fdp.remaining_bytes(); i++)
                    v.push_back(fdp.ConsumeIntegral<std::uint64_t>());
                enc.encode(v, p);
            }
            Ciphertext c;
            Encryptor(e.ctx, e.pk).encrypt(p, c);
            Evaluator ev(e.ctx);
            ev.mod_switch_to_inplace(c, pid);
            Plaintext q;
            Decryptor(e.ctx, e.sk).decrypt(c, q);
            std::vector<std::uint64_t> out;
            enc.decode(q, out);
        }
    }
    catch (const std::exception &)
    {
    }
    return 0;
}
