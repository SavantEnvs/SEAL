// Evaluator on fuzz-shaped ciphertexts/plaintexts: add/sub/negate/multiply/square/relinearize/
// mod_switch/rescale/rotate/multiply_plain/add_plain/transform_to_ntt/exponentiate/apply_galois,
// incl. size-0 and size>2 ciphertexts (BEHZ multiply, key switching).
// Input: byte 0 = scheme; then a program of op bytes with operands drawn by FuzzedDataProvider.
#include "seal_fuzz_common.h"
#include <fuzzer/FuzzedDataProvider.h>

using namespace seal;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
    FuzzedDataProvider fdp(data, size);
    const auto scheme = sealfuzz::pick_scheme(fdp.ConsumeIntegral<std::uint8_t>());
    const auto &e = sealfuzz::env(scheme);
    const auto &ctx = e.ctx;
    Encryptor encryptor(ctx, e.pk);
    Evaluator ev(ctx);
    const std::size_t slots = ctx.first_context_data()->parms().poly_modulus_degree();

    auto make_plain = [&](Plaintext &p) {
        if (scheme == scheme_type::ckks)
        {
            CKKSEncoder enc(ctx);
            std::vector<double> v;
            const std::size_t k = fdp.ConsumeIntegralInRange<std::size_t>(0, 8);
            for (std::size_t i = 0; i < k; i++)
            {
                v.push_back(fdp.ConsumeFloatingPointInRange<double>(-1000.0, 1000.0));
            }
            enc.encode(v, std::pow(2.0, 30), p);
        }
        else
        {
            BatchEncoder enc(ctx);
            std::vector<std::uint64_t> v;
            const std::size_t k = fdp.ConsumeIntegralInRange<std::size_t>(0, 8);
            for (std::size_t i = 0; i < k; i++)
            {
                v.push_back(fdp.ConsumeIntegral<std::uint64_t>() % ctx.first_context_data()->parms().plain_modulus().value());
            }
            v.resize(std::min<std::size_t>(v.size(), slots));
            enc.encode(v, p);
        }
    };

    try
    {
        Ciphertext regs[2];
        for (auto &r : regs)
        {
            Plaintext p;
            make_plain(p);
            encryptor.encrypt(p, r);
        }
        int steps = 0;
        while (fdp.remaining_bytes() > 0 && steps++ < 16)
        {
            const std::uint8_t op = fdp.ConsumeIntegral<std::uint8_t>();
            Ciphertext &a = regs[op & 1];
            Ciphertext &b = regs[(op >> 1) & 1];
            switch ((op >> 2) % 20)
            {
            case 0:
                ev.add_inplace(a, b);
                break;
            case 1:
                ev.sub_inplace(a, b);
                break;
            case 2:
                ev.negate_inplace(a);
                break;
            case 3:
                ev.multiply_inplace(a, b);
                break;
            case 4:
                ev.square_inplace(a);
                break;
            case 5:
                ev.relinearize_inplace(a, e.rk);
                break;
            case 6:
                ev.mod_switch_to_next_inplace(a);
                break;
            case 7:
                if (scheme == scheme_type::ckks)
                    ev.rescale_to_next_inplace(a);
                else
                    ev.mod_reduce_to_next_inplace(a);
                break;
            case 8:
                if (scheme == scheme_type::ckks)
                    ev.rotate_vector_inplace(a, fdp.ConsumeIntegralInRange<int>(-2, 2), e.gk);
                else
                    ev.rotate_rows_inplace(a, fdp.ConsumeIntegralInRange<int>(-2, 2), e.gk);
                break;
            case 9:
                if (scheme == scheme_type::ckks)
                    ev.complex_conjugate_inplace(a, e.gk);
                else
                    ev.rotate_columns_inplace(a, e.gk);
                break;
            case 10:
            {
                Plaintext p;
                make_plain(p);
                ev.multiply_plain_inplace(a, p);
                break;
            }
            case 11:
            {
                Plaintext p;
                make_plain(p);
                ev.add_plain_inplace(a, p);
                break;
            }
            case 12:
            {
                Plaintext p;
                make_plain(p);
                ev.sub_plain_inplace(a, p);
                break;
            }
            case 13:
                if (a.is_ntt_form())
                    ev.transform_from_ntt_inplace(a);
                else
                    ev.transform_to_ntt_inplace(a);
                break;
            case 14:
                ev.exponentiate_inplace(a, fdp.ConsumeIntegralInRange<std::uint64_t>(0, 4), e.rk);
                break;
            case 15:
                // Public mutator: any size, including 0 and > 2.
                a.resize(ctx, a.parms_id(), fdp.ConsumeIntegralInRange<std::size_t>(0, 5));
                break;
            case 16:
                a.is_ntt_form() = !a.is_ntt_form();
                break;
            case 17:
                a.scale() = fdp.ConsumeFloatingPoint<double>();
                break;
            case 18:
                ev.apply_galois_inplace(a, fdp.ConsumeBool() ? 3 : 2 * slots - 1, e.gk);
                break;
            case 19:
            {
                std::vector<Ciphertext> v{ a, b };
                ev.multiply_many(v, e.rk, a);
                break;
            }
            }
        }
    }
    catch (const std::exception &)
    {
    }
    return 0;
}
