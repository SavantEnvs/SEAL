// Shared setup for the SEAL fuzz harnesses (mayhem/harnesses/*.cpp).
//
// Contexts and keys are built once per process and are read-only afterwards: every SEAL API the
// harnesses call takes them by const reference. The contexts use a fixed-seed Blake2xb PRNG factory
// (EncryptionParameters::set_random_generator), so key generation and encryption are deterministic
// and each input's result depends only on that input.
#pragma once

#include "seal/seal.h"
#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <vector>

namespace sealfuzz
{
    using namespace seal;

    struct Env
    {
        SEALContext ctx;
        SecretKey sk;
        PublicKey pk;
        RelinKeys rk;
        GaloisKeys gk;

        explicit Env(const EncryptionParameters &parms) : ctx(parms, true, sec_level_type::none)
        {
            KeyGenerator kg(ctx);
            sk = kg.secret_key();
            kg.create_public_key(pk);
            kg.create_relin_keys(rk);
            // A few rotation steps (plus column rotation / conjugation) keep setup cheap.
            if (ctx.key_context_data()->parms().scheme() == scheme_type::ckks)
            {
                kg.create_galois_keys(std::vector<int>{ 1, -1, 2 }, gk);
            }
            else
            {
                kg.create_galois_keys(std::vector<int>{ 0, 1, -1, 2 }, gk);
            }
        }
    };

    inline EncryptionParameters make_parms(scheme_type scheme)
    {
        constexpr std::size_t n = 4096;
        EncryptionParameters parms(scheme);
        parms.set_poly_modulus_degree(n);
        if (scheme == scheme_type::ckks)
        {
            parms.set_coeff_modulus(CoeffModulus::Create(n, { 40, 30, 30, 40 }));
        }
        else
        {
            parms.set_coeff_modulus(CoeffModulus::BFVDefault(n));
            parms.set_plain_modulus(PlainModulus::Batching(n, 20));
        }
        prng_seed_type seed{};
        for (std::size_t i = 0; i < seed.size(); i++)
        {
            seed[i] = 0x5EA15EEDULL + i;
        }
        parms.set_random_generator(std::make_shared<Blake2xbPRNGFactory>(seed));
        return parms;
    }

    inline const Env &env(scheme_type scheme)
    {
        static const Env bfv(make_parms(scheme_type::bfv));
        static const Env bgv(make_parms(scheme_type::bgv));
        static const Env ckks(make_parms(scheme_type::ckks));
        switch (scheme)
        {
        case scheme_type::bgv:
            return bgv;
        case scheme_type::ckks:
            return ckks;
        default:
            return bfv;
        }
    }

    // Maps a selector byte to one of the three schemes.
    inline scheme_type pick_scheme(std::uint8_t b)
    {
        switch (b % 3)
        {
        case 0:
            return scheme_type::bfv;
        case 1:
            return scheme_type::bgv;
        default:
            return scheme_type::ckks;
        }
    }

    inline const seal_byte *as_bytes(const std::uint8_t *p)
    {
        return reinterpret_cast<const seal_byte *>(p);
    }
} // namespace sealfuzz
