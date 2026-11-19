// Seed generator for the SEAL fuzz targets (not part of the build; seeds are committed under
// mayhem/<target>/testsuite/). Writes valid serialized objects, prefixed with each harness's
// selector byte, for every scheme and compression mode.
//   clang++ -std=c++17 -I native/src -I build/native/src -I <gsl>/include mayhem/tools/gen_seeds.cpp \
//     -I mayhem/harnesses build/lib/libseal*.a ... -o gen_seeds && ./gen_seeds mayhem
#include "seal_fuzz_common.h"
#include <fstream>
#include <string>
#include <sys/stat.h>

using namespace seal;
using namespace sealfuzz;

static std::string root;
static void put(const std::string &target, const std::string &name, std::uint8_t sel, bool with_sel,
                const std::vector<seal_byte> &b)
{
    std::string d = root + "/" + target;
    mkdir(d.c_str(), 0755);
    d += "/testsuite";
    mkdir(d.c_str(), 0755);
    std::ofstream f(d + "/" + name, std::ios::binary);
    if (with_sel)
        f.put(static_cast<char>(sel));
    f.write(reinterpret_cast<const char *>(b.data()), static_cast<std::streamsize>(b.size()));
}
template <class T>
static std::vector<seal_byte> ser(const T &o, compr_mode_type m)
{
    std::vector<seal_byte> b(static_cast<std::size_t>(o.save_size(m)));
    b.resize(static_cast<std::size_t>(o.save(b.data(), b.size(), m)));
    return b;
}
static const char *mname(compr_mode_type m)
{
    return m == compr_mode_type::none ? "none" : m == compr_mode_type::zlib ? "zlib" : "zstd";
}

int main(int argc, char **argv)
{
    root = argc > 1 ? argv[1] : "mayhem";
    const scheme_type schemes[] = { scheme_type::bfv, scheme_type::bgv, scheme_type::ckks };
    const char *sn[] = { "bfv", "bgv", "ckks" };
    for (std::uint8_t s = 0; s < 3; s++)
    {
        const Env &e = env(schemes[s]);
        Encryptor enc(e.ctx, e.pk);
        enc.set_secret_key(e.sk);
        Evaluator ev(e.ctx);
        Plaintext p;
        if (schemes[s] == scheme_type::ckks)
            CKKSEncoder(e.ctx).encode(std::vector<double>{ 1.5, -2.25, 3.0 }, std::pow(2.0, 30), p);
        else
            BatchEncoder(e.ctx).encode(std::vector<std::uint64_t>{ 1, 2, 3, 4 }, p);
        Ciphertext c, c3, cl;
        enc.encrypt(p, c);
        ev.square(c, c3);
        ev.mod_switch_to_next(c, cl);
        for (auto m : { compr_mode_type::none, compr_mode_type::zlib, compr_mode_type::zstd })
        {
            std::string sfx = std::string(sn[s]) + "_" + mname(m);
            for (std::uint8_t u : { 0, 0x80 })
                put("fuzz_ciphertext_load", "ct_" + sfx + (u ? "_unsafe" : ""), s | u, true, ser(c, m));
            put("fuzz_ciphertext_load", "ct3_" + sfx, s, true, ser(c3, m));
            put("fuzz_decryptor", "ct_" + sfx, s, true, ser(c, m));
            put("fuzz_decryptor", "ct3_" + sfx, s, true, ser(c3, m));
            put("fuzz_decryptor", "ctlow_" + sfx, s, true, ser(cl, m));
            put("fuzz_plaintext_load", "pt_" + sfx, s, true, ser(p, m));
            put("fuzz_kswitchkeys_load", "relin_" + sfx, s | (0 << 2), true, ser(e.rk, m));
            put("fuzz_kswitchkeys_load", "galois_" + sfx, s | (1 << 2), true, ser(e.gk, m));
            put("fuzz_kswitchkeys_load", "kswitch_" + sfx, s | (2 << 2), true, ser(static_cast<const KSwitchKeys &>(e.rk), m));
            put("fuzz_key_load", "pk_" + sfx, s, true, ser(e.pk, m));
            put("fuzz_key_load", "sk_" + sfx, s | 4, true, ser(e.sk, m));
            put("fuzz_encparams_load", "parms_" + sfx, 0, false, ser(e.ctx.key_context_data()->parms(), m));
        }
        // Seeded (symmetric) ciphertext serialization: the compact form load_members expands.
        for (auto m : { compr_mode_type::none, compr_mode_type::zstd })
        {
            std::vector<seal_byte> b;
            auto ser_ct = enc.encrypt_symmetric(p);
            b.resize(static_cast<std::size_t>(ser_ct.save_size(m)));
            b.resize(static_cast<std::size_t>(ser_ct.save(b.data(), b.size(), m)));
            put("fuzz_ciphertext_load", std::string("ctseeded_") + sn[s] + "_" + mname(m), s, true, b);
            put("fuzz_decryptor", std::string("ctseeded_") + sn[s] + "_" + mname(m), s, true, b);
        }
        // Evaluator / encoder programs: a few fixed byte strings.
        std::vector<seal_byte> prog;
        for (int i = 0; i < 64; i++)
            prog.push_back(static_cast<seal_byte>((i * 37 + 11) & 0xff));
        put("fuzz_evaluator", std::string("prog_") + sn[s], s, true, prog);
        put("fuzz_encoder", std::string("enc_") + sn[s], s, true, prog);
    }

    // C API: BFV, N=4096, BFVDefault coeff modulus, plain modulus 786433 (same as the harness).
    {
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(4096);
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(4096));
        parms.set_plain_modulus(786433);
        SEALContext ctx(parms);
        KeyGenerator kg(ctx);
        PublicKey pk;
        kg.create_public_key(pk);
        RelinKeys rk;
        kg.create_relin_keys(rk);
        Encryptor enc(ctx, pk);
        Plaintext p("1x^3 + 2x^1 + 7");
        Ciphertext c;
        enc.encrypt(p, c);
        for (auto m : { compr_mode_type::none, compr_mode_type::zstd })
        {
            std::string sfx = mname(m);
            put("fuzz_c_load", "ct_" + sfx, 0, true, ser(c, m));
            put("fuzz_c_load", "ct_unsafe_" + sfx, 0x80, true, ser(c, m));
            put("fuzz_c_load", "pt_" + sfx, 1, true, ser(p, m));
            put("fuzz_c_load", "pk_" + sfx, 2, true, ser(pk, m));
            put("fuzz_c_load", "sk_" + sfx, 3, true, ser(kg.secret_key(), m));
            put("fuzz_c_load", "kswitch_" + sfx, 4, true, ser(static_cast<const KSwitchKeys &>(rk), m));
            put("fuzz_c_load", "parms_" + sfx, 5, true, ser(parms, m));
            put("fuzz_c_load", "modulus_" + sfx, 6, true, ser(Modulus(786433), m));
        }
        auto b = ser(c, compr_mode_type::none);
        put("fuzz_c_load", "header16", 7, true, std::vector<seal_byte>(b.begin(), b.begin() + 16));
        put("fuzz_c_load", "header8", 7, true, std::vector<seal_byte>(b.begin(), b.begin() + 8));
        put("fuzz_c_load", "header32", 7, true, std::vector<seal_byte>(b.begin(), b.begin() + 32));
    }
    for (auto t : { "1x^2 + 3", "7FFx^3 + 1x^1 + 3", "0", "Ax^4095 + 1" })
    {
        std::string s(t);
        put("fuzz_plaintext_string", std::string("poly_") + std::to_string(s.size()), 0, false,
            std::vector<seal_byte>(reinterpret_cast<const seal_byte *>(s.data()),
                                   reinterpret_cast<const seal_byte *>(s.data()) + s.size()));
    }
    return 0;
}
