// Plaintext(const std::string &hex_poly): the hex-polynomial text parser ("7FFx^3 + 1x^1 + 3"),
// to_string() and re-parse (must round-trip), then BFV encryption + decryption of the parsed
// plaintext, which must decrypt back to itself when it is valid for the context.
// Input: the polynomial text.
#include "seal_fuzz_common.h"
#include <cstdlib>
#include <string>

using namespace seal;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
    const std::string s(reinterpret_cast<const char *>(data), size);
    Plaintext p;
    try
    {
        p = s;
    }
    catch (const std::exception &)
    {
        return -1; // the library refused to parse the input
    }
    Plaintext q(p.to_string());
    if (q != p)
    {
        std::abort();
    }
    const auto &e = sealfuzz::env(scheme_type::bfv);
    if (!is_valid_for(p, e.ctx))
    {
        return 0;
    }
    Ciphertext c;
    Encryptor(e.ctx, e.sk).encrypt_symmetric(p, c);
    Plaintext r;
    Decryptor(e.ctx, e.sk).decrypt(c, r);
    if (r != p)
    {
        std::abort();
    }
    return 0;
}
