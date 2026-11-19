// Ciphertext::load / unsafe_load: SEALHeader parsing (incl. the 3.4 header upgrade), zlib/zstd
// decompression, Ciphertext::load_members (seeded-ciphertext expansion), is_valid_for. A loaded
// ciphertext is saved and reloaded, so the round trip must agree.
// Input: byte 0 = scheme (bits 0-1, mod 3) + bit 7 selects unsafe_load; rest = serialized Ciphertext.
#include "seal_fuzz_common.h"
#include <cstdlib>

using namespace seal;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
    if (size < 1)
    {
        return -1;
    }
    const auto &e = sealfuzz::env(sealfuzz::pick_scheme(data[0] & 0x03));
    const bool unsafe = data[0] & 0x80;
    Ciphertext c;
    try
    {
        if (unsafe)
        {
            c.unsafe_load(e.ctx, sealfuzz::as_bytes(data + 1), size - 1);
            if (!is_valid_for(c, e.ctx))
            {
                return -1;
            }
        }
        else
        {
            c.load(e.ctx, sealfuzz::as_bytes(data + 1), size - 1);
        }
    }
    catch (const std::exception &)
    {
        return -1; // the library refused to parse the input
    }

    for (auto mode : { compr_mode_type::none, compr_mode_type::zstd })
    {
        std::vector<seal_byte> buf(static_cast<std::size_t>(c.save_size(mode)));
        auto n = c.save(buf.data(), buf.size(), mode);
        Ciphertext d;
        d.load(e.ctx, buf.data(), static_cast<std::size_t>(n));
        if (d.size() != c.size() || d.parms_id() != c.parms_id() || d.is_ntt_form() != c.is_ntt_form() ||
            d.dyn_array().size() != c.dyn_array().size() ||
            !std::equal(c.dyn_array().cbegin(), c.dyn_array().cend(), d.dyn_array().cbegin()))
        {
            std::abort();
        }
    }
    return 0;
}
