// C API load wrappers (native/src/seal/c, the layer the .NET binding calls): Ciphertext_Load,
// Plaintext_Load, PublicKey_Load, SecretKey_Load, KSwitchKeys_Load (+ UnsafeLoad), EncParams_Load and
// Modulus_Load with a raw pointer + size; on S_OK the object is saved again through *_SaveSize/*_Save
// into a caller buffer and reloaded, and both loads must agree on the byte count.
// Kind 7 instead runs Serialization_IsValidHeader / Serialization_IsCompatibleVersion on the bytes
// with the caller-supplied size (the 5b8a7cb0 fix); a header that is not exactly 16 bytes must be
// reported invalid.
// Input: byte 0 = kind (mod 8) + bit 7 UnsafeLoad; rest = serialized object (or header bytes).
#include "seal/c/ciphertext.h"
#include "seal/c/encryptionparameters.h"
#include "seal/c/kswitchkeys.h"
#include "seal/c/modulus.h"
#include "seal/c/plaintext.h"
#include "seal/c/publickey.h"
#include "seal/c/sealcontext.h"
#include "seal/c/secretkey.h"
#include "seal/c/serialization.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace
{
    void *make_context()
    {
        void *parms = nullptr;
        if (EncParams_Create1(0x1 /* bfv */, &parms) != 0)
            std::abort();
        EncParams_SetPolyModulusDegree(parms, 4096);
        uint64_t len = 0;
        CoeffModulus_BFVDefault(4096, 128, &len, nullptr);
        std::vector<void *> coeffs(len);
        CoeffModulus_BFVDefault(4096, 128, &len, coeffs.data());
        EncParams_SetCoeffModulus(parms, len, coeffs.data());
        for (void *m : coeffs)
            Modulus_Destroy(m);
        EncParams_SetPlainModulus2(parms, 786433);
        void *ctx = nullptr;
        if (SEALContext_Create(parms, true, 128, &ctx) != 0)
            std::abort();
        EncParams_Destroy(parms);
        return ctx;
    }

    using LoadFn = long (*)(void *, void *, uint8_t *, uint64_t, int64_t *);

    struct Kind
    {
        long (*create)(void **);
        long (*destroy)(void *);
        long (*load)(void *, void *, uint8_t *, uint64_t, int64_t *);
        long (*unsafe_load)(void *, void *, uint8_t *, uint64_t, int64_t *);
        long (*save_size)(void *, uint8_t, int64_t *);
        long (*save)(void *, uint8_t *, uint64_t, uint8_t, int64_t *);
    };

    long ct_create(void **p) { return Ciphertext_Create1(nullptr, p); }
    long pt_create(void **p) { return Plaintext_Create1(nullptr, p); }
    long ep_create(void **p) { return EncParams_Create1(0x1, p); }
    long mod_create(void **p) { return Modulus_Create1(0, p); }
    // EncParams_Load / Modulus_Load take no context.
    long ep_load(void *t, void *, uint8_t *in, uint64_t n, int64_t *r) { return EncParams_Load(t, in, n, r); }
    long mod_load(void *t, void *, uint8_t *in, uint64_t n, int64_t *r) { return Modulus_Load(t, in, n, r); }

    const Kind kinds[] = {
        { ct_create, Ciphertext_Destroy, Ciphertext_Load, Ciphertext_UnsafeLoad, Ciphertext_SaveSize, Ciphertext_Save },
        { pt_create, Plaintext_Destroy, Plaintext_Load, Plaintext_UnsafeLoad, Plaintext_SaveSize, Plaintext_Save },
        { PublicKey_Create1, PublicKey_Destroy, PublicKey_Load, PublicKey_UnsafeLoad, PublicKey_SaveSize,
          PublicKey_Save },
        { SecretKey_Create1, SecretKey_Destroy, SecretKey_Load, SecretKey_UnsafeLoad, SecretKey_SaveSize,
          SecretKey_Save },
        { KSwitchKeys_Create1, KSwitchKeys_Destroy, KSwitchKeys_Load, KSwitchKeys_UnsafeLoad, KSwitchKeys_SaveSize,
          KSwitchKeys_Save },
        { ep_create, EncParams_Destroy, ep_load, ep_load, EncParams_SaveSize, EncParams_Save },
        { mod_create, Modulus_Destroy, mod_load, mod_load, Modulus_SaveSize, Modulus_Save },
    };
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
    if (size < 1)
    {
        return -1;
    }
    static void *ctx = make_context();
    const unsigned kind = (data[0] & 0x7f) % 8;
    const bool unsafe = data[0] & 0x80;
    // Exact-size heap copy so ASan sees the caller's bound.
    std::vector<uint8_t> in(data + 1, data + size);
    if (kind == 7)
    {
        // `in` is already an exact-size heap buffer. The API rejects a null pointer with E_POINTER,
        // so an empty header gets a 1-byte buffer with size 0.
        uint8_t empty = 0;
        uint8_t *hdr = in.empty() ? &empty : in.data();
        bool valid = false, compatible = false;
        Serialization_IsValidHeader(hdr, in.size(), &valid);
        Serialization_IsCompatibleVersion(hdr, in.size(), &compatible);
        // A header that is not exactly 16 bytes is never valid.
        if (in.size() != 16 && (valid || compatible))
            std::abort();
        return 0;
    }
    const Kind &k = kinds[kind];
    void *obj = nullptr;
    if (k.create(&obj) != 0)
        std::abort();
    int64_t n = 0;
    long hr = (unsafe ? k.unsafe_load : k.load)(obj, ctx, in.empty() ? nullptr : in.data(), in.size(), &n);
    if (hr == 0)
    {
        if (n <= 0 || static_cast<uint64_t>(n) > in.size())
            std::abort();
        int64_t sz = 0;
        if (k.save_size(obj, 0 /* none */, &sz) == 0 && sz > 0)
        {
            std::vector<uint8_t> out(static_cast<std::size_t>(sz));
            int64_t written = 0;
            if (k.save(obj, out.data(), out.size(), 0, &written) == 0)
            {
                void *obj2 = nullptr;
                k.create(&obj2);
                int64_t n2 = 0;
                if (k.unsafe_load(obj2, ctx, out.data(), static_cast<uint64_t>(written), &n2) != 0 || n2 != written)
                    std::abort();
                k.destroy(obj2);
            }
        }
    }
    k.destroy(obj);
    return 0;
}
