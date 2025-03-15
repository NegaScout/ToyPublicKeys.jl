using SHA
# NOTE: This RSA implementation tries to follow RFC 2313, however it is not conformant with it. Future work: conform this with RFC 2313 or better, with RFC 2437

struct pkcs1_v1_5_t end
const pkcs1_v1_5 = pkcs1_v1_5_t()

struct pkcs1_v2_2_t end
const pkcs1_v2_2 = pkcs1_v2_2_t()

"""
    RSAPrivateKey

RSAPrivateKey is PrivateKey struct for RSA.
It holds all information to derive public key and make efficient calculations.
"""
struct RSAPrivateKey
    version::Int
    modulus::BigInt
    public_exponent::BigInt
    exponent::BigInt
    primes::Vector{BigInt}
    crt_exponents::Vector{BigInt}
    crt_coefficients::Vector{BigInt}
end

"""
    RSAPrivateKey

    RSAPrivateKey is PublicKey struct for RSA.
It holds all neccecary information to perform public key computations, but not more.
"""
struct RSAPublicKey
    version::Int
    modulus::BigInt
    exponent::BigInt
end

"""
    RSAKey

Union of RSAPrivateKey and RSAPublicKey for methods, that do not require specific key.
"""
const RSAKey = Union{RSAPrivateKey,RSAPublicKey}

function validate(key::RSAPrivateKey)
    (length(key.primes) >= 2) || error("length(key.primes) < 2") |> throw
    all((key.public_exponent > 0, key.exponent > 0)) && all(key.primes .> 0) || error("all((key.public_exponent, key.exponent) .> 0, key.primes .> 0)") |> throw
    (length(key.exponent) > 0) || error("length(key.primes) < 2") |> throw
    (prod(key.primes) == key.modulus) || error("(prod(key.primes) != key.modulus)") |> throw
    ((key.exponent * key.public_exponent) % lcm((key.primes .- 1)...)) == 1 || error("(key.exponent * key.public_exponent) % lcm((key.exponent - 1), (key.public_exponent - 1)) != 1") |> throw
    (key.public_exponent * key.crt_exponents[1]) % (key.primes[1] - 1) == 1 || error(" (key.public_exponent * key.crt_exponents[1]) % (key.primes[1] - 1) != 1") |> throw
    (key.public_exponent * key.crt_exponents[2]) % (key.primes[2] - 1) == 1 || error("(key.public_exponent * key.crt_exponents[2]) % (key.primes[2] - 1) != 1") |> throw
    # is this consistent with the struct?
    (key.primes[2] * key.crt_coefficients[1]) % key.primes[1] == 1 || error("(key.primes[2] * key.crt_coefficients[2]) % key.primes[1] != 1") |> throw
end

"""
    RSAStep(::pkcs1_v1_5_t, msg::BigInt, key::RSAPrivateKey)

Fast implementation of the RSA exponentiation step when RSAPrivateKey is provided.
It uses [Chinese remainer theorem](https://en.wikipedia.org/wiki/Chinese_remainder_theorem) for very fast `exp() mod n` calculations.
"""
function RSAEP(v::pkcs1_v1_5_t, msg::BigInt, key::RSAPublicKey)
    return RSAStep(v, msg, key)
end

"""
    RSAStep(::pkcs1_v1_5_t, msg::BigInt, key::RSAPublicKey)

RSA exponentiation step when only public key is available.
Uses [repeated squares](https://en.wikipedia.org/wiki/Exponentiation_by_squaring)
and other fast modulo exponentiation tricks in its GMP implementation (Base.GMP.MPZ.powm).
"""
function RSADP(v::pkcs1_v1_5_t, msg::BigInt, key::RSAPrivateKey)
    return RSAStep(v, msg, key)
end

"""
    RSASP1(::pkcs1_v1_5_t, msg::BigInt, key::RSAPrivateKey)

"""
function RSASP1(v::pkcs1_v1_5_t, msg::BigInt, key::RSAPrivateKey)
    return RSAStep(v, msg, key)
end

"""
    RSAVP1(::pkcs1_v1_5_t, msg::BigInt, key::RSAPublicKey)

"""
function RSAVP1(v::pkcs1_v1_5_t, msg::BigInt, key::RSAPublicKey)
    return RSAStep(v, msg, key)
end

function RSAStep(::pkcs1_v1_5_t, msg::BigInt, key::RSAPrivateKey)
    if !(0 <= msg < key.modulus)
        error("msg has to be 0 <= msg < n, got: msg = $msg, n = $key.modulus")
    end
    ret = power_crt(
        msg,
        key.primes[1],
        key.primes[2],
        key.crt_exponents[1],
        key.crt_exponents[2],
        key.crt_coefficients[1],
    )
    ret < 0 && (ret += key.modulus)
    return ret
end

function RSAStep(::pkcs1_v1_5_t, msg::BigInt, key::RSAPublicKey)
    if !(0 <= msg < key.modulus)
        error("msg has to be 0 <= msg < n, got: msg = $msg, n = $key.modulus")
    end
    ret = Base.GMP.MPZ.powm(msg, key.exponent, key.modulus)
    ret < 0 && (ret += key.modulus)
    return ret
end

"""
    RSAStep(::pkcs1_v1_5_t, msg::AbstractVector{T}, key::RSAKey) where {T<:Base.BitInteger}

RSA exponentiation step for AbstractVectors (arbitrary buffers).
Only prepares the buffer for [`RSAStep(msg::BigInt, key::RSAPublicKey)`](@ref).
"""
function RSAStep(::pkcs1_v1_5_t, msg::AbstractVector{T}, key::RSAKey) where {T<:Base.BitInteger}
    msg_bi = BigInt()
    # https://gmplib.org/manual/Integer-Import-and-Export#index-mpz_005fimport
    # void mpz_import (mpz_t rop, size_t count, int order, size_t size, int endian, size_t nails, const void *op)
    _order = 0
    _endian = 0
    _nails = 0
    Base.GMP.MPZ.import!(
        msg_bi, length(msg), _order, sizeof(eltype(msg)), _endian, _nails, pointer(msg)
    )
    result = RSAStep(pkcs1_v1_5, msg_bi, key)
    # https://gmplib.org/manual/Integer-Import-and-Export#index-mpz_005fexport
    # void * mpz_export (void *rop, size_t *countp, int order, size_t size, int endian, size_t nails, const mpz_t op)
    msg_buf = Vector{T}(undef, abs(result.size))
    Base.GMP.MPZ.export!(msg_buf, result; order=_order, nails=_nails, endian=_endian)
    return msg_buf
end

"""
    RSAStep(::pkcs1_v1_5_t, msg::String, key::RSAKey)

RSA exponentiation step for Strings.
Only prepares the buffer for [`RSAStep(msg::BigInt, key::RSAPublicKey)`](@ref).
"""
function RSAStep(::pkcs1_v1_5_t, msg::String, key::RSAKey)
    msg_cu = codeunits(msg)
    result = RSAStep(pkcs1_v1_5, msg_cu, key)
    transformed_msg = String(result)
    return transformed_msg
end

function rsaes_oaep_encrypt(M::Vector{UInt8}, key::RSAPublicKey; label="", hash=SHA.sha1, MGF=MGF1)
    EM = pad(pkcs1_v2_2, M, key, label=label, hash=hash, MGF=MGF)
    m = OS2IP(EM)
    c = RSAEP(pkcs1_v1_5, m, key)
    k = (Base.GMP.MPZ.sizeinbase(key.modulus, 2)/8) |> ceil |> Integer
    C = I2OSP(c, k)
    return C
end

function rsaes_oaep_decrypt(C::Vector{UInt8}, key::RSAPrivateKey; label="", hash=SHA.sha1, MGF=MGF1)
    c = OS2IP(C)
    m = RSADP(pkcs1_v1_5, c, key)
    k = (Base.GMP.MPZ.sizeinbase(key.modulus, 2)/8) |> ceil |> Integer
    EM = I2OSP(m, k)
    M = unpad(pkcs1_v2_2, EM, key, label=label, hash=hash, MGF=MGF)
    return M
end

function rsaes_pkvs1_v1_5_encrypt(M::String, key::RSAPublicKey)
    EM = pad(pkcs1_v1_5, M)
    m = OS2IP(EM)
    c = RSAEP(pkcs1_v1_5, m, key)
    k = (Base.GMP.MPZ.sizeinbase(key.modulus, 2)/8) |> ceil |> Integer
    C = I2OSP(c, k)
    return C
end

function rsaes_pkvs1_v1_5_decrypt(C::String, key::RSAPrivateKey)
    c = OS2IP(C)
    m = RSADP(pkcs1_v1_5, c, key)
    k = (Base.GMP.MPZ.sizeinbase(key.modulus, 2)/8) |> ceil |> Integer
    EM = I2OSP(m, k)
    m = unpad(pkcs1_v1_5, EM)
    return m
end

"""
    encrypt(::pkcs1_v1_5_t,
            msg::Union{AbstractString,AbstractVector},
            key::RSAPublicKey
            ; pad_length=32)

RSA encryption function with [PKCS#1 v1.5 padding](https://www.rfc-editor.org/rfc/rfc2313#section-8.1).
"""
function encrypt(::pkcs1_v1_5_t,
                 msg::Union{AbstractString,AbstractVector},
                 key::RSAPublicKey
                 ; pad_length=32
)
    msg_padded = ToyPublicKeys.pad(pkcs1_v1_5, msg, pad_length)
    return RSAStep(pkcs1_v1_5, msg_padded, key)
end

"""
    decrypt(::pkcs1_v1_5_t, msg::AbstractString, key::RSAPrivateKey)

RSA decryption function for strings, expects [PKCS#1 v1.5 padding](https://www.rfc-editor.org/rfc/rfc2313#section-8.1).
"""
function decrypt(::pkcs1_v1_5_t, msg::AbstractString, key::RSAPrivateKey)
    msg_ = codeunits(msg)
    msg_decr = RSAStep(pkcs1_v1_5, msg_, key)
    unpaded = ToyPublicKeys.unpad(pkcs1_v1_5, vcat(typeof(msg_decr)([0]), msg_decr)) # todo: leading zero is ignored, gotta deal with this 
    return String(unpaded)
end

"""
    decrypt(::pkcs1_v1_5_t, msg::AbstractVector, key::RSAPrivateKey)

RSA decryption function for vectors (arbitrary buffers), expects [PKCS#1 v1.5 padding](https://www.rfc-editor.org/rfc/rfc2313#section-8.1).
"""
function decrypt(::pkcs1_v1_5_t, msg::AbstractVector, key::RSAPrivateKey)
    msg_decr = RSAStep(pkcs1_v1_5, msg, key)
    return ToyPublicKeys.unpad(pkcs1_v1_5, vcat(typeof(msg_decr)([0]), msg_decr)) # todo: leading zero is ignored, gotta deal with this
end

"""
    generate_rsa_key_pair(::pkcs1_v1_5_t, bits::Integer)

RSA key pair constructor (hopefully) according to [RFC 2313](https://www.rfc-editor.org/rfc/rfc2313.txt)
"""
function generate_rsa_key_pair(::pkcs1_v1_5_t, bits::Integer)
    bits <= 0 && error("bits <= 0")
    # todo: not enough bit size
    e = big"65537"
    p = rand_prime_for_rsa(bits, e)
    q = rand_prime_for_rsa(bits, e)
    while p == q
        q = rand_prime_for_rsa(bits, e)
    end
    m = p * q
    carm_tot = lcm(p − 1, q − 1)
    if !(1 < e < carm_tot)
        println(
            "Broken carm_tot, has to be (1 < e < carm_tot): e = $e, carm_tot = $carm_tot"
        )
        return Nothing
    end
    d = BigInt()
    Base.GMP.MPZ.invert!(d, big"65537", carm_tot)
    d_p, d_q, q_inv, p_inv = power_crt_components(d, p, q)
    return (
        RSAPrivateKey(0, m, e, d, [p, q],
                                  [d_p, d_q],
                                  [q_inv, p_inv]),
        RSAPublicKey(0, m, e),
    )
end

"""
    sign(::pkcs1_v1_5_t, msg::String, key::RSAPrivateKey; pad_length=32)

Sign string with RSA key.
"""
function sign(::pkcs1_v1_5_t, msg::String, key::RSAPrivateKey; pad_length=32, hash=SHA.sha1)
    error("needs reimplementing to be pkcs1_v1_5_t compliant") |> throw
    digest = hash(msg)
    msg_padded = ToyPublicKeys.pad(pkcs1_v1_5, digest, pad_length)
    return String(RSAStep(pkcs1_v1_5, msg_padded, key))
end

"""
    sign(::pkcs1_v1_5_t, msg::AbstractVector, key::RSAPrivateKey; pad_length=32)

Sign AbstractVector (arbitrary buffer using [SHA256](https://en.wikipedia.org/wiki/SHA-2)) with RSA key.
"""
function sign(::pkcs1_v1_5_t, msg::AbstractVector, key::RSAPrivateKey; pad_length=32, hash=SHA.sha1)
    error("needs reimplementing to be pkcs1_v1_5_t compliant") |> throw
    digest = hash(String(msg))
    msg_padded = ToyPublicKeys.pad(pkcs1_v1_5, digest, pad_length)
    return RSAStep(pkcs1_v1_5, msg_padded, key)
end

"""
    verify_signature(::pkcs1_v1_5_t, msg::String, signature::String, key::RSAPublicKey)

Verify the signature.
"""
function verify_signature(::pkcs1_v1_5_t, msg::String, signature::String, key::RSAPublicKey, hash=SHA.sha1)
    error("needs reimplementing to be pkcs1_v1_5_t compliant") |> throw
    signature_ = codeunits(signature)
    signature_decr = ToyPublicKeys.RSAStep(pkcs1_v1_5, signature_, key)
    unpaded_hash = ToyPublicKeys.unpad(pkcs1_v1_5, vcat(typeof(signature_decr)([0]), signature_decr)) # todo: leading zero is ignored, gotta deal with this
    digest = hash(msg)
    return unpaded_hash == digest
end
