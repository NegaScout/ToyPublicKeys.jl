using SHA
# NOTE: This RSA implementation tries to follow RFC 2313, however it is not conformant with it. Future work: conform this with RFC 2313 or better, with RFC 2437

"""
    RSAPrivateKey is PrivateKey struct for RSA.
    It holds all information to derive public key and make efficient calculations.
"""
struct RSAPrivateKey
    version::Int
    modulus::BigInt
    public_exponent::BigInt
    exponent::BigInt
    primes::Tuple{BigInt,BigInt}
    crt_exponents::Tuple{BigInt,BigInt}
    crt_coefficients::Tuple{BigInt,BigInt}
end

"""
    RSAPrivateKey is PublicKey struct for RSA.
    It holds all neccecary information to perform public key computations, but not more.
"""
struct RSAPublicKey
    version::Int
    modulus::BigInt
    exponent::BigInt
end

const RSAKey = Union{RSAPrivateKey,RSAPublicKey}

"""
    Fast implementation of the RSA exponentiation step, when RSAPrivateKey is provided.
    It uses Chinese remainer theorem for very fast `exp() mod n` calculations.
"""
function RSAStep(msg::BigInt, key::RSAPrivateKey)
    if !(0 <= msg < key.modulus)
        error("msg has to be 0 <= msg < n, got: msg = $msg, n = $key.modulus")
    end
    return power_crt(
        msg,
        key.primes[1],
        key.primes[2],
        key.crt_exponents[1],
        key.crt_coefficients[1],
        key.crt_exponents[2],
        key.crt_coefficients[2],
    )
end

"""
    RSA exponentiation step when only public key is available. 
    Uses repeated squares and other fast modulo exponentiation tricks in its GMP implementation.
"""
function RSAStep(msg::BigInt, key::RSAPublicKey)
    if !(0 <= msg < key.modulus)
        error("msg has to be 0 <= msg < n, got: msg = $msg, n = $key.modulus")
    end
    return Base.GMP.MPZ.powm(msg, key.exponent, key.modulus)
end

"""
    RSA exponentiation step for AbstractVectors (arbitrary buffers).
    Same as the core BigInt version but with Vector to BigInt construction
    and deconstruction.
"""
function RSAStep(msg::AbstractVector{T}, key::RSAKey) where {T<:Base.BitInteger}
    msg_bi = BigInt()
    # https://gmplib.org/manual/Integer-Import-and-Export#index-mpz_005fimport
    # void mpz_import (mpz_t rop, size_t count, int order, size_t size, int endian, size_t nails, const void *op)
    _order = 0
    _endian = 0
    _nails = 0
    Base.GMP.MPZ.import!(
        msg_bi, length(msg), _order, sizeof(eltype(msg)), _endian, _nails, pointer(msg)
    )
    result = RSAStep(msg_bi, key)
    # https://gmplib.org/manual/Integer-Import-and-Export#index-mpz_005fexport
    # void * mpz_export (void *rop, size_t *countp, int order, size_t size, int endian, size_t nails, const mpz_t op)
    msg_buf = Vector{T}(undef, result.size)
    Base.GMP.MPZ.export!(msg_buf, result; order=_order, nails=_nails, endian=_endian)
    return msg_buf
end

"""
    RSA exponentiation step for Strings.
"""
function RSAStep(msg::String, key::RSAKey)
    msg_cu = codeunits(msg)
    result = RSAStep(msg_cu, key)
    transformed_msg = String(result)
    return transformed_msg
end

"""
    RSA encryption function with random padding.
"""
function encrypt(
    msg::Union{AbstractString,AbstractVector}, key::RSAPublicKey; pad_length=32
)
    msg_padded = ToyPublicKeys.pad(msg, pad_length)
    return RSAStep(msg_padded, key)
end

"""
    RSA decryption function for strings.
"""
function decrypt(msg::AbstractString, key::RSAPrivateKey)
    msg_ = codeunits(msg)
    msg_decr = RSAStep(msg_, key)
    unpaded = ToyPublicKeys.unpad(vcat(typeof(msg_decr)([0]), msg_decr)) # todo: leading zero is ignored, gotta deal with this 
    return String(unpaded)
end

"""
    RSA decryption function for vectors.
"""
function decrypt(msg::AbstractVector, key::RSAPrivateKey)
    msg_decr = RSAStep(msg, key)
    return ToyPublicKeys.unpad(vcat(typeof(msg_decr)([0]), msg_decr)) # todo: leading zero is ignored, gotta deal with this
end

"""
    RSA key pair constructor.
"""
function generate_rsa_key_pair(bits::Integer)
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
    p_pow, q_param_p, q_pow, q_param_q = power_crt_components(d, p, q)
    return (
        RSAPrivateKey(0, m, e, d, (p, q), (p_pow, q_pow), (q_param_p, q_param_q)),
        RSAPublicKey(0, m, e),
    )
end

"""
    Sign string with RSA key.
"""
function sign(msg::String, key::RSAPrivateKey; pad_length=32)
    digest = SHA.sha256(msg)
    msg_padded = ToyPublicKeys.pad(digest, pad_length)
    return String(RSAStep(msg_padded, key))
end

"""
    Sign AbstractVector (arbitrary buffer) with RSA key.
"""
function sign(msg::AbstractVector, key::RSAPrivateKey; pad_length=32)
    digest = SHA.sha256(String(msg))
    msg_padded = ToyPublicKeys.pad(digest, pad_length)
    return RSAStep(msg_padded, key)
end

"""
    Verify the sign result.
"""
function verify_signature(msg::String, signature::String, key::RSAPublicKey; pad_length=32)
    signature_ = codeunits(signature)
    signature_decr = ToyPublicKeys.RSAStep(signature_, key)
    unpaded_hash = ToyPublicKeys.unpad(vcat(typeof(signature_decr)([0]), signature_decr)) # todo: leading zero is ignored, gotta deal with this
    digest = SHA.sha256(msg)
    return unpaded_hash == digest
end
