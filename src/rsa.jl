using SHA
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
    RSAPublicKey

    RSAPublicKey is PublicKey struct for RSA.
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
function RSAStep(::pkcs1_v1_5_t, msg::Vector{UInt8}, key::RSAKey)
    msg_bi = OS2IP(msg)
    result = RSAStep(pkcs1_v1_5, msg_bi, key)
    xLen = (Base.GMP.MPZ.sizeinbase(result, 2) / 8) |> ceil |> Integer
    ret = I2OSP(result, xLen)
    return ret
end

"""
    RSAStep(::pkcs1_v1_5_t, msg::String, key::RSAKey)

RSA exponentiation step for Strings.
Only prepares the buffer for [`RSAStep(msg::BigInt, key::RSAPublicKey)`](@ref).
"""
function RSAStep(::pkcs1_v1_5_t, msg::String, key::RSAKey)
    msg_cu = Vector{UInt8}(msg)
    result = RSAStep(pkcs1_v1_5, msg_cu, key)
    transformed_msg = String(result)
    return transformed_msg
end

"""
    encrypt(::pkcs1_v1_5_t,
            msg::Vector{UInt8},
            key::RSAPublicKey)

RSA encryption function with [PKCS#1 v1.5 padding](https://www.rfc-editor.org/rfc/rfc2313#section-8.1).
"""
function encrypt(::pkcs1_v1_5_t,
                 msg::Vector{UInt8},
                 key::RSAPublicKey)
    return rsaes_pkvs1_v1_5_encrypt(msg, key)
end

"""
    encrypt(::pkcs1_v2_2_t,
            msg::Vector{UInt8},
            key::RSAPublicKey)

RSA encryption function with [PKCS#1 v1.5 padding](https://www.rfc-editor.org/rfc/rfc2313#section-8.1).
"""
function encrypt(::pkcs1_v2_2_t,
                 msg::Vector{UInt8},
                 key::RSAPublicKey)
    return rsaes_oaep_encrypt(msg, key)
end

"""
    encrypt(msg::Vector{UInt8},
            key::RSAPublicKey)

RSA encryption function with [PKCS#1 v1.5 padding](https://www.rfc-editor.org/rfc/rfc2313#section-8.1).
"""
function encrypt(msg::Vector{UInt8},
                 key::RSAPublicKey)
    return rsaes_oaep_encrypt(msg, key)
end

"""
    decrypt(::pkcs1_v1_5_t,
            msg::Vector{UInt8},
            key::RSAPrivateKey)

RSA decryption function for strings, expects [PKCS#1 v1.5 padding](https://www.rfc-editor.org/rfc/rfc2313#section-8.1).
"""
function decrypt(::pkcs1_v1_5_t,
                 msg::Vector{UInt8},
                 key::RSAPrivateKey)
    return rsaes_pkvs1_v1_5_decrypt(msg, key)
end

"""
    decrypt(::pkcs1_v2_2_t,
            msg::Vector{UInt8},
            key::RSAPrivateKey)

RSA decryption function for strings, expects [PKCS#1 v1.5 padding](https://www.rfc-editor.org/rfc/rfc2313#section-8.1).
"""
function decrypt(::pkcs1_v2_2_t,
                 msg::Vector{UInt8},
                 key::RSAPrivateKey)
    return rsaes_oaep_decrypt(msg, key)
end

"""
    decrypt(msg::Vector{UInt8},
            key::RSAPrivateKey)

RSA decryption function for strings, expects [PKCS#1 v1.5 padding](https://www.rfc-editor.org/rfc/rfc2313#section-8.1).
"""
function decrypt(msg::Vector{UInt8},
                 key::RSAPrivateKey)
    return rsaes_oaep_decrypt(msg, key)
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
    sign(::pkcs1_v1_5_t,
         msg::Vector{UInt8},
         key::RSAPrivateKey)
Sign string with RSA key.
"""
function sign(::pkcs1_v1_5_t,
              msg::Vector{UInt8},
              key::RSAPrivateKey)
    return rsassa_pkcs1_v1_5_sign(msg, key)
end

"""
    sign(::pkcs1_v2_2_t,
         msg::Vector{UInt8},
         key::RSAPrivateKey)
Sign string with RSA key.
"""
function sign(::pkcs1_v2_2_t,
              msg::Vector{UInt8},
              key::RSAPrivateKey)
    return rsassa_pss_sign(msg, key)
end

"""
    sign(msg::Vector{UInt8},
         key::RSAPrivateKey)
Sign string with RSA key.
"""
function sign(msg::Vector{UInt8},
              key::RSAPrivateKey)
    return rsassa_pss_sign(msg, key)
end

"""
    verify_signature(::pkcs1_v1_5_t,
                     msg::Vector{UInt8},
                     signature::Vector{UInt8},
                     key::RSAPublicKey)

Verify the signature.
"""
function verify_signature(::pkcs1_v1_5_t,
                          msg::Vector{UInt8},
                          signature::Vector{UInt8},
                          key::RSAPublicKey)
    return rsassa_pkcs1_v1_5_verify(msg, signature, key)
end

"""
    verify_signature(::pkcs1_v2_2_t,
                     msg::Vector{UInt8},
                     signature::Vector{UInt8},
                     key::RSAPublicKey)

Verify the signature.
"""
function verify_signature(::pkcs1_v2_2_t,
                          msg::Vector{UInt8},
                          signature::Vector{UInt8},
                          key::RSAPublicKey)
    return rsassa_pss_verify(msg, signature, key)
end

"""
    verify_signature(msg::Vector{UInt8},
                     signature::Vector{UInt8},
                     key::RSAPublicKey)

Verify the signature.
"""
function verify_signature(msg::Vector{UInt8},
                          signature::Vector{UInt8},
                          key::RSAPublicKey)
    return rsassa_pss_verify(msg, signature, key)
end
