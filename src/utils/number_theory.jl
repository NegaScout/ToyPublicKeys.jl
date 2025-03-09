"""
    function power_crt(
        base::BigInt,
        p::BigInt,
        q::BigInt,
        d_p::BigInt,
        d_q::BigInt,
        q_inv::BigInt,
    )

CRT for PKCS #1 based parameters.
"""
function power_crt(
    base::BigInt,
    p::BigInt,
    q::BigInt,
    d_p::BigInt,
    d_q::BigInt,
    q_inv::BigInt,
)
    m1 = Base.GMP.MPZ.powm(base, d_p, p)
    m2 = Base.GMP.MPZ.powm(base, d_q, q)
    return (m2 + ((m1 - m2) * q_inv) * q) % (p*q)
end

"""
    power_crt(base::BigInt, pow::BigInt, p::BigInt, q::BigInt)

Wrapper around core implementation, only for generating the parameters if they are not provided. 
"""
function power_crt(base::BigInt, pow::BigInt, p::BigInt, q::BigInt)
    d_p, d_q, q_inv, _ = power_crt_components(pow, p, q)
    return power_crt(base, p, q, d_p, d_q, q_inv)
end

"""
    power_crt_components(d::BigInt, p::BigInt, q::BigInt)

Utility function for calculating dth power in p*q mod [CRT](https://en.wikipedia.org/wiki/Chinese_remainder_theorem) parameters for PKCS #1.
"""
function power_crt_components(d::BigInt, p::BigInt, q::BigInt)
    d_p = d % (p - 1) # e. totient for primes
    d_q = d % (q - 1)
    q_inv = BigInt()
    Base.GMP.MPZ.invert!(q_inv, q, p)
    p_inv = BigInt()
    Base.GMP.MPZ.invert!(p_inv, p, q)
    return (d_p, d_q, q_inv, p_inv)
end

"""
    power_crt_components(e::BigInt, d::BigInt, primes::Vector{BigInt})

Utility function for calculating the [CRT](https://en.wikipedia.org/wiki/Chinese_remainder_theorem) parameters for PKCS #1.
"""
function power_crt_components(pow::BigInt, primes::Vector{BigInt})
    error("not implemented") |> throw
end
