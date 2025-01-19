"""
    power_crt(
        base::BigInt,
        p::BigInt,
        q::BigInt,
        p_pow::BigInt,
        q_param_p::BigInt,
        q_pow::BigInt,
        q_param_q::BigInt,
    )

Core implementation of exponentiation over modulus using [CRT](https://en.wikipedia.org/wiki/Chinese_remainder_theorem).
"""
function power_crt(
    base::BigInt,
    p::BigInt,
    q::BigInt,
    p_pow::BigInt,
    q_param_p::BigInt,
    q_pow::BigInt,
    q_param_q::BigInt,
)
    p_base = base % p
    z_p_result = Base.GMP.MPZ.powm(p_base, p_pow, p)

    q_base = base % q
    z_q_result = Base.GMP.MPZ.powm(q_base, q_pow, q)
    return (z_p_result * q_param_p + z_q_result * q_param_q) % (p * q)
end

"""
    power_crt(base::BigInt, pow::BigInt, p::BigInt, q::BigInt)

Wrapper around core implementation, only for generating the parameters if they are not provided. 
"""
function power_crt(base::BigInt, pow::BigInt, p::BigInt, q::BigInt)
    p_pow, q_param_p, q_pow, q_param_q = power_crt_components(pow, p, q)
    return power_crt(base, p, q, p_pow, q_param_p, q_pow, q_param_q)
end

"""
    power_crt_components(pow::BigInt, p::BigInt, q::BigInt)

Utility function for calculating the [CRT](https://en.wikipedia.org/wiki/Chinese_remainder_theorem) parameters.
"""
function power_crt_components(pow::BigInt, p::BigInt, q::BigInt)
    p_pow = pow % (p - 1) # pow % φ(p)
    q_param_p = BigInt()
    Base.GMP.MPZ.invert!(q_param_p, q, p)
    q_param_p *= q

    q_pow = pow % (q - 1) # pow % φ(q)
    q_param_q = BigInt()
    Base.GMP.MPZ.invert!(q_param_q, p, q)
    q_param_q *= p

    return (p_pow, q_param_p, q_pow, q_param_q)
end
