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

function power_crt(base::BigInt, pow::BigInt, p::BigInt, q::BigInt)
    p_pow, q_param_p, q_pow, q_param_q = power_crt_components(pow, p, q)
    p_base = base % p
    z_p_result = Base.GMP.MPZ.powm(p_base, p_pow, p)

    q_base = base % q
    z_q_result = Base.GMP.MPZ.powm(q_base, q_pow, q)
    return (z_p_result * q_param_p + z_q_result * q_param_q) % (p * q)
end

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
