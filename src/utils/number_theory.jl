function power_crt(base::BigInt, pow::BigInt, p::BigInt, q::BigInt)
    p_base = base % p
    p_pow = pow % (p - 1) # pow % φ(p)
    z_p_result = Base.GMP.MPZ.powm(p_base, p_pow, p)
    q_param_p = BigInt()
    Base.GMP.MPZ.invert!(q_param_p, q, p)
    q_param_p *= q

    q_base = base % q
    q_pow = pow % (q - 1) # pow % φ(q)
    z_q_result = Base.GMP.MPZ.powm(q_base, q_pow, q)
    q_param_q = BigInt()
    Base.GMP.MPZ.invert!(q_param_q, p, q)
    q_param_q *= p

    return (z_p_result * q_param_p + z_q_result * q_param_q) % (p * q)
end
