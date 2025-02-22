using SHA
# https://www.ietf.org/rfc/rfc2631.txt
struct DHPrivateKey
    modulus::BigInt
    public_component::BigInt
    private_component::BigInt
end

struct DHPublicKey
    modulus::BigInt
    public_component::BigInt
end

function DHStep(intermidiary::DHPublicKey, key::DHPrivateKey)
    return Base.GMP.MPZ.powm(intermidiary.public_component,
                             key.private_component,
                             key.modulus)
end

function _sha1(data:: BigInt)
    buf = Vector{UInt8}(undef, data.size)
    Base.GMP.MPZ.export!(buf, data; order=0, nails=0, endian=0)
    return SHA.sha1(buf)
end

function dh_params(p_size::Integer, q_size::Integer)
    L = p_size
    m = q_size
    m_prime = BigInt(ceil(m/160))
    L_prime = BigInt(ceil(L/160))
    N_prime = BigInt(ceil(L/1024))
    SEED = BigInt(0)
    q = big"0"
    while true
        SEED = rand(big"2" << p_size:big"2" << (2*p_size))
        U = BigInt(0)
        for i in 0:(m_prime - 1)
            _U_temp  = (_sha1(SEED + i) .⊻ _sha1(SEED + m_prime + i))
            _U = BigInt(0)
            Base.GMP.MPZ.import!(_U, length(_U_temp), 0, sizeof(eltype(_U_temp)), 0, 0, pointer(_U_temp))
            U = U + _U  * (2 << (160 * i))
        end
        q = U | (big"2" << (m - 1)) | big"1"
        if is_probab_prime_p(q, 80) ∈ [:prime, :probably_prime]
            break
        end
    end
    while true
        counter = BigInt(0)
        R = SEED + 2*m_prime + L_prime*counter
        V = BigInt(0)
        for i in 0:(L_prime - 1)
            _V = BigInt()
            _V_temp  = _sha1(R + i) * (big"2" << (160 * i))
            Base.GMP.MPZ.import!(_V, length(_V_temp), 0, sizeof(eltype(_V_temp)), 0, 0, pointer(_V_temp))
            V = V + _V * (big"2" << (160 * i))
        end
        W = V % (big"2" << L)
        X = W | (big"2" << (L - 1))
        _X = (X % (big"2" * q))
        p = X - _X + 1
        if p > (big"2" << (L - 1)) && is_probab_prime_p(p, 80) ∈ [:prime, :probably_prime]
            j = BigInt((p - 1)/q)
            g = BigInt()
            while true
                h = rand(2:(p - 2))
                g = Base.GMP.MPZ.powm(h, j, p)
                g != 1 && break
            end
            return g, p, q, SEED, counter
        else
            counter += 1
            if counter >= 4096*N_prime
                return nothing
            end
        end
    end
end

function generate_dh_key_pair(p::BigInt, g::BigInt, bits::Integer)
    private = random_bigint_from_range(bits)
    public = Base.GMP.MPZ.powm(g, private, p)
    return (DHPrivateKey(p, public, private), DHPublicKey(p, public))
end
