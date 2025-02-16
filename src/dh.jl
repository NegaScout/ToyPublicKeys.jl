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

function dh_params(bits::Integer)
    m_prime = BigInt(ceil(bits/160))
    L_prime = BigInt(ceil(bits/160))
    N_prime = BigInt(ceil(L_prime/1024))
    SEED = BigInt(0)
    while true
        SEED = rand_prime_for_dh(bits)
        U = BigInt(0)
        for i in 0:m_prime - 1
            U = U + (SHA.sha1(SEED + i) ⊻ SHA.sha1(SEED + m_prime + i)) * (2 << (160 * i))
        end
        q = U | 2 << (m - 1) | 1
        if is_probab_prime_p(q, 80) ∈ [:prime, :probably_prime]
            break
        end
    end
    while true
        counter = BigInt(0)
        R = SEED + 2*m_prime + L_prime*counter
        V = BigInt(0)
        for i in 0:L_prime-1
            V = V + SHA.sha1(R + i) * (2 << (160 * i))
        end
        W = V % 2 << L
        X = W | 2 << (L - 1)
        p = X - (X % 2 << q) + 1
        if p > (2 << (L-1)) && is_probab_prime_p(p, 80) ∈ [:prime, :probably_prime]
            return p, q, SEED, counter
        else
            counter += 1
            if counter < 4096*N
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
