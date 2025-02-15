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
    p = rand_prime_for_dh(bits)
    q = rand_prime_for_dh(bits)
    j = BigInt(ceil((p - 1) / q))
    h = big"0"
    g = big"1"
    while true
        h = rand(big"2":BigInt(p-2))
        g = Base.GMP.MPZ.powm(h, j, p)
        if g != 1
            break
        end
    end
    return (p, g)
end

function generate_dh_key_pair(p::BigInt, g::BigInt, bits::Integer)
    private = random_bigint_from_range(bits)
    public = Base.GMP.MPZ.powm(g, private, p)
    return (DHPrivateKey(p, public, private), DHPublicKey(p, public))
end
