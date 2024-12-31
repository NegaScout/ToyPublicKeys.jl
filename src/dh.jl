struct DHPrivateKey
    modulus::BigInt
    public_component::BigInt
    private_component::BigInt
end

struct DHPublicKey
    modulus::BigInt
    public_component::BigInt
end

function DHStep(key::DHPrivateKey)
    return Base.GMP.MPZ.powm(key.public_component, key.private_component, key.modulus)
end

function DHStep(intermidiary::BigInt, key::DHPrivateKey)
    return Base.GMP.MPZ.powm(intermidiary, key.private_component, key.modulus)
end

function generate_DHKeyPair(modulus::BigInt, public::BigInt, private::BigInt)
    return (DHPrivateKey(modulus, public, private), DHPublicKey(modulus, public))
end
