struct RSAKey
    key_module::BigInt
    key_component::BigInt
    type:: AsymetricKeyType
end

function RSAStep(m::BigInt, e::BigInt, n::BigInt)
    return (m ^ e) % n
end

function encrypt(msg, key::RSAKey)
    return RSAStep(msg, key.key_component, key.key_module)
end

# Decryption using the private key
function decrypt(msg, key::RSAKey)
    return RSAStep(msg, key.key_component, key.key_module)
end
