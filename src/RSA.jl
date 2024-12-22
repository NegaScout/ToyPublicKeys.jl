struct RSAKey
    key_module::BigInt
    key_component::BigInt
    type:: AsymetricKeyType
end

function RSAStep(msg::BigInt, e::BigInt, n::BigInt)
    return (msg ^ e) % n
end
end

function encrypt(msg, key::RSAKey)
    return RSAStep(msg, key.key_component, key.key_module)
end

# Decryption using the private key
function decrypt(msg, key::RSAKey)
    return RSAStep(msg, key.key_component, key.key_module)
end
