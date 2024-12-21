module ToyPublicKeys

@enum AsymetricKeyType public_key private_key

include("RSA.jl")
export RSAKey, encrypt, decrypt
end
