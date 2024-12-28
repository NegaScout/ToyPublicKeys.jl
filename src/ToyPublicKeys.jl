module ToyPublicKeys

@enum AsymetricKeyType public_key private_key
include("utils/primes.jl")
include("utils/random.jl")
include("padding/pkcs_1_v1_5.jl")
include("rsa.jl")
export RSAKey, encrypt, decrypt
end
