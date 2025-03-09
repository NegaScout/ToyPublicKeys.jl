var documenterSearchIndex = {"docs":
[{"location":"api_reference/","page":"API Reference","title":"API Reference","text":"Modules = [ToyPublicKeys]","category":"page"},{"location":"api_reference/#ToyPublicKeys.RSAKey","page":"API Reference","title":"ToyPublicKeys.RSAKey","text":"RSAKey\n\nUnion of RSAPrivateKey and RSAPublicKey for methods, that do not require specific key.\n\n\n\n\n\n","category":"type"},{"location":"api_reference/#ToyPublicKeys.RSAPrivateKey","page":"API Reference","title":"ToyPublicKeys.RSAPrivateKey","text":"RSAPrivateKey\n\nRSAPrivateKey is PrivateKey struct for RSA. It holds all information to derive public key and make efficient calculations.\n\n\n\n\n\n","category":"type"},{"location":"api_reference/#ToyPublicKeys.RSAPublicKey","page":"API Reference","title":"ToyPublicKeys.RSAPublicKey","text":"RSAPrivateKey\n\nRSAPrivateKey is PublicKey struct for RSA.\n\nIt holds all neccecary information to perform public key computations, but not more.\n\n\n\n\n\n","category":"type"},{"location":"api_reference/#ToyPublicKeys.RSADP-Tuple{ToyPublicKeys.pkcs1_v1_5_t, BigInt, RSAPublicKey}","page":"API Reference","title":"ToyPublicKeys.RSADP","text":"RSAStep(::pkcs1_v1_5_t, msg::BigInt, key::RSAPublicKey)\n\nRSA exponentiation step when only public key is available. Uses repeated squares and other fast modulo exponentiation tricks in its GMP implementation (Base.GMP.MPZ.powm).\n\n\n\n\n\n","category":"method"},{"location":"api_reference/#ToyPublicKeys.RSAEP-Tuple{ToyPublicKeys.pkcs1_v1_5_t, BigInt, RSAPrivateKey}","page":"API Reference","title":"ToyPublicKeys.RSAEP","text":"RSAStep(::pkcs1_v1_5_t, msg::BigInt, key::RSAPrivateKey)\n\nFast implementation of the RSA exponentiation step when RSAPrivateKey is provided. It uses Chinese remainer theorem for very fast exp() mod n calculations.\n\n\n\n\n\n","category":"method"},{"location":"api_reference/#ToyPublicKeys.RSASP1-Tuple{ToyPublicKeys.pkcs1_v1_5_t, BigInt, RSAPrivateKey}","page":"API Reference","title":"ToyPublicKeys.RSASP1","text":"RSASP1(::pkcs1_v1_5_t, msg::BigInt, key::RSAPrivateKey)\n\n\n\n\n\n","category":"method"},{"location":"api_reference/#ToyPublicKeys.RSAStep-Tuple{ToyPublicKeys.pkcs1_v1_5_t, String, RSAKey}","page":"API Reference","title":"ToyPublicKeys.RSAStep","text":"RSAStep(::pkcs1_v1_5_t, msg::String, key::RSAKey)\n\nRSA exponentiation step for Strings. Only prepares the buffer for RSAStep(msg::BigInt, key::RSAPublicKey).\n\n\n\n\n\n","category":"method"},{"location":"api_reference/#ToyPublicKeys.RSAStep-Union{Tuple{T}, Tuple{ToyPublicKeys.pkcs1_v1_5_t, AbstractVector{T}, RSAKey}} where T<:Union{Int128, Int16, Int32, Int64, Int8, UInt128, UInt16, UInt32, UInt64, UInt8}","page":"API Reference","title":"ToyPublicKeys.RSAStep","text":"RSAStep(::pkcs1_v1_5_t, msg::AbstractVector{T}, key::RSAKey) where {T<:Base.BitInteger}\n\nRSA exponentiation step for AbstractVectors (arbitrary buffers). Only prepares the buffer for RSAStep(msg::BigInt, key::RSAPublicKey).\n\n\n\n\n\n","category":"method"},{"location":"api_reference/#ToyPublicKeys.RSAVP1-Tuple{ToyPublicKeys.pkcs1_v1_5_t, BigInt, RSAPublicKey}","page":"API Reference","title":"ToyPublicKeys.RSAVP1","text":"RSAVP1(::pkcs1_v1_5_t, msg::BigInt, key::RSAPublicKey)\n\n\n\n\n\n","category":"method"},{"location":"api_reference/#ToyPublicKeys.decrypt-Tuple{ToyPublicKeys.pkcs1_v1_5_t, AbstractString, RSAPrivateKey}","page":"API Reference","title":"ToyPublicKeys.decrypt","text":"decrypt(::pkcs1_v1_5_t, msg::AbstractString, key::RSAPrivateKey)\n\nRSA decryption function for strings, expects PKCS#1 v1.5 padding.\n\n\n\n\n\n","category":"method"},{"location":"api_reference/#ToyPublicKeys.decrypt-Tuple{ToyPublicKeys.pkcs1_v1_5_t, AbstractVector, RSAPrivateKey}","page":"API Reference","title":"ToyPublicKeys.decrypt","text":"decrypt(::pkcs1_v1_5_t, msg::AbstractVector, key::RSAPrivateKey)\n\nRSA decryption function for vectors (arbitrary buffers), expects PKCS#1 v1.5 padding.\n\n\n\n\n\n","category":"method"},{"location":"api_reference/#ToyPublicKeys.encrypt-Tuple{ToyPublicKeys.pkcs1_v1_5_t, Union{AbstractString, AbstractVector}, RSAPublicKey}","page":"API Reference","title":"ToyPublicKeys.encrypt","text":"encrypt(::pkcs1_v1_5_t,\n        msg::Union{AbstractString,AbstractVector},\n        key::RSAPublicKey\n        ; pad_length=32)\n\nRSA encryption function with PKCS#1 v1.5 padding.\n\n\n\n\n\n","category":"method"},{"location":"api_reference/#ToyPublicKeys.generate_rsa_key_pair-Tuple{ToyPublicKeys.pkcs1_v1_5_t, Integer}","page":"API Reference","title":"ToyPublicKeys.generate_rsa_key_pair","text":"generate_rsa_key_pair(::pkcs1_v1_5_t, bits::Integer)\n\nRSA key pair constructor (hopefully) according to RFC 2313\n\n\n\n\n\n","category":"method"},{"location":"api_reference/#ToyPublicKeys.is_probab_prime_p-Tuple{BigInt, Int64}","page":"API Reference","title":"ToyPublicKeys.is_probab_prime_p","text":"is_probab_prime_p(n::BigInt, n_tests::Int)\n\nBinding for GMPlib's gmpzprobabprime_p function. Only uses probability based tests as it would equal factoring n` otherwise.\n\n\n\n\n\n","category":"method"},{"location":"api_reference/#ToyPublicKeys.pad-Union{Tuple{T}, Tuple{ToyPublicKeys.pkcs1_v1_5_t, AbstractVector{T}}, Tuple{ToyPublicKeys.pkcs1_v1_5_t, AbstractVector{T}, Any}} where T<:Union{Int128, Int16, Int32, Int64, Int8, UInt128, UInt16, UInt32, UInt64, UInt8}","page":"API Reference","title":"ToyPublicKeys.pad","text":"pad(::pkcs1_v1_5_t, msg::AbstractVector{T}, pad_length=32) where {T<:Base.BitInteger}\n\nCore implementation of the PKCS#1 v1.5 padding.\n\n\n\n\n\n","category":"method"},{"location":"api_reference/#ToyPublicKeys.pad-Union{Tuple{T}, Tuple{ToyPublicKeys.pkcs1_v1_5_t, T}, Tuple{ToyPublicKeys.pkcs1_v1_5_t, T, Any}} where T<:AbstractString","page":"API Reference","title":"ToyPublicKeys.pad","text":"pad(::pkcs1_v1_5_t, msg::T, pad_length=32) where {T<:AbstractString}\n\nWrapper for the core pad function.\n\n\n\n\n\n","category":"method"},{"location":"api_reference/#ToyPublicKeys.power_crt-NTuple{4, BigInt}","page":"API Reference","title":"ToyPublicKeys.power_crt","text":"power_crt(base::BigInt, pow::BigInt, p::BigInt, q::BigInt)\n\nWrapper around core implementation, only for generating the parameters if they are not provided. \n\n\n\n\n\n","category":"method"},{"location":"api_reference/#ToyPublicKeys.power_crt-NTuple{6, BigInt}","page":"API Reference","title":"ToyPublicKeys.power_crt","text":"function power_crt(\n    base::BigInt,\n    p::BigInt,\n    q::BigInt,\n    d_p::BigInt,\n    d_q::BigInt,\n    q_inv::BigInt,\n)\n\nCRT for PKCS #1 based parameters.\n\n\n\n\n\n","category":"method"},{"location":"api_reference/#ToyPublicKeys.power_crt_components-Tuple{BigInt, BigInt, BigInt}","page":"API Reference","title":"ToyPublicKeys.power_crt_components","text":"power_crt_components(d::BigInt, p::BigInt, q::BigInt)\n\nUtility function for calculating dth power in p*q mod CRT parameters for PKCS #1.\n\n\n\n\n\n","category":"method"},{"location":"api_reference/#ToyPublicKeys.power_crt_components-Tuple{BigInt, Vector{BigInt}}","page":"API Reference","title":"ToyPublicKeys.power_crt_components","text":"power_crt_components(e::BigInt, d::BigInt, primes::Vector{BigInt})\n\nUtility function for calculating the CRT parameters for PKCS #1.\n\n\n\n\n\n","category":"method"},{"location":"api_reference/#ToyPublicKeys.rand_prime_for_rsa","page":"API Reference","title":"ToyPublicKeys.rand_prime_for_rsa","text":"rand_prime_for_rsa(bits::Integer, no_gcd_with=big\"65537\")\n\nHelper function for rsa random primes, since they should satisfy special properties.\n\n\n\n\n\n","category":"function"},{"location":"api_reference/#ToyPublicKeys.random_bigint_from_range-Tuple{Integer}","page":"API Reference","title":"ToyPublicKeys.random_bigint_from_range","text":"random_bigint_from_range(bits::Integer)\n\nCustom random big int function since core julia does not yet provide 'proper one' (in my opinion).\n\n\n\n\n\n","category":"method"},{"location":"api_reference/#ToyPublicKeys.sign-Tuple{ToyPublicKeys.pkcs1_v1_5_t, AbstractVector, RSAPrivateKey}","page":"API Reference","title":"ToyPublicKeys.sign","text":"sign(::pkcs1_v1_5_t, msg::AbstractVector, key::RSAPrivateKey; pad_length=32)\n\nSign AbstractVector (arbitrary buffer using SHA256) with RSA key.\n\n\n\n\n\n","category":"method"},{"location":"api_reference/#ToyPublicKeys.sign-Tuple{ToyPublicKeys.pkcs1_v1_5_t, String, RSAPrivateKey}","page":"API Reference","title":"ToyPublicKeys.sign","text":"sign(::pkcs1_v1_5_t, msg::String, key::RSAPrivateKey; pad_length=32)\n\nSign string with RSA key.\n\n\n\n\n\n","category":"method"},{"location":"api_reference/#ToyPublicKeys.unpad-Union{Tuple{T}, Tuple{ToyPublicKeys.pkcs1_v1_5_t, AbstractVector{T}}} where T<:Union{Int128, Int16, Int32, Int64, Int8, UInt128, UInt16, UInt32, UInt64, UInt8}","page":"API Reference","title":"ToyPublicKeys.unpad","text":"unpad(::pkcs1_v1_5_t, msg::AbstractVector{T}) where {T<:Base.BitInteger}\n\nCore implementation for the PKCS#1 v1.5 pad unwrapping.\n\n\n\n\n\n","category":"method"},{"location":"api_reference/#ToyPublicKeys.unpad-Union{Tuple{T}, Tuple{ToyPublicKeys.pkcs1_v1_5_t, T}} where T<:AbstractString","page":"API Reference","title":"ToyPublicKeys.unpad","text":"unpad(::pkcs1_v1_5_t, msg::T) where {T<:AbstractString}\n\nWrapper for the core unpad function.\n\n\n\n\n\n","category":"method"},{"location":"api_reference/#ToyPublicKeys.verify_signature","page":"API Reference","title":"ToyPublicKeys.verify_signature","text":"verify_signature(::pkcs1_v1_5_t, msg::String, signature::String, key::RSAPublicKey)\n\nVerify the signature.\n\n\n\n\n\n","category":"function"},{"location":"api_reference/","page":"API Reference","title":"API Reference","text":"","category":"page"},{"location":"examples/#Public-API-examples","page":"Examples","title":"Public API examples","text":"","category":"section"},{"location":"examples/#Encryption-and-decryption","page":"Examples","title":"Encryption and decryption","text":"","category":"section"},{"location":"examples/","page":"Examples","title":"Examples","text":"import Random\nusing ToyPublicKeys\nRandom.seed!(42)\nprivate_key, public_key = ToyPublicKeys.generate_rsa_key_pair(ToyPublicKeys.pkcs1_v1_5, 2048)\nmsg = \"Super secret message!\"\nprintln(msg)\nencrypted = ToyPublicKeys.encrypt(ToyPublicKeys.pkcs1_v1_5, msg, public_key)\nprintln(encrypted)\ndecrypted = ToyPublicKeys.decrypt(ToyPublicKeys.pkcs1_v1_5, encrypted, private_key)\nprintln(decrypted)","category":"page"},{"location":"examples/#Signatures-and-their-verification","page":"Examples","title":"Signatures and their verification","text":"","category":"section"},{"location":"examples/","page":"Examples","title":"Examples","text":"import Random\nusing ToyPublicKeys\nRandom.seed!(42)\nprivate_key, public_key = ToyPublicKeys.generate_rsa_key_pair(ToyPublicKeys.pkcs1_v1_5, 2048)\nmsg = \"Super authentic message!\"\nprintln(\"Currently this feature is disabled\")\n#println(msg)\n#signature = ToyPublicKeys.sign(ToyPublicKeys.pkcs1_v1_5, msg, private_key)\n#println(signature)\n#authentic = ToyPublicKeys.verify_signature(ToyPublicKeys.pkcs1_v1_5, msg, signature, public_key)\n#println(authentic)","category":"page"},{"location":"","page":"Home","title":"Home","text":"CurrentModule = ToyPublicKeys","category":"page"},{"location":"#ToyPublicKeys","page":"Home","title":"ToyPublicKeys","text":"","category":"section"},{"location":"","page":"Home","title":"Home","text":"Documentation for ToyPublicKeys.","category":"page"}]
}
