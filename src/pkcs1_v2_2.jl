function I2OSP(x::BigInt, xLen::Integer)
    _order = 0
    _endian = 0
    _nails = 0
    n = (Base.GMP.MPZ.sizeinbase(x, 2) / 8) |> ceil |> Integer
    ret = zeros(UInt8, n)
    Base.GMP.MPZ.export!(ret, x; order=_order, nails=_nails, endian=_endian)
    ret_len = ret |> length
    if ret_len < xLen
        ret = vcat(zeros(UInt8, xLen - ret_len), ret)
    elseif ret_len > xLen
        error("ret_len > xLen") |> throw
    end
    return ret
end

function OS2IP(x::Vector{UInt8})
    bi = BigInt()
    _order = 0
    _endian = 0
    _nails = 0
    Base.GMP.MPZ.import!(
        bi, length(x), _order, sizeof(eltype(x)), _endian, _nails, pointer(x)
    )
    return bi
end

function rsaes_oaep_encode(msg::Vector{UInt8},
                           key::RSAKey;
                           label=UInt8[],
                           MGF=ToyPublicKeys.MGF1,
                           hash=SHA.sha1)
    k = (Base.GMP.MPZ.sizeinbase(key.modulus, 2)/8) |> ceil |> Integer
    lHash = hash(label)
    hLen = lHash |> length
    LLen = label |> length
    LLen > (big"2" << 60) && throw(error("label too long"))
    mLen = msg |> length
    mLen > k - 2 * hLen - 2 && throw(error("message too long"))
    pLen = (k - mLen - 2 * hLen - 2)
    PS = zeros(UInt8, pLen)
    seed = rand(UInt8, hLen)
    dbMask = MGF(seed, k - hLen - 1, hash=hash)
    DB = vcat(lHash, PS, ones(UInt8, 1), msg)
    maskedDB = DB .⊻ dbMask
    seedMask = MGF(maskedDB, hLen)
    maskedSeed = seed .⊻ seedMask
    EM = vcat(zeros(UInt8, 1), maskedSeed, maskedDB)
    return EM
end

function rsaes_oaep_decode(msg::Vector{UInt8},
                           key::RSAKey;
                           label=UInt8[],
                           MGF=ToyPublicKeys.MGF1,
                           hash=SHA.sha1)
    k = (Base.GMP.MPZ.sizeinbase(key.modulus, 2)/8) |> ceil |> Integer
    lHash = hash(label)
    hLen = lHash |> length
    Y = msg[1]
    Y != 0 && error("Y != 0") |> throw
    maskedSeed = msg[2:end][1:hLen]
    DBLen = k - hLen - 1
    maskedDB = msg[2:end][hLen + 1:end]
    seedMask = MGF(maskedDB, hLen)
    seed = maskedSeed .⊻ seedMask
    dbMask = MGF(seed, k - hLen - 1)
    DB = maskedDB .⊻ dbMask
    lHashPrime = DB[1:hLen]
    lHashPrime != lHash && error("lHashPrime != lHash")
    PSIndexInView = findfirst(a -> a==1, DB[hLen + 1:end])
    isnothing(PSIndexInView) && error("not EME-OAEP encoded or malformed")
    PSIndex = PSIndexInView + hLen
    PS = DB[hLen + 1:PSIndex - 1]
    any(PS .!= 0) && error("PS should be zero filled vector") |> throw
    X = DB[PSIndex]
    X != 1 && error("X != 1") |> throw
    M = DB[PSIndex + 1:end]
    return M
end

function MGF1(mgfSeed::Vector{UInt8},
              maskLen:: Integer;
              hash = SHA.sha1)
    hLen = hash(UInt8[]) |> length
    maskLen >= (2 << 32) && error("mask too long") |> throw
    T = zeros(UInt8, 0)
    for counter in big"0":BigInt((ceil(maskLen / hLen) - 1))
        C = I2OSP(counter, 4)
        _T = vcat(mgfSeed, C)
        __T = hash(_T)
        T = vcat(T, __T)
    end
    return T[1:maskLen]
end

function emsa_pss_encode(M::Vector{UInt8},
                         emBits::Integer;
                         MGF=ToyPublicKeys.MGF1,
                         hash=SHA.sha1,
                         sLen=0)
    hLen = hash(UInt8[]) |> length
    (emBits >= 8*hLen + 8 * sLen + 9) || error("emBits !>= 8hLen + 8 * sLen + 9") |> throw
    emLen = ceil(emBits/8) |> Integer
    emLen < hLen + sLen + 2 && error("encoding error") |> throw
    length(M) > (big"2" << 60) && error("message too long") |> throw
    salt = UInt8[]
    if sLen > 0
        salt = rand(UInt8, sLen)
    end
    mHash = hash(M)
    MPrime = vcat(zeros(UInt8, 8), mHash, salt)
    H = hash(MPrime)
    PS = zeros(UInt8, emLen - sLen - hLen - 2)
    DB = vcat(PS, ones(UInt8, 1), salt)
    dbMask = MGF(H, emLen - hLen - 1)
    maskedDB = DB .⊻ dbMask
    maskedDB[1] &= 0xFF >> (8 * emLen - emBits)
    EM = vcat(maskedDB, H, UInt8[0xbc])
    return EM
end

function emsa_pss_verify(M::Vector{UInt8},
                         EM::Vector{UInt8},
                         emBits::Integer;
                         MGF=ToyPublicKeys.MGF1,
                         hash=SHA.sha1,
                         sLen=0)
    length(M) > (big"2" << 60) && error("inconsistent") |> throw
    mHash = hash(M)
    hLen = mHash |> length
    emLen = ceil(emBits/8) |> Integer
    emLen < hLen + sLen + 2 && error("inconsistent") |> throw
    EM[end] != 0xbc && error("inconsistent") |> throw
    maskedDB = EM[1:emLen - hLen - 1]
    H = EM[emLen - hLen:emLen - 1]
    (maskedDB[1] & ~(0xFF >> (8 * emLen - emBits))) != 0 && error("inconsistent") |> throw
    dbMask = MGF(H, emLen - hLen - 1)
    DB = maskedDB .⊻ dbMask
    DB[1] &= 0xFF >> (8 * emLen - emBits)
    (DB[1:emLen - hLen - sLen - 2] .!= 0) |> any && error("inconsistent") |> throw
    DB[emLen - hLen - sLen - 1] != 1 && error("inconsistent") |> throw
    salt = DB[end - sLen + 1 : end]
    MPrime = MPrime = vcat(zeros(UInt8, 8), mHash, salt)
    HPrime = hash(MPrime)
    return H == HPrime
end

function rsaes_oaep_encrypt(M::Vector{UInt8},
                            key::RSAPublicKey;
                            label="",
                            hash=SHA.sha1,
                            MGF=MGF1)
    EM = rsaes_oaep_encode(M, key, label=label, hash=hash, MGF=MGF)
    m = OS2IP(EM)
    c = RSAEP(pkcs1_v1_5, m, key)
    k = (Base.GMP.MPZ.sizeinbase(key.modulus, 2)/8) |> ceil |> Integer
    C = I2OSP(c, k)
    return C
end

function rsaes_oaep_decrypt(C::Vector{UInt8},
                            key::RSAPrivateKey;
                            label="",
                            hash=SHA.sha1,
                            MGF=MGF1)
    c = OS2IP(C)
    m = RSADP(pkcs1_v1_5, c, key)
    k = (Base.GMP.MPZ.sizeinbase(key.modulus, 2)/8) |> ceil |> Integer
    EM = I2OSP(m, k)
    M = rsaes_oaep_decode(EM, key, label=label, hash=hash, MGF=MGF)
    return M
end

function rsaes_pkvs1_v1_5_encrypt(M::String, key::RSAPublicKey)
    EM = pad(pkcs1_v1_5, M)
    m = OS2IP(EM)
    c = RSAEP(pkcs1_v1_5, m, key)
    k = (Base.GMP.MPZ.sizeinbase(key.modulus, 2)/8) |> ceil |> Integer
    C = I2OSP(c, k)
    return C
end

function rsaes_pkvs1_v1_5_decrypt(C::String,
                                  key::RSAPrivateKey)
    c = OS2IP(C)
    m = RSADP(pkcs1_v1_5, c, key)
    k = (Base.GMP.MPZ.sizeinbase(key.modulus, 2)/8) |> ceil |> Integer
    EM = I2OSP(m, k)
    m = unpad(pkcs1_v1_5, EM)
    return m
end

function rsassa_pss_sign(M::Vector{UInt8},
                         key::RSAPrivateKey)
    modBits = Base.GMP.MPZ.sizeinbase(key.modulus, 2)
    EM = emsa_pss_encode(M, modBits - 1)
    m = OS2IP(EM)
    s = RSASP1(pkcs1_v1_5, m, key)
    k = (modBits/8) |> ceil |> Integer
    S = I2OSP(s, k)
    return S
end

function rsassa_pss_verify(M::Vector{UInt8},
                           S::Vector{UInt8},
                           key::RSAPublicKey)
    modBits = Base.GMP.MPZ.sizeinbase(key.modulus, 2)
    k = (modBits/8) |> ceil |> Integer
    length(S) !=  k && error("invalid signature") |> throw
    s = OS2IP(S)
    m = RSAVP1(pkcs1_v1_5, s, key)
    emLen = ceil((modBits - 1)/8) |> Integer
    EM = I2OSP(m, emLen)
    result = emsa_pss_verify(M, EM, modBits - 1)
    return result
end

function validate(key::RSAPrivateKey)
    (length(key.primes) >= 2) || error("length(key.primes) < 2") |> throw
    all((key.public_exponent > 0, key.exponent > 0)) && all(key.primes .> 0) || error("all((key.public_exponent, key.exponent) .> 0, key.primes .> 0)") |> throw
    (length(key.exponent) > 0) || error("length(key.primes) < 2") |> throw
    (prod(key.primes) == key.modulus) || error("(prod(key.primes) != key.modulus)") |> throw
    ((key.exponent * key.public_exponent) % lcm((key.primes .- 1)...)) == 1 || error("(key.exponent * key.public_exponent) % lcm((key.exponent - 1), (key.public_exponent - 1)) != 1") |> throw
    (key.public_exponent * key.crt_exponents[1]) % (key.primes[1] - 1) == 1 || error(" (key.public_exponent * key.crt_exponents[1]) % (key.primes[1] - 1) != 1") |> throw
    (key.public_exponent * key.crt_exponents[2]) % (key.primes[2] - 1) == 1 || error("(key.public_exponent * key.crt_exponents[2]) % (key.primes[2] - 1) != 1") |> throw
    # is this consistent with the struct?
    (key.primes[2] * key.crt_coefficients[1]) % key.primes[1] == 1 || error("(key.primes[2] * key.crt_coefficients[2]) % key.primes[1] != 1") |> throw
end

"""
    RSAStep(::pkcs1_v1_5_t, msg::BigInt, key::RSAPrivateKey)

Fast implementation of the RSA exponentiation step when RSAPrivateKey is provided.
It uses [Chinese remainer theorem](https://en.wikipedia.org/wiki/Chinese_remainder_theorem) for very fast `exp() mod n` calculations.
"""
function RSAEP(v::pkcs1_v1_5_t, msg::BigInt, key::RSAPublicKey)
    return RSAStep(v, msg, key)
end

"""
    RSAStep(::pkcs1_v1_5_t, msg::BigInt, key::RSAPublicKey)

RSA exponentiation step when only public key is available.
Uses [repeated squares](https://en.wikipedia.org/wiki/Exponentiation_by_squaring)
and other fast modulo exponentiation tricks in its GMP implementation (Base.GMP.MPZ.powm).
"""
function RSADP(v::pkcs1_v1_5_t, msg::BigInt, key::RSAPrivateKey)
    return RSAStep(v, msg, key)
end

"""
    RSASP1(::pkcs1_v1_5_t, msg::BigInt, key::RSAPrivateKey)

"""
function RSASP1(v::pkcs1_v1_5_t, msg::BigInt, key::RSAPrivateKey)
    return RSAStep(v, msg, key)
end

"""
    RSAVP1(::pkcs1_v1_5_t, msg::BigInt, key::RSAPublicKey)

"""
function RSAVP1(v::pkcs1_v1_5_t, msg::BigInt, key::RSAPublicKey)
    return RSAStep(v, msg, key)
end
