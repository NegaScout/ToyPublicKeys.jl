function pad(::pkcs1_v2_2_t,
             msg::Vector{UInt8},
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

function unpad(::pkcs1_v2_2_t,
               msg::Vector{UInt8},
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

function MGF1(mgfSeed::Vector{UInt8}, maskLen:: Integer; hash = SHA.sha1)
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

function emsa_pss_encode(M::Vector{UInt8}, emBits::Integer; MGF=ToyPublicKeys.MGF1, hash=SHA.sha1, sLen=0)
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

function emsa_pss_verify(M::Vector{UInt8}, EM::Vector{UInt8}, emBits::Integer; MGF=ToyPublicKeys.MGF1, hash=SHA.sha1, sLen=0)
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
