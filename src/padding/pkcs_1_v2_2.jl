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
