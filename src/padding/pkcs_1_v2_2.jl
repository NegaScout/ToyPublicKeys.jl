function pad(::pkcs1_v2_2_t,
             msg::Union{AbstractString, AbstractVector},
             key::RSAKey;
             label="",
             MGF=ToyPublicKeys.MGF1,
             hash=SHA.sha1)
    msg = msg |> Vector{UInt8}
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
               msg::Union{AbstractString, AbstractVector},
               key::RSAKey;
               label="",
               MGF=ToyPublicKeys.MGF1,
               hash=SHA.sha1)
    k = (Base.GMP.MPZ.sizeinbase(key.modulus, 2)/8) |> ceil |> Integer
    lHash = hash(label)
    hLen = lHash |> length
    Y = msg[1]
    maskedSeed = msg[2:end][1:hLen]
    DBLen = k - hLen - 1
    maskedDB = msg[2:end][hLen + 1:end]
    seedMask = MGF(maskedDB, hLen)
    seed = maskedSeed .⊻ seedMask
    dbMask = MGF(seed, k - hLen - 1)
    DB = maskedDB .⊻ dbMask
    lHashPrime = DB[1:hLen]
    PSLen = findfirst(Vector{UInt8}([1]), DB)
    PSIndex = (PSLen |> first) - 1
    PS = DB[hLen + 1:PSIndex]
    X = DB[PSIndex + 1]
    M = DB[PSIndex + 2:end]
    return M
end

function MGF1(mgfSeed::Vector{UInt8}, maskLen:: Integer; hash = SHA.sha1)
    hLen = hash("") |> length
    maskLen >= (2 << 32) && error("mask too long") |> throw
    T = Vector{UInt8}()
    for counter in big"0":BigInt((ceil(maskLen / hLen) - 1))
        C = I2OSP(counter, 4) |> Vector{UInt8}
        T = vcat(T, hash(vcat(mgfSeed, C) |> String))
    end
    return T[1:maskLen]
end
