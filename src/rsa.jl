struct RSAKey
    key_module::BigInt
    key_module_factorization:: Tuple{BigInt, BigInt}
    key_component::BigInt
    type:: AsymetricKeyType
end

function RSAStep(msg::BigInt, key::RSAKey)
    if !(0 <= msg < key.key_module)
        error("msg has to be 0 <= msg < n, got: msg = $msg, n = $key.key_module")
    end
    if key.key_module_factorization != (0, 0)
        return ToyPublicKeys.power_crt(msg, key.key_component, key.key_module_factorization[1], key.key_module_factorization[2])
    else
        return Base.GMP.MPZ.powm(msg, key.key_component, key.key_module)
    end
end

function RSAStep(msg::AbstractVector{T}, key::RSAKey) where T <: Base.BitInteger
    msg_bi = BigInt()
    # https://gmplib.org/manual/Integer-Import-and-Export#index-mpz_005fimport
    # void mpz_import (mpz_t rop, size_t count, int order, size_t size, int endian, size_t nails, const void *op)
    _order = 0
    _endian = 0
    _nails = 0
    Base.GMP.MPZ.import!(msg_bi, length(msg), _order, sizeof(eltype(msg)), _endian, _nails, pointer(msg))
    result = RSAStep(msg_bi, key)
    # https://gmplib.org/manual/Integer-Import-and-Export#index-mpz_005fexport
    # void * mpz_export (void *rop, size_t *countp, int order, size_t size, int endian, size_t nails, const mpz_t op)
    msg_buf = Vector{T}(undef, msg_bi.size)
    Base.GMP.MPZ.export!(msg_buf, result, order=_order, nails=_nails, endian=_endian)
    return msg_buf
end

function RSAStep(msg::String, key::RSAKey)
    msg_cu = codeunits(msg)
    result = RSAStep(msg_cu, key)
    transformed_msg = String(result)
    return transformed_msg
end

function pass_trough_GMP(str::String)
    bi = BigInt()
    _order = 0
    _endian = 0
    _nails = 0
    # https://gmplib.org/manual/Integer-Import-and-Export#index-mpz_005fimport
    # void mpz_import (mpz_t rop, size_t count, int order, size_t size, int endian, size_t nails, const void *op)
    msg_ = codeunits(str)
    Base.GMP.MPZ.import!(bi, length(msg_), _order, sizeof(eltype(msg_)), _endian, _nails, pointer(msg_))
    # https://gmplib.org/manual/Integer-Import-and-Export#index-mpz_005fexport
    # void * mpz_export (void *rop, size_t *countp, int order, size_t size, int endian, size_t nails, const mpz_t op)
    buff = Vector{UInt8}(undef, bi.size)
    Base.GMP.MPZ.export!(buff, bi, order=_order, nails=_nails, endian=_endian)
    return String(buff)
end

function encrypt(msg::Union{AbstractString, AbstractVector}, key::RSAKey; pad_length=32)
    msg_padded = ToyPublicKeys.pad(msg, pad_length)
    return RSAStep(msg_padded, key)
end

function decrypt(msg::AbstractString, key::RSAKey)
    msg_ = codeunits(msg)
    msg_decr = RSAStep(msg_, key)
    unpaded = ToyPublicKeys.unpad(vcat(typeof(msg_decr)([0]), msg_decr)) # todo: leading zero is ignored, gotta deal with this 
    return String(unpaded)
end

function decrypt(msg::AbstractVector, key::RSAKey)
    msg_decr = RSAStep(msg, key)
    return ToyPublicKeys.unpad(vcat(typeof(msg_decr)([0]), msg_decr)) # todo: leading zero is ignored, gotta deal with this
end

function generate_RSAKeyPair(type:: Type)
    # todo: not enough bit size
    p = rand_prime(type)
    q = rand_prime(type)
    m = p * q
    carm_tot = lcm(p − 1, q − 1)
    e = big"65537"
    if !(1 < e < carm_tot)
        println("Broken carm_tot,  has to be (1 < e < carm_tot): e = $e, carm_tot = $carm_tot")
        return Nothing
    end
    d = BigInt()
    Base.GMP.MPZ.invert!(d, big"65537", carm_tot)
    return (RSAKey(m, (p, q), d, private_key), RSAKey(m, (0, 0), e, public_key))
end
