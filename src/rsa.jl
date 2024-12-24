struct RSAKey
    key_module::BigInt
    key_module_factorization:: Tuple{BigInt, BigInt}
    key_component::BigInt
    type:: AsymetricKeyType
end

function RSAStep(msg::BigInt, e::BigInt, n::BigInt)
    if !(0 <= msg < n)
        error("msg has to be 0 <= msg < n")
    end
    return Base.GMP.MPZ.powm(msg, e, n)
end

function RSAStep(msg::AbstractArray{T}, e::BigInt, n::BigInt) where T
    msg_bi = BigInt()
    # https://gmplib.org/manual/Integer-Import-and-Export#index-mpz_005fimport
    # void mpz_import (mpz_t rop, size_t count, int order, size_t size, int endian, size_t nails, const void *op)
    _order = 0
    _size = 1
    _endian = 0
    _nails = 0
    Base.GMP.MPZ.import!(msg_bi, length(msg), _order, _size, _endian, _nails, pointer(msg))
    result = RSAStep(msg_bi, e, n)
    # https://gmplib.org/manual/Integer-Import-and-Export#index-mpz_005fexport
    msg_buf = Vector{UInt8}(undef, msg_bi.size)
    Base.GMP.MPZ.export!(msg_buf, result, order=_order, nails=_nails, endian=_endian)
    return msg_buf
end

function RSAStep(msg::String, e::BigInt, n::BigInt)
    msg_cu = codeunits(msg)
    result = RSAStep(msg_cu, e, n)
    transformed_msg = String(result)
    return transformed_msg
end

function pass_trough_GMP(str::String)
    bi = BigInt()
    # https://gmplib.org/manual/Integer-Import-and-Export#index-mpz_005fimport
    # void mpz_import (mpz_t rop, size_t count, int order, size_t size, int endian, size_t nails, const void *op)
    _order = 0
    _size = 1
    _endian = 0
    _nails = 0
    Base.GMP.MPZ.import!(bi, length(str), _order, _size, _endian, _nails, pointer(str))
    # https://gmplib.org/manual/Integer-Import-and-Export#index-mpz_005fexport
    buff = Vector{UInt8}(undef, bi.size)
    Base.GMP.MPZ.export!(buff, bi, order=_order, nails=_nails, endian=_endian)
    return String(buff)
end

function encrypt(msg, key::RSAKey)
    return RSAStep(msg, key.key_component, key.key_module)
end

function decrypt(msg, key::RSAKey)
    # todo: take advantage of known factorization
    return RSAStep(msg, key.key_component, key.key_module)
end

function generate_RSAKeyPair()
    # todo: not enough bit size
    p = rand_prime()
    q = rand_prime()
    m = p * q
    carm_tot = lcm(p − 1, q − 1)
    e = big"65537"
    if e >= carm_tot
        pritln("Broken carm tot")
        return Nothing
    end
    d = big"65537"
    Base.GMP.MPZ.invert!(d, carm_tot) # for some reason Base.GMP.MPZ.invert is broken
    return (RSAKey(m, (p, q), d, private_key), RSAKey(m, (0, 0), e, public_key))
end
