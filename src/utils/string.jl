function s_to_os(buf::String)
    _buf = buf |> uppercase
    it = Iterators.Stateful(_buf)
    part = Base.Iterators.partition(it, 2)
    return join(map(join, part), ':')
end

function i2osp(x::BigInt)
    return i2osp(x, Base.GMP.MPZ.sizeinbase(x, 16))
end

function i2osp(x::BigInt, xLen::Integer)
    xLen |> isodd && (xLen += 1)
    base_size = Base.GMP.MPZ.sizeinbase(x, 16)
    base_size > xLen && throw(error("integer too big for xLen"))
    buf = zeros(UInt8, xLen)
    fill!(buf, '0')
    buf_ptr = pointer(buf)
    Base.GMP.MPZ.get_str!(buf_ptr + xLen - base_size, 16, x)
    return s_to_os(buf |> String)
end

function os2ip(x::String)
    # use Cstring instead..?
    buf = replace(x, ":" => "") |> lowercase |> Vector{UInt8}
    push!(buf, 0)
    target = BigInt(0)
    Base.GMP.MPZ.set_str!(target, pointer(buf), 16) == 0 || throw(error("string not valid base 16"))
    return target
end

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
