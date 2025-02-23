function I2OSP(x::BigInt)
    return I2OSP(x, Base.GMP.MPZ.sizeinbase(x, 16))
end

function I2OSP(x::BigInt, xLen::Integer)
    xLen |> isodd && (xLen += 1)
    base_size = Base.GMP.MPZ.sizeinbase(x, 16)
    base_size > xLen && throw(error("integer too big for xLen"))
    buf = zeros(UInt8, xLen)
    fill!(buf, '0')
    buf_ptr = pointer(buf)
    Base.GMP.MPZ.get_str!(buf_ptr + xLen - base_size, 16, x)
    _buf = String(buf) |> uppercase
    it = Iterators.Stateful(_buf)
    part = Base.Iterators.partition(it, 2)
    return join(map(join, part), ':')
end

function OS2IP(x::String)
    # use Cstring instead..?
    buf = replace(x, ":" => "") |> lowercase |> Vector{UInt8}
    push!(buf, 0)
    target = BigInt(0)
    Base.GMP.MPZ.set_str!(target, pointer(buf), 16) == 0 || throw(error("string not valid base 16"))
    return target
end
