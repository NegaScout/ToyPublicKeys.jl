function mpz_import(x::Vector{UInt8})
    bi = BigInt()
    _order = 0
    _endian = 0
    _nails = 0
    ccall((:__gmpz_import, Base.GMP.libgmp),
           Cvoid,
           (Ref{BigInt}, Csize_t, Cint, Csize_t, Cint, Csize_t, Ptr{Cvoid}),
           bi, length(x), _order, sizeof(eltype(x)), _endian, _nails, pointer(x))
    return bi
end