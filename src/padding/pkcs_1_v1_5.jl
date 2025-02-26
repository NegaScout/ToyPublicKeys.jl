const padding_pkcs_1_v1_5_num_c_chars = 3
const padding_pkcs_1_v1_5_pad_start = 3

"""
    pad(::pkcs1_v1_5_t, msg::AbstractVector{T}, pad_length=32) where {T<:Base.BitInteger}

Core implementation of the [PKCS#1 v1.5 padding](https://www.rfc-editor.org/rfc/rfc2313#section-8.1).
"""
function pad(::pkcs1_v1_5_t, msg::AbstractVector{T}, pad_length=32) where {T<:Base.BitInteger}
    pad_length > 8 || throw(error("Will not create pad with length < 8"))
    buff = rand(T(1):T(typemax(T)), pad_length + 3)
    buff[1] = 0
    buff[2] = 2
    buff[pad_length + 3] = 0
    append!(buff, msg)
    return buff
end

"""
    pad(::pkcs1_v1_5_t, msg::T, pad_length=32) where {T<:AbstractString}

Wrapper for the core pad function.
"""
function pad(::pkcs1_v1_5_t, msg::T, pad_length=32) where {T<:AbstractString}
    pad_length > 8 || throw(error("Will not create pad with length < 8"))
    msg_cu = codeunits(msg)
    msg_padded = pad(pkcs1_v1_5, msg_cu, pad_length)
    return T(msg_padded)
end

"""
    unpad(::pkcs1_v1_5_t, msg::AbstractVector{T}) where {T<:Base.BitInteger}

Core implementation for the [PKCS#1 v1.5 pad](https://www.rfc-editor.org/rfc/rfc2313#section-8.1) unwrapping.
"""
function unpad(::pkcs1_v1_5_t, msg::AbstractVector{T}) where {T<:Base.BitInteger}
    pos = findfirst(==(T(0)),
                    view(msg,
                         padding_pkcs_1_v1_5_pad_start:length(msg))) + padding_pkcs_1_v1_5_num_c_chars
    return view(msg, pos:length(msg))
end

"""
    unpad(::pkcs1_v1_5_t, msg::T) where {T<:AbstractString}

Wrapper for the core unpad function.
"""
function unpad(::pkcs1_v1_5_t, msg::T) where {T<:AbstractString}
    msg_cu = codeunits(msg)
    msg_unpadded = unpad(pkcs1_v1_5, msg_cu)
    return T(msg_unpadded)
end
