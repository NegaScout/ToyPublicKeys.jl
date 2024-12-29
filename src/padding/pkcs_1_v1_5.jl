const padding_pkcs_1_v1_5_num_c_chars = 3
const padding_pkcs_1_v1_5_pad_start = 3

function is_padded(msg:: AbstractVector{T}) where T <: Base.BitInteger
    if length(msg) < 3
        return false
    elseif msg[1] != T(0) && msg[2] != T(3)
        return false
    elseif nothing == findfirst(==(T(0)), view(msg, padding_pkcs_1_v1_5_pad_start:length(msg)))
        return false
    else
        return true
    end
end

function pad(msg:: AbstractVector{T}, pad_length=32) where T <: Base.BitInteger
    buff = rand(T(1):T(typemax(T)), pad_length + 3)
    buff[1] = 0
    buff[2] = 2
    buff[pad_length + 3] = 0
    append!(buff, msg)
    return buff
end

function pad(msg:: T, pad_length=32) where T <: AbstractString
    msg_cu = codeunits(msg)
    msg_padded = pad(msg_cu, pad_length)
    return T(msg_padded)
end

function unpad(msg:: AbstractVector{T}) where T <: Base.BitInteger
    if !is_padded(msg)
        error("Not padded: $msg")
    end
    pos = findfirst(==(T(0)), view(msg, padding_pkcs_1_v1_5_pad_start:length(msg))) + padding_pkcs_1_v1_5_num_c_chars
    return view(msg, pos:length(msg))
end

function unpad(msg:: T) where T <: AbstractString
    msg_cu = codeunits(msg)
    msg_unpadded = unpad(msg_cu)
    return T(msg_unpadded)
end
