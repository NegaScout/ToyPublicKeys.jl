function pad(msg:: Vector{UInt8}, pad_length=32)
    buff = rand(UInt8(1):UInt8(typemax(UInt8)), pad_length + 3)
    buff[1] = 0
    buff[2] = 2
    buff[pad_length + 3] = 0
    append!(buff, msg)
    return buff
end

function unpad(msg:: Vector{UInt8})
    num_of_c_chars = 3
    start_of_padding = 3
    if msg[1] != 0 && msg[2] != 2
        error("Not pkcs_1_v1_5")
    end
    pos = findfirst(==(0), view(msg, start_of_padding:length(msg))) + num_of_c_chars
    return view(msg, pos:length(msg))
end
