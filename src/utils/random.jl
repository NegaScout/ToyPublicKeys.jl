function random_bigint_from_range(bits::Integer)
    bits <= 0 && error("bits <= 0")
    return rand((BigInt(2)^(bits - 1)):(BigInt(2)^bits))
end
