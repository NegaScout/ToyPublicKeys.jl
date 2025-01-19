"""
    random_bigint_from_range(bits::Integer)

Custom random big int function since core julia does not yet provide 'proper one' (in my opinion).
"""
function random_bigint_from_range(bits::Integer)
    bits <= 0 && error("bits <= 0")
    lower = BigInt(1) << (bits - 1)
    upper = (BigInt(1) << bits) - 1
    return rand(lower:upper)
end
