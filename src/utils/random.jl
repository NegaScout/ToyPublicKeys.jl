"""
    Custom random big int function since core julia does not yet provide 'proper one' (in my opinion).
"""
function random_bigint_from_range(bits::Integer)
    bits <= 0 && error("bits <= 0")
    return rand((BigInt(2)<<(bits - 1)):(BigInt(2)<<bits))
end
