function random_bigint_from_range(bits::bitcnt_t)
    # todo: properly type rand_state and maintain global state
    rand_state = Vector{UInt8}(undef, 32)
    ccall((:__gmp_randinit_default, :libgmp),
            Cvoid,
            (Ptr{UInt8},),
            rand_state)
    x = BigInt(0)
    # https://gmplib.org/manual/Random-State-Initialization#index-gmp_005frandinit_005fdefault
    #  void mpz_rrandomb (mpz_t rop, gmp_randstate_t state, mp_bitcnt_t n)
    ccall((:__gmpz_rrandomb, :libgmp),
            Cvoid,
            (mpz_t, Ptr{UInt8}, bitcnt_t),
            x, rand_state, bits)
    return x
end
