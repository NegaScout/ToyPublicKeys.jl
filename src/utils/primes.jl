const mpz_t = Ref{BigInt}
const bitcnt_t = Culong

"""
    Binding for GMPlib's gmpz_probab_prime_p function. 
    Only uses probability based tests as it would equall factoring n otherwise.
"""
function is_probab_prime_p(n::BigInt, n_tests::Int)
    # https://gmplib.org/manual/Number-Theoretic-Functions#index-mpz_005fprobab_005fprime_005fp
    ret = (ccall((:__gmpz_probab_prime_p, :libgmp), Cint, (mpz_t, Cint), n, n_tests))
    if ret == 2
        return :prime
    elseif ret == 1
        return :probably_prime
    elseif ret == 0
        return :not_prime
    end
end

"""
    Helper function for rsa random primes, since they should satisfy special properties.
"""
function rand_prime_for_rsa(bits::Integer, no_gcd_with=big"65537")
    bits <= 0 && error("bits <= 0")
    ntest = 20
    fst = Nothing
    while true
        fst = random_bigint_from_range(bits)
        if is_probab_prime_p(fst, ntest) ∈ [:prime, :probably_prime] &&
            gcd(fst, no_gcd_with) == 1
            break
        end
    end
    return fst
end
