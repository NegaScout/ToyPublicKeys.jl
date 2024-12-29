const mpz_t = Ref{BigInt}
const bitcnt_t = Culong

function is_probab_prime_p(n:: BigInt, n_tests:: Int)
    # https://gmplib.org/manual/Number-Theoretic-Functions#index-mpz_005fprobab_005fprime_005fp
    ret = (ccall((:__gmpz_probab_prime_p, :libgmp),
                    Cint,
                    (mpz_t, Cint),
                    n, n_tests))
    if ret == 2
        return :prime
    elseif ret == 1
        return :probably_prime
    elseif ret == 0
        return :not_prime
    end
end

function rand_prime_for_rsa(type:: Type, no_lcm_with=big"65537")
    ntest = 20
    fst = Nothing
    while true
        fst = BigInt(rand(type))
        if is_probab_prime_p(fst, ntest) ∈ [:prime, :probably_prime] && gcd(fst, no_lcm_with) == 1
            break
        end
    end
    return fst
end
