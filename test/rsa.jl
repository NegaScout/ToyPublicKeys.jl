@testset "pass_trough_GMP" begin
    function pass_trough_GMP(str::String)
        bi = BigInt()
        _order = 0
        _endian = 0
        _nails = 0
        # https://gmplib.org/manual/Integer-Import-and-Export#index-mpz_005fimport
        # void mpz_import (mpz_t rop, size_t count, int order, size_t size, int endian, size_t nails, const void *op)
        msg_ = Vector{UInt8}(str)
        Base.GMP.MPZ.import!(
            bi, length(msg_), _order, sizeof(eltype(msg_)), _endian, _nails, pointer(msg_)
        )
        # https://gmplib.org/manual/Integer-Import-and-Export#index-mpz_005fexport
        # void * mpz_export (void *rop, size_t *countp, int order, size_t size, int endian, size_t nails, const mpz_t op)
        buff = Vector{UInt8}(undef, bi.size)
        Base.GMP.MPZ.export!(buff, bi; order=_order, nails=_nails, endian=_endian)
        return String(buff)
    end
    test_str = "this_is_test_str"
    @test pass_trough_GMP(test_str) == "this_is_test_str"
end

@testset "power_crt_components" begin
    factor1 = big"9679"
    factor2 = big"7883"
    pow = big"654321"
    d_p, d_q, q_inv, p_inv = ToyPublicKeys.power_crt_components(pow, factor1, factor2)
    @test (d_p == 5895)
    @test (d_q == 115)
    @test (q_inv == 6785)
    @test (p_inv == 2357)
end

@testset "power_crt from power_crt_components" begin
    base = big"123456"
    modul = big"76299557"
    factor1 = big"9679"
    factor2 = big"7883"
    pow = big"654321"
    d_p, d_q, q_inv, _ = ToyPublicKeys.power_crt_components(pow, factor1, factor2)
    pow_crt = ToyPublicKeys.power_crt(base, factor1, factor2, d_p, d_q, q_inv)
    pow_m = Base.GMP.MPZ.powm(base, pow, modul)
    @test pow_crt == pow_m
end

@testset "power_crt" begin
    base = big"123456"
    modul = big"76299557"
    factor1 = big"9679"
    factor2 = big"7883"
    pow = big"654321"
    pow_crt = ToyPublicKeys.power_crt(base, pow, factor1, factor2)
    pow_m = Base.GMP.MPZ.powm(base, pow, modul)
    @test pow_crt == pow_m
end

@testset "validate generate_rsa_key_pair" begin
    Random.seed!(42)
    private_key, public_key = ToyPublicKeys.generate_rsa_key_pair(ToyPublicKeys.pkcs1_v1_5, 2048)
    @test try
        ToyPublicKeys.validate(private_key)
        true
    catch
        false
    end
end

@testset "RSAStep(RSAStep) is identity ~ BigInt" begin
    Random.seed!(42)
    private_key, public_key = ToyPublicKeys.generate_rsa_key_pair(ToyPublicKeys.pkcs1_v1_5, 2048)
    msg = big"123"
    encrypted = ToyPublicKeys.RSAStep(ToyPublicKeys.pkcs1_v1_5, msg, public_key)
    decrypted = ToyPublicKeys.RSAStep(ToyPublicKeys.pkcs1_v1_5, encrypted, private_key)
    @test msg == decrypted
end

@testset "RSAStep(RSAStep) is identity ~ Vector{UInt8}" begin
    Random.seed!(42)
    private_key, public_key = ToyPublicKeys.generate_rsa_key_pair(ToyPublicKeys.pkcs1_v1_5, 2048)
    msg = Vector{UInt8}("123")
    encrypted = ToyPublicKeys.RSAStep(ToyPublicKeys.pkcs1_v1_5, msg, public_key)
    decrypted = ToyPublicKeys.RSAStep(ToyPublicKeys.pkcs1_v1_5, encrypted, private_key)
    @test msg == decrypted
end

@testset "RSAStep(RSAStep) is identity ~ String" begin
    Random.seed!(42)
    private_key, public_key = ToyPublicKeys.generate_rsa_key_pair(ToyPublicKeys.pkcs1_v1_5, 2048)
    msg = "123"
    encrypted = ToyPublicKeys.RSAStep(ToyPublicKeys.pkcs1_v1_5, msg, public_key)
    decrypted = ToyPublicKeys.RSAStep(ToyPublicKeys.pkcs1_v1_5, encrypted, private_key)
    @test msg == decrypted
end

@testset "Decryption(Encryption) is identity ~ Vector{UInt8}" begin
    Random.seed!(42)
    private_key, public_key = ToyPublicKeys.generate_rsa_key_pair(ToyPublicKeys.pkcs1_v1_5, 2048)
    msg = Vector{UInt8}("123")
    encrypted = ToyPublicKeys.encrypt(ToyPublicKeys.pkcs1_v1_5, msg, public_key)
    decrypted = ToyPublicKeys.decrypt(ToyPublicKeys.pkcs1_v1_5, encrypted, private_key)
    @test decrypted == msg
end

@testset "Decryption(Encryption) is identity ~ String" begin
    Random.seed!(42)
    private_key, public_key = ToyPublicKeys.generate_rsa_key_pair(ToyPublicKeys.pkcs1_v1_5, 2048)
    msg = Vector{UInt8}("123")
    encrypted = ToyPublicKeys.encrypt(ToyPublicKeys.pkcs1_v1_5, msg, public_key)
    decrypted = ToyPublicKeys.decrypt(ToyPublicKeys.pkcs1_v1_5, encrypted, private_key)
    @test decrypted == msg
end

@testset "RSASP1(RSAVP1) is true" begin
    Random.seed!(42)
    private_key, public_key = ToyPublicKeys.generate_rsa_key_pair(ToyPublicKeys.pkcs1_v1_5, 2048)
    msg = big"3"
    signature = ToyPublicKeys.RSASP1(ToyPublicKeys.pkcs1_v1_5, msg, private_key)
    @test ToyPublicKeys.RSAVP1(ToyPublicKeys.pkcs1_v1_5, signature, public_key) == msg
end

@testset "rsaes_oaep_decrypt(rsaes_oaep_encrypt) is true" begin
    Random.seed!(42)
    private_key, public_key = ToyPublicKeys.generate_rsa_key_pair(ToyPublicKeys.pkcs1_v1_5, 2048)
    msg = Vector{UInt8}("123")
    C = ToyPublicKeys.rsaes_oaep_encrypt(msg, public_key)
    ret = ToyPublicKeys.rsaes_oaep_decrypt(C, private_key)
    @test ret == msg
end

@testset "rsassa_pss_verify(rsassa_pss_sign) is true" begin
    Random.seed!(42)
    private_key, public_key = ToyPublicKeys.generate_rsa_key_pair(ToyPublicKeys.pkcs1_v1_5, 2048)
    M = Vector{UInt8}("123")
    S = ToyPublicKeys.rsassa_pss_sign(M, private_key)
    valid = ToyPublicKeys.rsassa_pss_verify(M, S, public_key)
    @test valid == true
end

@testset "rsassa_pkcs1_v1_5_verify(rsassa_pkcs1_v1_5_sign) is true" begin
    Random.seed!(42)
    private_key, public_key = ToyPublicKeys.generate_rsa_key_pair(ToyPublicKeys.pkcs1_v1_5, 2048)
    M = Vector{UInt8}("321")
    S = ToyPublicKeys.rsassa_pkcs1_v1_5_sign(M, private_key)
    valid = ToyPublicKeys.rsassa_pkcs1_v1_5_verify(M, S, public_key)
    @test valid == true
end
