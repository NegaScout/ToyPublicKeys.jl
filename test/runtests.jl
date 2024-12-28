using ToyPublicKeys
using Test
import Random

@testset "Decryption(Encryption) is identity ~ BigInt" begin
    n = big"3233"       # Example modulus
    e = big"17"         # Example public exponent
    d = big"2753"       # Example private exponent

    public_key = ToyPublicKeys.RSAKey(n, (BigInt(53), BigInt(61)), e, ToyPublicKeys.public_key)
    private_key = ToyPublicKeys.RSAKey(n, (BigInt(1), BigInt(1)), d, ToyPublicKeys.private_key)
    msg = big"1"

    encrypted = ToyPublicKeys.encrypt(msg, public_key)
    decrypted = ToyPublicKeys.decrypt(encrypted, private_key)
    @test decrypted == msg
end

@testset "RSA.jl" begin
    test_str = "this_is_test_str"
    @test ToyPublicKeys.pass_trough_GMP(test_str) == "this_is_test_str"
end

@testset "Decryption(Encryption) is identity ~ CodeUnits" begin
    n = big"3233"       # Example modulus
    e = big"17"         # Example public exponent
    d = big"2753"       # Example private exponent

    public_key = ToyPublicKeys.RSAKey(n, (BigInt(53), BigInt(61)), e, ToyPublicKeys.public_key)
    private_key = ToyPublicKeys.RSAKey(n, (BigInt(1), BigInt(1)), d, ToyPublicKeys.private_key)
    msg = Base.CodeUnits("1")

    encrypted = ToyPublicKeys.encrypt(msg, public_key)
    decrypted = ToyPublicKeys.decrypt(encrypted, private_key)
    @test decrypted == msg
end

@testset "Decryption(Encryption) is identity ~ String" begin
    n = big"3233"       # Example modulus
    e = big"17"         # Example public exponent
    d = big"2753"       # Example private exponent

    public_key = ToyPublicKeys.RSAKey(n, (BigInt(53), BigInt(61)), e, ToyPublicKeys.public_key)
    private_key = ToyPublicKeys.RSAKey(n, (BigInt(1), BigInt(1)), d, ToyPublicKeys.private_key)
    msg = "1"

    encrypted = ToyPublicKeys.encrypt(msg, public_key)
    decrypted = ToyPublicKeys.decrypt(encrypted, private_key)
    @test decrypted == msg
end

end
