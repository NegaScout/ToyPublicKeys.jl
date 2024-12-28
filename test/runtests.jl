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

@testset "padding/pkcs_1_v1_5" begin
    test_vector = Vector{UInt8}([1,2,3])
    Random.seed!(42)
    padded_vector_correct = UInt8[0x00, 0x02, 0x7a, 0xb4, 0xac, 0x2b, 0x9d, 0xab, 0x75, 0x4d, 0xa9, 0xa4, 0x58, 0x45, 0x84, 0x17, 0x46, 0x31, 0x6d, 0x7c, 0x15, 0x84, 0x33, 0x9a, 0x66, 0x51, 0x6f, 0xdb, 0x52, 0x90, 0x53, 0x29, 0xb9, 0x5f, 0x00, 0x01, 0x02, 0x03]
    padded_vec = ToyPublicKeys.pad(test_vector)
    @test padded_vector_correct == padded_vec
    unpadded_vector = ToyPublicKeys.unpad(padded_vector_correct)
    @test test_vector == unpadded_vector
end
