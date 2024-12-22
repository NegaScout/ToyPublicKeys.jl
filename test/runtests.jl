using ToyPublicKeys
using Test

@testset "Decryption(Encryption) is identity ~ BigInt" begin
    n = big"3233"       # Example modulus
    e = big"17"         # Example public exponent
    d = big"2753"       # Example private exponent

    public_key = ToyPublicKeys.RSAKey(n, e, ToyPublicKeys.public_key)
    private_key = ToyPublicKeys.RSAKey(n, d, ToyPublicKeys.private_key)
    msg = big"123"

    encrypted = ToyPublicKeys.encrypt(msg, public_key)
    println("Encrypted Message: $encrypted")

    decrypted = ToyPublicKeys.decrypt(encrypted, private_key)
    println("Decrypted Message: $decrypted")
    encrypted == msg
end

@testset "Decryption(Encryption) is identity ~ CodeUnits" begin
    n = big"3233"       # Example modulus
    e = big"17"         # Example public exponent
    d = big"2753"       # Example private exponent

    public_key = ToyPublicKeys.RSAKey(n, e, ToyPublicKeys.public_key)
    private_key = ToyPublicKeys.RSAKey(n, d, ToyPublicKeys.private_key)
    msg = Base.CodeUnits("123")

    encrypted = ToyPublicKeys.encrypt(msg, public_key)
    println("Encrypted Message: $encrypted")

    decrypted = ToyPublicKeys.decrypt(encrypted, private_key)
    println("Decrypted Message: $decrypted")
    encrypted == msg
end

@testset "Decryption(Encryption) is identity ~ String" begin
    n = big"3233"       # Example modulus
    e = big"17"         # Example public exponent
    d = big"2753"       # Example private exponent

    public_key = ToyPublicKeys.RSAKey(n, e, ToyPublicKeys.public_key)
    private_key = ToyPublicKeys.RSAKey(n, d, ToyPublicKeys.private_key)
    msg = "123"

    encrypted = ToyPublicKeys.encrypt(msg, public_key)
    println("Encrypted Message: $encrypted")

    decrypted = ToyPublicKeys.decrypt(encrypted, private_key)
    println("Decrypted Message: $decrypted")
    encrypted == msg
end

@testset "RSA.jl" begin
    test_str = "this_is_test_str"
    ToyPublicKeys.pass_trough_GMP(test_str) == "this_is_test_str"
end
