@testset "padding/pkcs_1_v1_5" begin
    test_vector = Vector{UInt8}([1,2,3])
    Random.seed!(42)
    padded_vector_correct = UInt8[0x00, 0x02, 0x7a, 0xb4, 0xac, 0x2b, 0x9d, 0xab, 0x75, 0x4d, 0xa9, 0xa4, 0x58, 0x45, 0x84, 0x17, 0x46, 0x31, 0x6d, 0x7c, 0x15, 0x84, 0x33, 0x9a, 0x66, 0x51, 0x6f, 0xdb, 0x52, 0x90, 0x53, 0x29, 0xb9, 0x5f, 0x00, 0x01, 0x02, 0x03]
    padded_vec = ToyPublicKeys.pad(ToyPublicKeys.pkcs1_v1_5, test_vector)
    @test padded_vector_correct == padded_vec
    unpadded_vector = ToyPublicKeys.unpad(ToyPublicKeys.pkcs1_v1_5, padded_vector_correct)
    @test test_vector == unpadded_vector
end

@testset "padding/pkcs_1_v1_5 throws error for pad length < 8" begin
    test_vector = Vector{UInt8}([1,2,3])
    Random.seed!(42)
    padded_vector_correct = UInt8[0x00, 0x02, 0x7a, 0xb4, 0xac, 0x2b, 0x9d, 0xab, 0x75, 0x4d, 0xa9, 0xa4, 0x58, 0x45, 0x84, 0x17, 0x46, 0x31, 0x6d, 0x7c, 0x15, 0x84, 0x33, 0x9a, 0x66, 0x51, 0x6f, 0xdb, 0x52, 0x90, 0x53, 0x29, 0xb9, 0x5f, 0x00, 0x01, 0x02, 0x03]
    @test_throws ErrorException ToyPublicKeys.pad(ToyPublicKeys.pkcs1_v1_5, test_vector, 7)
end

@testset "padding/pkcs_1_v1_5 pad(unpad) is identity" begin
    test_vector = Vector{UInt8}([1,2,3])
    Random.seed!(42)
    padded = ToyPublicKeys.pad(ToyPublicKeys.pkcs1_v1_5, test_vector)
    @test ToyPublicKeys.unpad(ToyPublicKeys.pkcs1_v1_5, padded) == test_vector
end

@testset "padding/pkcs_1_v2_2 pad(unpad) is identity" begin
    test_vector = Vector{UInt8}([1,2,3])
    Random.seed!(42)
    private_key, public_key = ToyPublicKeys.generate_rsa_key_pair(ToyPublicKeys.pkcs1_v1_5, 2048)
    padded = ToyPublicKeys.pad(ToyPublicKeys.pkcs1_v2_2,
                               test_vector,
                               public_key)
    @test test_vector == ToyPublicKeys.unpad(ToyPublicKeys.pkcs1_v2_2,
                                             padded,
                                             public_key)
end
