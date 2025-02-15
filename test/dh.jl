
@testset "dh basics" begin
    Random.seed!(42)
    bits = 128
    p, g = ToyPublicKeys.dh_params(bits)
    a_private_key, a_public_key = ToyPublicKeys.generate_dh_key_pair(p, g, bits)
    b_private_key, b_public_key = ToyPublicKeys.generate_dh_key_pair(p, g, bits)
    a_shared_s = ToyPublicKeys.DHStep(b_public_key, a_private_key)
    b_shared_s = ToyPublicKeys.DHStep(a_public_key, b_private_key)
    @test a_shared_s == b_shared_s
end
