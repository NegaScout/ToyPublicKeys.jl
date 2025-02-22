
@testset "dh basics" begin
    Random.seed!(42)
    g, p, q, SEED, counter = ToyPublicKeys.dh_params(1024, 160)
    a_private_key, a_public_key = ToyPublicKeys.generate_dh_key_pair(p, g, 1024)
    b_private_key, b_public_key = ToyPublicKeys.generate_dh_key_pair(p, g, 1024)
    a_shared_s = ToyPublicKeys.DHStep(b_public_key, a_private_key)
    b_shared_s = ToyPublicKeys.DHStep(a_public_key, b_private_key)
    @test a_shared_s == b_shared_s
end
