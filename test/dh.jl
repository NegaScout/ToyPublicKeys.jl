
@testset "dh basics" begin
    s_modulus = big"23"
    s_public = big"5"
    a_priv = big"4"
    b_priv = big"3"
    a_private_key, a_public_key = ToyPublicKeys.generate_DHKeyPair(s_modulus, s_public, a_priv)
    b_private_key, b_public_key = ToyPublicKeys.generate_DHKeyPair(s_modulus, s_public, b_priv)
    
    a_interm = ToyPublicKeys.DHStep(a_private_key)
    b_interm = ToyPublicKeys.DHStep(b_private_key)
    a_shared_s = ToyPublicKeys.DHStep(b_interm, a_private_key)
    b_shared_s = ToyPublicKeys.DHStep(a_interm, b_private_key)
    @test a_shared_s == b_shared_s
end
