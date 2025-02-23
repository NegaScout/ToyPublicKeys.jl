@testset "I2OSP" begin
    b = big"255"
    @test b |> ToyPublicKeys.I2OSP == "FF"
    @test b |> x -> ToyPublicKeys.I2OSP(x, 3) == "00:FF"
end

@testset "OS2IP" begin
    b = "FF"
    @test b |> ToyPublicKeys.OS2IP == big"255"
end

@testset "I2OSP |> OS2IP" begin
    b = big"255"
    @test b |> ToyPublicKeys.I2OSP |> ToyPublicKeys.OS2IP == b
end
