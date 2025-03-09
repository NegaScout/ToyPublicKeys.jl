@testset "i2osp" begin
    b = big"255"
    @test b |> ToyPublicKeys.i2osp == "FF"
    @test b |> x -> ToyPublicKeys.i2osp(x, 3) == "00:FF"
end

@testset "os2ip" begin
    b = "FF"
    @test b |> ToyPublicKeys.os2ip == big"255"
end

@testset "i2osp |> os2ip" begin
    b = big"255"
    @test b |> ToyPublicKeys.i2osp |> ToyPublicKeys.os2ip == b
end
