using ToyPublicKeys
using Test
import Random
@testset "ToyPublicKeys" begin
    include("utils.jl")
    include("padding.jl")
    include("rsa.jl")
    include("dh.jl")    
end
