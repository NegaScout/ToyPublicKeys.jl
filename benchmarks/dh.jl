using ToyPublicKeys
using BenchmarkTools
using Random

test_for_bitsizes = [(1024, 160)]
for bitsize in test_for_bitsizes
    Random.seed!(42)
    println("Benchmarking ToyPublicKeys.dh_params for bitsizes $bitsize")
    display(@benchmark ToyPublicKeys.dh_params($bitsize...))
end

for bitsize in test_for_bitsizes
    Random.seed!(42)
    println("Benchmarking ToyPublicKeys.DHStep for bitsizes $bitsize")
    g, p, q, SEED, counter = ToyPublicKeys.dh_params(bitsize...)
    a_private_key, a_public_key = ToyPublicKeys.generate_dh_key_pair(p, g, bitsize |> first)
    b_private_key, b_public_key = ToyPublicKeys.generate_dh_key_pair(p, g, bitsize |> first)
    display(@benchmark ToyPublicKeys.DHStep($b_public_key, $b_private_key))
end
