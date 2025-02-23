using ToyPublicKeys
using BenchmarkTools
using Random

test_for_bitsizes = [1024, 2048, 4096]
for bitsize in test_for_bitsizes
    Random.seed!(42)
    n = rand(big"2" << bitsize: big"2" << (bitsize + 1))
    println("Benchmarking ToyPublicKeys.I2OSP for bitsize $bitsize")
    display(@benchmark ToyPublicKeys.I2OSP($n))
    str = ToyPublicKeys.I2OSP(n)
    println("Benchmarking ToyPublicKeys.OS2IP for bitsize $bitsize")
    display(@benchmark ToyPublicKeys.OS2IP($str))
end
