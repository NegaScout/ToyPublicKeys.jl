using BenchmarkTools
using Random

num_of_nums = 1000
rand_sample = rand(Int, (num_of_nums, 3)) .|> abs .|> BigInt

@btime [Base.GMP.MPZ.powm($rand_sample[i, 1], $rand_sample[i, 2], $rand_sample[i, 3]) for i in 1:num_of_nums]
@btime [($rand_sample[i, 1] ^ $rand_sample[i, 2]) % $rand_sample[i, 3] for i in 1:num_of_nums]
@btime Base.GMP.MPZ.powm(big"123456", big"265277633", big"582541027")
@btime power_crt(big"123456", big"265277633", big"38561", big"15107")
