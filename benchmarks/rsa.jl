using ToyPublicKeys
using BenchmarkTools
using Random

test_for_bitsizes = [1024, 2048, 4096]
for bitsize in test_for_bitsizes
    Random.seed!(42)
    println("Benchmarking ToyPublicKeys.generate_rsa_key_pair for bitsize $bitsize")
    display(@benchmark ToyPublicKeys.generate_rsa_key_pair($bitsize))
end

for bitsize in test_for_bitsizes
    Random.seed!(42)
    println("Benchmarking ToyPublicKeys.encrypt for bitsize $bitsize")
    priv_key, public_key = ToyPublicKeys.generate_rsa_key_pair(bitsize) 
    msg = "1"
    display(@benchmark ToyPublicKeys.encrypt($msg, $public_key))
end

for bitsize in test_for_bitsizes
    Random.seed!(42)
    println("Benchmarking ToyPublicKeys.decrypt for bitsize $bitsize")
    priv_key, public_key = ToyPublicKeys.generate_rsa_key_pair(bitsize) 
    msg = "1"
    encrypted = ToyPublicKeys.encrypt(msg, public_key)
    display(@benchmark ToyPublicKeys.decrypt($encrypted, $priv_key))
end

for bitsize in test_for_bitsizes
    Random.seed!(42)
    println("Benchmarking ToyPublicKeys.sign for bitsize $bitsize")
    priv_key, public_key = ToyPublicKeys.generate_rsa_key_pair(bitsize) 
    msg = "1"
    display(@benchmark ToyPublicKeys.sign($msg, $priv_key))
end

for bitsize in test_for_bitsizes
    Random.seed!(42)
    println("Benchmarking ToyPublicKeys.verify_signature for bitsize $bitsize")
    priv_key, public_key = ToyPublicKeys.generate_rsa_key_pair(bitsize) 
    msg = "1"
    signature = ToyPublicKeys.sign(msg, priv_key)
    display(@benchmark ToyPublicKeys.verify_signature($msg, $signature, $public_key))
end
