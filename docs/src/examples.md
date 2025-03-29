# Public API examples
## Encryption and decryption
```@example
import Random
using ToyPublicKeys
Random.seed!(42)
private_key, public_key = ToyPublicKeys.generate_rsa_key_pair(ToyPublicKeys.pkcs1_v1_5, 2048)
msg = "Super secret message!"
println(msg)
msg = Vector{UInt8}(msg)
encrypted = ToyPublicKeys.encrypt(msg, public_key)
println(encrypted)
decrypted = ToyPublicKeys.decrypt(encrypted, private_key)
println(decrypted |> String)
```

## Signatures and their verification
```@example
import Random
using ToyPublicKeys
Random.seed!(42)
private_key, public_key = ToyPublicKeys.generate_rsa_key_pair(ToyPublicKeys.pkcs1_v1_5, 2048)
msg = "Super authentic message!"
println(msg)
msg = Vector{UInt8}(msg)
signature = ToyPublicKeys.sign(msg, private_key)
println("And its signature:")
println(signature)
authentic = ToyPublicKeys.verify_signature(msg, signature, public_key)
println("Is it authentic..?")
println(authentic)
```
