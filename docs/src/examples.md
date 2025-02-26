# Public API examples
## Encryption and decryption
```@example
import Random
using ToyPublicKeys
Random.seed!(42)
private_key, public_key = ToyPublicKeys.generate_rsa_key_pair(ToyPublicKeys.pkcs1_v1_5, 2048)
msg = "Super secret message!"
println(msg)
encrypted = ToyPublicKeys.encrypt(ToyPublicKeys.pkcs1_v1_5, msg, public_key)
println(encrypted)
decrypted = ToyPublicKeys.decrypt(ToyPublicKeys.pkcs1_v1_5, encrypted, private_key)
println(decrypted)
```
## Signatures and their verification
```@example
import Random
using ToyPublicKeys
Random.seed!(42)
private_key, public_key = ToyPublicKeys.generate_rsa_key_pair(ToyPublicKeys.pkcs1_v1_5, 2048)
msg = "Super authentic message!"
println(msg)
signature = ToyPublicKeys.sign(ToyPublicKeys.pkcs1_v1_5, msg, private_key)
println(signature)
authentic = ToyPublicKeys.verify_signature(ToyPublicKeys.pkcs1_v1_5, msg, signature, public_key)
println(authentic)
```
