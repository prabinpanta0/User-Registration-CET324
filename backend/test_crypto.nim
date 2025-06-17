import nimcrypto
import nimcrypto/sha2

echo "Testing nimcrypto/sha2 for SHA256..."

let data = "hello"
let hash = sha256.digest(data)
echo "SHA256 of '", data, "': ", hash
