# Basic  [Bitcoin whitepaper](https://bitcoin.org/bitcoin.pdf) implementation with transactions, UTXOs, mining, fee processing, and networking.

# TODO:
- Tests
- Networking
- Docker compose with simulation
- Merkle Root optimization
- Dynamic P-o-W difficulty depending an average number of blocks per hour
- Dynamic mining reward depending on the total number of blocks
- Improved nonce search algorithm (not sequential bruteforce)
- Store precalculated available UTXOs instead of iteration through the whole blockchain

# Keep in mind that it doesn't implement any BIPs and may lack of features for real-world usage, treat it as a project to demonstrate and understand how Blockchain works 

# Windows
First install [Desktop development with C++](https://learn.microsoft.com/en-us/cpp/build/vscpp-step-0-installation) (required for `secp256k1`).