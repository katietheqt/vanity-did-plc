# `vanity-did-plc`
An efficient tool to crack [PLC ("public ledger of credentials")](https://github.com/did-method-plc/did-method-plc) DIDs that match regex patterns.

### Usage
> [!WARNING]
> Due to the nature of how this tool works, your DID will be initially created with an incredibly weak key as a secondary rotation key - this is important to make it quick, but you should revoke it immediately. It should really be done automatically, but I couldn't be bothered to implement the required signing and such here :3

1. Clone this repository
2. Run `cargo run --release -- did:key:yourrotationkey ^regex+`
   - if you don't run in release mode it will take an eternity
   - running with `RUSTFLAGS="-C target-cpu=native"` will improve performance somewhat
3. Wait for it to output a link to a DID document
4. Create an account on your PDS by approximately following [this guide](https://github.com/bluesky-social/pds/blob/main/ACCOUNT_MIGRATION.md). It currently appears to be impossible to create an account on the official `bsky.social` PDS using an existing DID, so you will have to use a self-hosted one for now. 

There's a bunch of other options, run with `--help` to see them.

### Implementation
`plc` DIDs are generated by hashing the genesis operation that created them (with SHA256), and this operation must be signed with one of the rotation keys specified within it - these keys are elliptic curve keys using either the `SecP256K1` or `SecP256R1` curves. Signing with these keys is relatively slow, so avoiding it as much as possible is preferable. To that end, this code adds a secondary rotation key with a private key of 1 (`did:key:zQ3shVc2UkAfJCdc1TR8E66J85h48P43r93q8jGPkPpjF9Ef9` in DID form) to make the signing operation as cheap as possible. There is also some other tricks to reduce the amount of hashing required, but the key optimization here is the main one. The code is reasonably documented, feel free to look at it for more info :3