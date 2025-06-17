
# Installation

To get started with the CLI, first install Rust. See [https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install). The fastest way is running the following command in your terminal:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

After Rust is installed, you should be able to run cargo:

```sh
cargo version
```

Output:
```
cargo 1.86.0 (adf9b6ad1 2025-02-28) # for example
```

Installing the TSP CLI program:

```sh
cargo install --git https://github.com/openwallet-foundation-labs/tsp.git examples --bin tsp
```

If you want to manage DIDs of type WebVH, you have to compile the CLI with the feature flag `create-webvh`.
Simply add `--features create-webvh` to the above command.
You can always verify WebVH, even without enabling the feature flag.

You should be able to run `tsp`:

```sh
tsp
```

Output:
```
Send and receive TSP messages

Usage: tsp [OPTIONS] <COMMAND>

Commands:
  show        Show information stored in the wallet
  verify      verify and add a identifier to the wallet
  print       
  create      create and register a did:web identifier
  update      Update the DID:WEBVH. Currently, only a rotation of TSP keys is supported
  import-piv  import an identity from a file (for demo purposes only)
  discover    Discover DIDs from the DID support server
  set-alias   
  set-route   
  set-parent  
  send        send a message
  receive     listen for messages
  request     propose a relationship
  accept      accept a relationship
  cancel      break up a relationship
  refer       send an identity referral
  publish     publish a new own identity
  help        Print this message or the help of the given subcommand(s)

Options:
  -w, --wallet <WALLET>          Wallet name to use [default: wallet]
      --password <PASSWORD>      Password used to encrypt the wallet [default: unsecure]
  -s, --server <SERVER>          Test server domain [default: demo.teaspoon.world]
      --did-server <DID_SERVER>  DID server domain [default: did.teaspoon.world]
      --verbose                  
  -y, --yes                      Always answer yes to any prompts
  -h, --help                     Print help
  -V, --version                  Print version
```
