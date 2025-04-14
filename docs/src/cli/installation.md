
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
cargo 1.77.1 (e52e36006 2024-03-26) for example
```

Installing the TSP CLI program:

```sh
cargo install --git https://github.com/openwallet-foundation-labs/tsp.git examples --bin tsp
```

You should be able to run `tsp`:

```sh
tsp
```

Output:
```
Send and receive TSP messages

Usage: tsp [OPTIONS] <COMMAND>

Commands:
  verify            verify and add a identifier to the wallet
  print             
  create            create and register a did:web identifier
  create-peer       
  create-from-file  import an identity from a file
  set-alias         
  set-route         
  set-parent        
  set-relation      
  send              send a message
  receive           listen for messages
  request           propose a relationship
  accept            accept a relationship
  cancel            break up a relationship
  refer             send an identity referral
  publish           publish a new own identity
  help              Print this message or the help of the given subcommand(s)

Options:
  -w, --wallet <WALLET>          Wallet name to use [default: wallet]
      --password <PASSWORD>      Password used to encrypt the wallet [default: unsecure]
  -s, --server <SERVER>          Test server domain [default: demo.teaspoon.world]
      --did-server <DID_SERVER>  DID server domain [default: did.teaspoon.world]
  -v, --verbose                  
  -y, --yes                      Always answer yes to any prompts
  -p, --pretty-print             Pretty print CESR messages
  -h, --help                     Print help
```
