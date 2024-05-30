
# Installation

To get started with the CLI, first install Rust. See [https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install). The fastest way is running the following command in your terminal:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

After Rust is installed you should be able to run cargo:

```sh
cargo version
```

Output:
```
cargo 1.77.1 (e52e36006 2024-03-26) for example
```

Installing the TSP CLI program:

```sh
cargo install --git https://github.com/wenjing/rust-tsp.git examples --bin tsp
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
  verify   
  create   
  send     
  receive  
  help     Print this message or the help of the given subcommand(s)

Options:
  -d, --database <DATABASE>  Database file path [default: database.json]
  -v, --verbose              
  -p, --pretty-print         Pretty print CESR messages
  -h, --help                 Print help
```
