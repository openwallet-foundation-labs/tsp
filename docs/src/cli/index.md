# TSP Command Line Interface

The command line interface is an _example_ application of the Rust TSP implementation.
It helps testing and exploring TSP, the cryptography, transports, modes and message encoding.
It also provides a `bench` command for sustained transport traffic tests.

Read the next sections on how to get started.

The CLI walkthroughs are split by relationship style:

- [Base mode](./base.md) for direct relationships and ordinary message exchange
- [Parallel relationships](./parallel.md) for referral-based relationship formation with a new VID pair
- [Nested mode](./nested.md) for inner relationships coupled to an outer relationship
- [Routed mode](./routed.md) for multi-hop delivery

A short demo of the CLI (made using the TSP SDK development version of May 2024):

<iframe width="754" height="380" frameborder="0" src="https://www.youtube.com/embed/WRwZ_rug4E4?si=638gVed4fGxTJTV7" allowfullscreen></iframe>
