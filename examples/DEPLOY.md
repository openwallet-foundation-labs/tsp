Using the TSP CLI Demo app
==========================
The TSP CLI demo application supports `https://` transports (for did:web and did:peer VIDs) and `tcp` transport (for did:peer VIDs).

You can see all the possible commands by running `tsp --help`.

The TSP CLI in `receive` mode can also act as an intermediary.

Deploying the Demo Server
=========================
To be able to use `https://` transport, a broadcast server is needed. The `demo-server` application provides the following:

* A broadcast server running at port 3000
* Two intermediaries running at port 3001 and 3002.

For deployment, it expects to be running on a SSL-secured web server (with a configurable domain, see the `server.rs` source code -- by default
it expects to run at `tsp-test.org`, and that is also the default domain where the CLI application expects to find it). Requests for the domain
it is deployed at should be forward to port 3000 of `demo-server`.

The two intermediaries are optional, but if desired, should be configured as followed:

* Queries for `p.DOMAIN` (for example, `p.tsp-test.org`) should be forwarded to port 3001
* Queries `q.DOMAIN` (for example, `q.tsp-test.org`) should be forwarded to port 3002
