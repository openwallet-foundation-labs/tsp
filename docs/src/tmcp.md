# TMCP: TSP x MCP

[TMCP](https://github.com/openwallet-foundation-labs/mcp-over-tsp-python/) is a fork of the MCP Python SDK that integrates TSP to encrypt and sign MCP messages. This enhancement ensures secure, verifiable communication between AI agents and TMCP-compatible servers.

We provide some example TMCP clients and servers [here](https://github.com/openwallet-foundation-labs/mcp-over-tsp-python/tree/main/demo), along with some [documentation](https://github.com/openwallet-foundation-labs/mcp-over-tsp-python/tree/main/demo#tmcp-demo) on how to use these TMCP clients and servers.

## Transport Security with TSP

TMCP supports all standard MCP transport types, with varying levels of security integration:

- **Stdio**: remains unchanged, as it is only used for local inter-process communication and does not require transport-level security.
- **WebSockets**: uses TSP to secure the bidirectional message exchange.
- **Server-Sent Events (SSE)**: uses TSP for both the POST requests and the SSE messages.
- **Streamable HTTP**: uses TSP for all POST requests, responses, and SSE messages.

This TSP integration works by giving the clients and servers their own TSP identity (either a DID Web or a DID WebVH), which is then used to open and seal MCP messages. The sealed TSP messages are then sent over whichever MCP transport is being used (WebSockets, SSE, or Streamable HTTP), after which they are opened and verified on the other side. This allows us to only make minimal changes to the transport layers of MCP while providing the enhanced security of TSP.
