# TMCP: TSP x MCP

[TMCP Python](https://github.com/openwallet-foundation-labs/tmcp-python/tree/main/demo) implements the TMCP transport hook, allowing you to use MCP over TSP. To use this, you need to use [our fork](https://github.com/openwallet-foundation-labs/mcp-transport-hooks) of the MCP Python SDK that adds transport hooks to make it possible to implement TMCP. These can be installed with:

```
uv add git+https://github.com/openwallet-foundation-labs/mcp-transport-hooks git+https://github.com/openwallet-foundation-labs/tmcp-python
```

See the [`./demo` directory](https://github.com/openwallet-foundation-labs/mcp-over-tsp-python/tree/main/tmcp/demo) for some example TMCP servers and clients.

## Example usage

Below is an example TMCP server using FastMCP. By default, it will generate a DID WebVH on initial start up and host it on the [TSP test bed](https://did.teaspoon.world/). The DID will be named according to the optionally provided format string, and will contain a combination of the provided alias (set to "tmcp" by default) and a random UUIDv4 to ensure uniqueness.

```py
from mcp.server.fastmcp import FastMCP
from tmcp import TmcpManager

# Create a MCP server
mcp = FastMCP("Demo", port=8001, transport_manager=TmcpManager(alias="demo", transport="http://localhost:8001/mcp"))


# Add an addition tool
@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two numbers"""
    return a + b


if __name__ == "__main__":
    # Initialize and run the server
    mcp.run(transport="streamable-http")
```

The DID format string, DID servers, and other TMCP settings can be passed on to the `TmcpManager` during initialization. See the [`TmcpSettings`](https://github.com/openwallet-foundation-labs/tmcp-python/blob/main/src/tmcp/tmcp.py#L17) for a full list of the available settings.

## TMCP Demo

The [TMCP demo](https://github.com/openwallet-foundation-labs/tmcp-python/tree/main/demo) shows how MCP clients and MCP servers can securely communicate over TSP.

### Run the server

In the `server` directory, run the demo TMCP server with:

```
uv run server.py
```

This hosts the demo TMCP server locally. When it starts, it prints its own DID. This DID will be either a newly generated DID published on <https://did.teaspoon.world/>, or a previously saved DID from the wallet using the server's name as an alias.

Currently, TMCP mainly focuses on the StreamableHTTP transport, as this is the most up-to-date transport type for MCP. The transport information is stored in the server's DID, so if you restart the server on a new port, a new DID will need to be generated. The client will automatically determine the transport to use based on the server's DID.

### Run the client

For the client, you will need an Anthropic API key, which you can get [here](https://console.anthropic.com/settings/keys). In the `client` directory, create a `.env` file with your Anthropic API key:

```
ANTHROPIC_API_KEY=sk-ant-api03-put-your-private-key-here
```

Then, run the demo TMCP client in the `client` directory with:

```bash
# Replace <server-did> with the DID of the target server
uv run client.py <server-did>
```

It should list the available MCP tools from the demo MCP server. You should be able to enter a query to prompt it to use these tools.

The server will print the encoded and decoded MCP over TSP messages that it sends and receives.

### Using other MCP servers

If you want to use TMCP with other existing MCP servers, some minor modification is required.

First, update the MCP Python SDK dependency to our fork, and install the TMCP transport hook with the following command:

```
uv add git+https://github.com/openwallet-foundation-labs/mcp-transport-hooks git+https://github.com/openwallet-foundation-labs/tmcp-python
```

Then, if the server uses the `FastMCP` server, configure it to use the TMCP transport hook. For example:

```py
mcp = FastMCP("Server", port=8001, transport_manager=TmcpManager(transport="http://localhost:8001/mcp"))

# implement server tools, resources, etc.

def main():
    mcp.run(transport="streamable-http")
```

If the server implements its own MCP server, make sure it uses StreambleHTTP with the TMCP transport hook.

The servers in this directory contain examples of such modified MCP servers. You can interact with these example servers using our same TMCP demo client.

### Using the fast-agent client

Our demo client only supports basic **MCP tools** and lacks support for other features of MCP such as resources and sampling. To try out these other MCP features, you can use a more advanced MCP client, like [fast-agent](https://github.com/evalstate/fast-agent). In the `client-fast-agent` folder there is a fork of fast-agent which has been modified to support TMCP.

First, set your Anthropic API key in `fastagent.secrets.yaml`:

```yaml
anthropic:
  api_key: "sk-ant-api03-your-key-here"
```

Then, you can start an interactive session with a TMCP server with the following command (type `exit` to exit the interactive session):

```
uv run fast-agent go --url did:your_server_did_here
```

Alternatively, you can put the server you want to connect with in `fastagent.config.yaml` and start fast-agent using the servers name from the config:

```
uv run fast-agent go --servers Demo
```

### Exploring more MCP features

To try out **MCP resources**, we have created a demo script `test-resource.py`, which is intended to work with our demo server in the `server` directory. After running the server, put the server's DID in the client's `fastagent.config.yaml`, and then run:

```
uv run test-resource.py
```

The `fastagent.config.yaml` config file also contains an example **MCP root**. Using the demo server's `show_roots` tool you can see that the root configuration is shared with the server. This tool may return an error if no roots are configured. MCP roots don't automatically share any data or provide any security guarantees; they only provide a way to share information with the server about what roots the server may use. How these roots are used in practice depends entirely on the server.

Fast-agent also supports **MCP prompts** with the `/prompts` command in the interactive session, and it supports **MCP sampling** and **eliciting** (see the `favorite_animal_guesser` tool in our demo server).
