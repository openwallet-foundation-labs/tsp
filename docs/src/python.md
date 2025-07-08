# TSP Python bindings

We use PyO3 to generate Python bindings for the TSP SDK. We recommend using [uv](https://docs.astral.sh/uv/) to manage your Python dependencies, but it is also possible to use `pyenv` with `maturin` manually.

To add TSP as a dependency to your uv project, use the following command:

```sh
uv add git+https://github.com/openwallet-foundation-labs/tsp#subdirectory=tsp_python
```

## Example usage

Here's an example showing how you can use the Python bindings to create an identity, resolve someone else's identity, and send and receive TSP messages:

```py
{{#include ../../tsp_python/example.py}}
```
