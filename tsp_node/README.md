# tsp-node

Node.js module based on `tsp-javascript` that binds to a WebAssembly binary build with rust

## How to run

First build `tsp-javascript` for Node.js. Run this from the repository root; the
`RUSTFLAGS` are required, because the WebAssembly target needs an explicit
`getrandom` backend:
```
RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build --target nodejs tsp_javascript/
```

That writes the package to `tsp_javascript/pkg`, which this module depends on by
path.

Then install the dependencies in this folder:
```
npm install
```

Run the tests in test.js with Mocha:
```
npm run test
```
