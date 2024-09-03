# tsp-node

Node.js module based on `tsp-javascript` that binds to a WebAssembly binary build with rust

## How to run

First build `tsp-javascript` for Node.js in the tsp-javascript folder:
```
wasm-pack build --target nodejs
```

Then install the dependencies in this folder:
```
npm install --dev
```

Run the tests in test.js with Mocha:
```
npm run test
```