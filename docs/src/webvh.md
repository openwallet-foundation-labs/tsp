# DID webvh

The TSP SDK and CLI can resolve DID:webvh natively.

## Create a DID:webvh

Creating a new webvh identity is as easy as running

```shell
tsp create --type webvh --alias foo-alias foo
```

The expected output would be something like

```
INFO tsp: published DID document at https://did.teaspoon.world/endpoint/foo/did.json
INFO tsp: published DID history
```
