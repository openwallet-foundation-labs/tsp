# DID webvh

## Creating a new did:webvh

### Step 0
Checkout https://github.com/decentralized-identity/didwebvh-py

### Step 1
```shell
tsp create --local foo
```
Output
```
INFO tsp: created identity did:web:did.teaspoon.world:user:foo
{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/jws-2020/v1"],"authentication":["did:web:did.teaspoon.world:user:max8#verification-key"],"id":"did:web:did.teaspoon.world:user:max8","keyAgreement":["did:web:did.teaspoon.world:user:max8#encryption-key"],"service":[{"id":"#tsp-transport","serviceEndpoint":"https://demo.teaspoon.world/user/did:web:did.teaspoon.world:user:max8","type":"TSPTransport"}],"verificationMethod":[{"controller":"did:web:did.teaspoon.world:user:max8","id":"did:web:did.teaspoon.world:user:max8#verification-key","publicKeyJwk":{"crv":"Ed25519","kty":"OKP","use":"sig","x":"sENIDVO8NUxo6-WM8sd9wnra5auLTHZNd2BLi4ZzZLw"},"type":"JsonWebKey2020"},{"controller":"did:web:did.teaspoon.world:user:max8","id":"did:web:did.teaspoon.world:user:max8#encryption-key","publicKeyJwk":{"crv":"X25519","kty":"OKP","use":"enc","x":"NXhJPs94TNtJSFm8d56Ni1r5q0VxF72upY78VIcEtiw"},"type":"JsonWebKey2020"}]}
```

### Step 2
```shell
python3 -m did_webvh.provision --auto "raw.githubusercontent.com/openwallet-foundation-labs/tsp/did-webvh/examples/test/foo"
```

Output
```
Provisioned DID in raw.githubusercontent.com_QmX6gpoQeyVuLT5sc7NeP3Nzh9ArrJ7yPAzu8oG5vDAhoC
```

### Step 3
- Open the `did.json` in the folder mentioned in the above output
- Replace everything except for the `id` in this file with the JSON returned by the `tsp create` command in the beginning.
- Replace all `did:web:did.teaspoon.world:user:foo` with the ID of the webvh doc

### Step 4
```shell
# replace the folder name with the one displayed in the output of the webvh provision command
 python3 -m did_webvh.update --auto raw.githubusercontent.com_QmX6gpoQeyVuLT5sc7NeP3Nzh9ArrJ7yPAzu8oG5vDAhoC
```

Output
```
Updated DID in raw.githubusercontent.com_QmX6gpoQeyVuLT5sc7NeP3Nzh9ArrJ7yPAzu8oG5vDAhoC
```

### Step 5
- Publish `did.json` and `did.jsonl` on the place you choose in Step 2, i.e., GitHub in this example

### Step 6
Export the DID we created in Step 1
```shell
tsp export-piv did:web:did.teaspoon.world:user:foo
```
Output
```json
{
  "id": "did:web:did.teaspoon.world:user:foo",
  "transport": "https://demo.teaspoon.world/user/did:web:did.teaspoon.world:user:foo",
  "publicSigkey": "AtNdnHax2pimxF1n0Wa6dqYFbmVjE40wwqlDEXMleko",
  "publicEnckey": "OGHlE0TJlXmt58bGxVt3Upkf2UN6Zto6zj2ZS-Xk0XE",
  "sigkey": "C65tnywEQLrHqJqsnmpxtE3G4EhO8Sq1zHGPGMSPe7s",
  "enckey": "3JAnFwxhCo7y8ppeYXzO3HCJxTq-pixPcn-Lnsx2vjI",
  "relationStatus": "Unrelated",
  "relationVid": null,
  "parentVid": null,
  "tunnel": null
}
```

### Step 7
- Replace the DID in `"id"` and `"transport"` with the DID stored in the `did.json` from Step 5

### Step 8
Import into the wallet
```shell
tsp import-piv <temporary-file-with-changed-ids> 
```
Output
```
INFO tsp: created identity from file did:webvh:QmX6gpoQeyVuLT5sc7NeP3Nzh9ArrJ7yPAzu8oG5vDAhoC:raw.githubusercontent.com:openwallet-foundation-labs:tsp:did-webvh:examples:test:foo
```

### Step 9
Check that your DID actually verifies

```shell
tsp --wallet test verify 'did:webvh:QmX6gpoQeyVuLT5sc7NeP3Nzh9ArrJ7yPAzu8oG5vDAhoC:raw.githubusercontent.com:openwallet-foundation-labs:tsp:did-webvh:examples:test:foo'
```

Output
```
INFO tsp: created new wallet
INFO tsp: did:webvh:QmX6gpoQeyVuLT5sc7NeP3Nzh9ArrJ7yPAzu8oG5vDAhoC:raw.githubusercontent.com:openwallet-foundation-labs:tsp:did-webvh:examples:test:foo is verified and added to the wallet test
```