import tsp
import random
import requests

store = tsp.SecureStore()

# Create identity
alice_username = "alice" + str(random.randint(0, 999999))
print(f"Username: {alice_username}")

alice = tsp.OwnedVid.bind(
    f"did:web:did.teaspoon.world:user:{alice_username}", # my DID
    f"https://demo.teaspoon.world/user/{alice_username}", # transport URL
)

# Publish DID (this is non-standard and dependents on the implementation of the DID support server)
response = requests.post("https://did.teaspoon.world/add-vid", data = alice.json(), headers={"Content-type": "application/json"})
if not response.ok:
    raise Exception(f"Could not publish DID (status code: {response.status_code}):\n{alice.json()}");

store.add_private_vid(alice)

# Resolve other party
bob_did = "did:web:did.teaspoon.world:user:bob"
store.resolve_did_web(bob_did)

response = store.send_message(alice.identifier(), bob_did, b"hi bob")

print(response.status_code)
