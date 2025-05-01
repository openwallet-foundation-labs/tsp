import tsp_python as tsp
import random
import requests

store = tsp.SecureStore()

# Create identity
print("Creating identity")
alice_username = "alice" + str(random.randint(0, 999999))
print(f"> Username: {alice_username}")

alice = tsp.OwnedVid.bind(
    f"did:web:did.teaspoon.world:endpoint:{alice_username}",  # my DID
    f"https://demo.teaspoon.world/endpoint/{alice_username}",  # transport URL
)

# Publish DID (this is non-standard and dependents on the implementation of the DID support server)
print("Publishing DID")
response = requests.post(
    "https://did.teaspoon.world/add-vid",
    data=alice.json(),
    headers={"Content-type": "application/json"},
)
if not response.ok:
    raise Exception(
        f"Could not publish DID (status code: {response.status_code}):\n{alice.json()}"
    )

store.add_private_vid(alice)

# Resolve other party (may fail if endpoint bob does not exist)
print("Resolve other party")
bob_did = "did:web:did.teaspoon.world:endpoint:bob"
endpoint = store.resolve_did_web(bob_did)
print("> Bob's endpoint:", endpoint)

# Send a message
print("Send a message")
response = store.send_message(alice.identifier(), bob_did, b"hi bob")
print(f"Success: {response.ok} ({response.status_code})")
