import tsp_python as tsp
import random
import requests

store = tsp.SecureStore()

# Create identity
print("Creating identity")
username = "alice" + str(random.randint(0, 999999))
did = "did:web:did.teaspoon.world:endpoint:" + username
transport_url = "https://p.teaspoon.world/endpoint/" + did
alice = tsp.OwnedVid.bind(did, transport_url)

# Publish DID (this is non-standard and dependents on the implementation of the DID support server)
print("Publishing DID: " + did)
response = requests.post(
    "https://did.teaspoon.world/add-vid",
    data=alice.json(),
    headers={"Content-type": "application/json"},
)
if not response.ok:
    raise Exception(f"Could not publish DID (status code: {response.status_code})")

# Save DID in wallet
store.add_private_vid(alice)

# Resolve other party (may fail if endpoint bob does not exist)
bob_did = "did:web:did.teaspoon.world:endpoint:bob"
print("Resolving DID: " + bob_did)
bob_endpoint = store.verify_vid(bob_did)
print("> Bob's endpoint:", bob_endpoint)

# Send a message
print("Sending message...")
store.send(alice.identifier(), bob_did, b"hi bob")

# Receive messages
print("Listening for messages...")
while True:
    response = store.receive(alice.identifier())
    print("Received: " + str(response))
    if isinstance(response, tsp.GenericMessage):
        print("> " + str(response.message))
