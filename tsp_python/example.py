import tsp
import random

store = tsp.Store()

alice_username = "alice" + str(random.randint(0, 999999))
print(f"Username: {alice_username}")

alice = tsp.OwnedVid.bind(
    f"did:web:did.teaspoon.world:user:{alice_username}",
    f"https://demo.teaspoon.world/user/{alice_username}",
)

store.add_private_vid(alice)

bob_did = "did:web:did.teaspoon.world:user:appelsap"
store.verify(bob_did)

message = store.seal_message(alice.identifier(), bob_did, None, b"hi bob")
print(message)

# TODO: send message
