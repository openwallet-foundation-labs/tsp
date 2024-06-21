from tsp import OwnedVid, Store, RequestRelationship, MessageType

def main():
    def new_vid():
        return OwnedVid.new_did_peer("tcp://127.0.0.1:1337")

    store = Store()
    alice = new_vid()
    bob = new_vid()

    store.add_private_vid(alice)
    store.add_private_vid(bob)

    message = b"hello world"

    (url, sealed) = store.make_relationship_request(alice.identifier(), bob.identifier(), None)

    assert url == "tcp://127.0.0.1:1337"

    received = store.open_message(sealed)

    match received:
        case RequestRelationship(sender, _route, _nested_vid, _thread_id):
            assert sender == alice.identifier()
            print("success")

        case other:
            print(f"unexpected message type {other}")
            assert False

if __name__ == '__main__':
    main()
