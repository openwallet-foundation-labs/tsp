# This files defines the Python types for the generated PyO3 classes that are exposed directly
# without wrapping it in a Python class

# ANCHOR: OwnedVid-mdBook
class OwnedVid:
    """Class for managing VIDs for which we own the private keys"""

    @staticmethod
    def new_did_peer(url: str) -> OwnedVid:
        """Create a `did:peer` for a particular end-point"""
        ...

    @staticmethod
    def new_did_webvh(did_name: str, transport: str) -> tuple[OwnedVid, str]:
        """Create a `did:webvh` for a name and a transport URL"""
        ...

    @staticmethod
    def bind(did: str, transport_url: str) -> OwnedVid:
        """Create a `did:web` by binding a DID to a transport URL"""
        ...

    def json(self) -> str:
        """Get a JSON representation of the VID"""
        ...

    def identifier(self) -> str:
        """Get the DID"""
        ...

    def endpoint(self) -> str:
        """Get the transport URL"""
        ...
    # ANCHOR_END: OwnedVid-mdBook
