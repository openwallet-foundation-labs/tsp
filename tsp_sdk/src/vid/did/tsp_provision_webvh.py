from did_webvh.askar import AskarSigningKey
from did_webvh.const import (
    METHOD_NAME,
)
from did_webvh.domain_path import DomainPath
from did_webvh.provision import provision_did

def placeholder_id(domain_path: str) -> str:
    pathinfo = DomainPath.parse_normalized(domain_path)
    return f"did:{METHOD_NAME}:{pathinfo.identifier}"


def tsp_provision_did(genesis_document: dict) -> tuple:
    update_key = AskarSigningKey.generate("ed25519")

    # the SCID in the transport does get percent encoded in Rust, but we need the original value to make the {SCID} replacement work.
    genesis_document['service'][0]['serviceEndpoint'] = genesis_document['service'][0]['serviceEndpoint'].replace('%7B', '{').replace('%7D', '}')

    params = dict(updateKeys=[update_key.multikey])
    state = provision_did(genesis_document, params=params, hash_name="sha2-256")

    state.proofs.append(
        state.create_proof(
            update_key,
            timestamp=state.timestamp,
        )
    )

    return state.history_json(), update_key.kid, update_key.key.get_jwk_secret()