import { useEffect, useState } from 'react';
import { OwnedVid, Vid, Store } from "../pkg/tsp_demo";

const bob = {
    id: "did:web:did.tsp-test.org:user:bob",
    publicEnckey: "QFn5SXupDgBTtzkGc2W3MvoSCHjd8uUD0dapfEXqET4",
    publicSigkey: "NBcP690uVtoJChxvBCxZyy2inI-R24G3aNBWOKwU5lI",
    transport: "thttps://demo.tsp-test.org"
};

export default function useStore() {
  const [store, ] = useState<Store>(new Store());
  const [id, setId] = useState<OwnedVid | null>(null);
  const [other, setOther] = useState<OwnedVid | null>(null);

  useEffect(() => {
    const vid = OwnedVid.new_did_peer("https://demo.tsp-test.org");
    setId(vid);
    store.add_private_vid(vid);

    const bob_vid = Vid.from_json(JSON.stringify(bob));
    setOther(bob_vid);
    store.add_verified_vid(bob_vid);

  }, [store]);
  
  return {
    id,
    other,
    store,
  }
}
