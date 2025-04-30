import { useEffect, useReducer, useRef } from 'react';
import {
  OwnedVid,
  Vid,
  Store,
  verify_vid,
  probe_message,
} from '../pkg/tsp_demo';
import { bufferToBase64, humanFileSize } from './util';
import ReconnectingWebSocket from 'reconnecting-websocket';

const TIMESTAMP_SERVER = {
  id: 'did:web:raw.githubusercontent.com:openwallet-foundation-labs:tsp:main:examples:test:timestamp-server',
  publicEnckey: '2SOeMndN9z4oArm7Vu7D7ZGnkbsAXZ2DO-GUAfBd_Bo',
  publicSigkey: 'HR76y6YG5BWHbj4UQsqX-5ybQPjtETiaZFa4LHWaI68',
  transport: 'https://demo.teaspoon.world/timestamp',
};

export interface Identity {
  label: string;
  vid: {
    enckey: string;
    id: string;
    publicEnckey: string;
    publicSigkey: string;
    sigkey: string;
    transport: string;
  };
}

export interface Contact {
  label: string;
  messages: Array<Message>;
  verified: boolean;
  vid: {
    id: string;
    publicEnckey: string;
    publicSigkey: string;
    transport: string;
  };
}

type Encoded =
  | string
  | {
    name: string;
    href: string;
    size: string;
  };

export interface Message {
  date: string;
  message: string;
  encoded: Encoded;
  timestampSignature: string;
  me: boolean;
}

interface State {
  id: Identity | null;
  contacts: Contact[];
  active: number | null;
}

function loadState(): State {
  const state = localStorage.getItem('state');

  if (state) {
    const parsed = JSON.parse(state);

    // clear old object url's
    parsed.contacts.forEach((contact: Contact) => {
      contact.messages.forEach((message: Message) => {
        if (typeof message.encoded !== 'string') {
          message.encoded.href = '';
        }
      });

      return contact;
    });

    return parsed;
  }

  return {
    id: null,
    contacts: [],
    active: null,
  };
}

type Action =
  | { type: 'setActive'; index: number | null }
  | { type: 'addContact'; contact: Contact }
  | { type: 'verifyContact'; vid: string }
  | { type: 'removeContact'; index: number }
  | { type: 'removeMessage'; contactIndex: number; messageIndex: number }
  | {
    type: 'addMessage';
    contactVid: string;
    message: string;
    encoded: Encoded;
    timestamp: number;
    timestampSignature: string;
    me: boolean;
  }
  | { type: 'setId'; id: Identity }
  | { type: 'reset' };

function reducer(state: State, action: Action): State {
  switch (action.type) {
    case 'setActive':
      return { ...state, active: action.index };
    case 'addContact':
      return {
        ...state,
        contacts: [...state.contacts, action.contact],
        active: state.contacts.length,
      };
    case 'verifyContact':
      return {
        ...state,
        contacts: state.contacts.map((c) =>
          c.vid.id === action.vid ? { ...c, verified: true } : c
        ),
        active: null,
      };
    case 'removeContact':
      return {
        ...state,
        contacts: state.contacts.filter((_, i) => i !== action.index),
        active: null,
      };
    case 'removeMessage':
      return {
        ...state,
        contacts: state.contacts.map((contact, i) => {
          if (i === action.contactIndex) {
            return {
              ...contact,
              messages: contact.messages.filter(
                (_, j) => j !== action.messageIndex
              ),
            };
          }

          return contact;
        }),
      };
    case 'addMessage':
      return {
        ...state,
        contacts: state.contacts.map((contact) => {
          if (contact.vid.id === action.contactVid) {
            return {
              ...contact,
              messages: [
                ...contact.messages,
                {
                  date: new Date(action.timestamp * 1000).toISOString(),
                  message: action.message,
                  encoded: action.encoded,
                  timestampSignature: action.timestampSignature || 'none',
                  me: action.me,
                },
              ],
            };
          }

          return contact;
        }),
      };
    case 'setId':
      return { ...state, id: action.id };
    case 'reset':
      return { id: null, contacts: [], active: null };
    default:
      return state;
  }
}

export default function useStore() {
  const ws = useRef<ReconnectingWebSocket | null>(null);
  const store = useRef<Store>(new Store());
  const [state, dispatch] = useReducer(reducer, loadState());

  const createIdentity = async (label: string, web: boolean) => {
    try {
      if (web) {
        const data = new URLSearchParams();
        data.append('name', label);
        let result = await fetch('https://demo.teaspoon.world/create-identity', {
          method: 'POST',
          body: data,
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        });
        let vidData = await result.json();
        const vid = OwnedVid.from_json(JSON.stringify(vidData));
        const id = { label, vid: vidData };
        store.current.add_private_vid(vid.create_clone());
        dispatch({ type: 'setId', id });
      } else {
        const vid = OwnedVid.new_did_peer(
          `https://demo.teaspoon.world/endpoint/[vid_placeholder]`
        );
        const id = { label, vid: JSON.parse(vid.to_json()) };
        store.current.add_private_vid(vid.create_clone());
        dispatch({ type: 'setId', id });
      }
    } catch (e) {
      console.error(e);
      return false;
    }

    return true;
  };

  const addContact = async (vidString: string, label: string) => {
    const vid = await verify_vid(vidString);

    const contact = {
      label,
      vid: JSON.parse(vid.create_clone().to_json()),
      messages: [],
      verified: false,
    };

    if (state.contacts.find((c: Contact) => c.vid.id === contact.vid)) {
      window.alert('Contact already exists');
      return;
    }

    store.current.add_verified_vid(vid.create_clone());
    dispatch({ type: 'addContact', contact });
  };

  const addContactFromUrl = (url: string) => {
    const parsedUrl = new URL(url);
    const params = new URLSearchParams(parsedUrl.hash.replace(/^(#)+/, ''));
    const label = params.get('label')!;

    if (!params.get('vid')) {
      return;
    }

    addContact(params.get('vid')!, label);
  };

  const deleteIdentity = () => {
    dispatch({ type: 'reset' });
    window.location.reload();
  };

  const deleteContact = (index: number) => {
    dispatch({ type: 'removeContact', index });
  };

  const deleteMessage = (contactIndex: number, messageIndex: number) => {
    dispatch({ type: 'removeMessage', contactIndex, messageIndex });
  };

  const setActive = (index: number | null) => {
    dispatch({ type: 'setActive', index });
  };

  const verifyContact = (vid: string) => {
    dispatch({
      type: 'verifyContact',
      vid,
    });
    dispatch({
      type: 'setActive',
      index: state.contacts.findIndex((c) => c.vid.id === vid),
    });
  };

  const sendBody = async (
    sender: Identity,
    vid: string,
    message: string,
    encoded: null | Encoded,
    body: Uint8Array
  ) => {
    const d = new Date();
    const timestamp = Math.round(d.getTime() / 1000);
    const unencrypted = new TextEncoder().encode(
      JSON.stringify({
        name: sender.label,
        timestamp,
      })
    );

    const { url, sealed } = store.current.seal_message(
      sender.vid.id,
      vid,
      unencrypted,
      body
    );
    // timestamp sign
    const signResponse = await fetch('https://demo.teaspoon.world/sign-timestamp', {
      method: 'POST',
      body: sealed,
    });

    if (signResponse.status !== 200) {
      window.alert(`Failed sending message ${signResponse.statusText}`);
      return;
    }

    const signed = new Uint8Array(await signResponse.arrayBuffer());

    const response = await fetch(url, {
      method: 'POST',
      body: signed,
    });

    if (response.status !== 200) {
      window.alert(`Failed sending message ${response.statusText}`);
      return;
    }

    dispatch({
      type: 'addMessage',
      contactVid: vid,
      encoded: encoded || (await bufferToBase64(sealed)),
      message,
      timestamp,
      timestampSignature: 'none',
      me: true,
    });
  };

  const sendMessage = async (vid: string, message: string) => {
    if (state.id) {
      const bytes = new TextEncoder().encode(message);
      const body = new Uint8Array([0, ...bytes]);

      sendBody(state.id, vid, message, null, body);
    }
  };

  const sendFile = async (vid: string, file: File) => {
    if (state.id && file.name.length > 0) {
      const name = new TextEncoder().encode(file.name.slice(0, 254));
      const fileBytes = new Uint8Array(await file.arrayBuffer());
      const body = new Uint8Array([name.length, ...name, ...fileBytes]);

      const blob = new Blob([fileBytes], {
        type: 'application/octet-stream',
      });

      const encoded = {
        name: file.name,
        href: window.URL.createObjectURL(blob),
        size: humanFileSize(fileBytes.length),
      };

      const message = `File: ${file.name} (${humanFileSize(file.size)})`;
      sendBody(state.id, vid, message, encoded, body);
    }
  };

  // populate the store
  useEffect(() => {
    if (store.current) {
      // timestamp server vid
      store.current.add_verified_vid(
        Vid.from_json(JSON.stringify(TIMESTAMP_SERVER))
      );
      state.contacts.forEach((contact: Contact) => {
        store.current.add_verified_vid(
          Vid.from_json(JSON.stringify(contact.vid))
        );
      });
      if (state.id) {
        store.current.add_private_vid(
          OwnedVid.from_json(JSON.stringify(state.id.vid))
        );
      }
    }
  }, [store.current]);

  // persist to local storage
  useEffect(() => {
    localStorage.setItem('state', JSON.stringify(state));
  }, [state]);

  // add contact via url hash
  useEffect(() => {
    if (window.location.hash) {
      addContactFromUrl(window.location.href);
      history.pushState(
        '',
        document.title,
        window.location.pathname + window.location.search
      );
    }
  }, []);

  // setup websocket
  useEffect(() => {
    if (state.id) {
      ws.current = new ReconnectingWebSocket(
        `wss://demo.teaspoon.world/endpoint/${state.id.vid.id}`
      );
      const wsCurrent = ws.current;
      ws.current.onmessage = async (e) => {
        try {
          // unseal timestamp server message
          const tsBytes = new Uint8Array(await e.data.arrayBuffer());
          const timestampSignature = bufferToBase64(tsBytes.slice(-64));
          const tsPlaintext = store.current.open_message(tsBytes);

          if (tsPlaintext.sender !== TIMESTAMP_SERVER.id) {
            window.alert(
              'Did not receive message signed by the timestamp server'
            );
            return;
          }

          // unseal inner message
          const bytes = tsPlaintext.nonconfidential_data;
          const envelope = JSON.parse(probe_message(bytes));
          const metadata = JSON.parse(envelope.nonconfidential_data);
          const timestamp = metadata.timestamp;

          if (!state.contacts.find((c) => c.vid.id === envelope.sender)) {
            await addContact(envelope.sender, metadata.name);
          }

          const plaintext = store.current.open_message(bytes);
          const contactVid = plaintext.sender as string;
          const isText = plaintext.message[0] === 0;

          if (isText) {
            const encoded = bufferToBase64(bytes);
            const body = new Uint8Array(plaintext.message);
            const message = new TextDecoder().decode(body.slice(1));

            dispatch({
              type: 'addMessage',
              contactVid,
              message,
              encoded,
              timestampSignature,
              timestamp,
              me: false,
            });
          } else {
            const body = new Uint8Array(plaintext.message);
            const name = new TextDecoder().decode(body.slice(1, body[0] + 1));
            const fileBytes = body.slice(body[0] + 1);
            const message = `File: ${name} (${humanFileSize(
              fileBytes.length
            )})`;

            const blob = new Blob([fileBytes], {
              type: 'application/octet-stream',
            });

            dispatch({
              type: 'addMessage',
              contactVid,
              message,
              encoded: {
                name,
                href: window.URL.createObjectURL(blob),
                size: humanFileSize(fileBytes.length),
              },
              timestampSignature,
              timestamp,
              me: false,
            });
          }
        } catch (e) {
          console.error(e);
        }
      };

      return () => wsCurrent.close();
    }
  }, [state.id, state.contacts.length]);

  return {
    addContact: addContactFromUrl,
    setActive,
    createIdentity,
    deleteIdentity,
    sendMessage,
    sendFile,
    deleteContact,
    verifyContact,
    deleteMessage,
    initialized: state.id !== null,
    ...state,
  };
}
