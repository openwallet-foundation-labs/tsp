import { useEffect, useReducer, useRef } from 'react';
import {
  OwnedVid,
  Vid,
  Store,
  verify_did_peer,
  probe_message,
} from '../pkg/tsp_demo';
import { bufferToBase64 } from './util';

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

export interface Message {
  date: string;
  message: string;
  encoded: string;
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
    return JSON.parse(state);
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
      encoded: string;
      me: boolean;
    }
  | { type: 'setId'; id: Identity }
  | { type: 'reset' };

function reducer(state: State, action: Action) {
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
                  date: new Date().toISOString(),
                  message: action.message,
                  encoded: action.encoded,
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
  const ws = useRef<WebSocket | null>(null);
  const store = useRef<Store>(new Store());
  const [state, dispatch] = useReducer(reducer, loadState());

  const createIdentity = (label: string) => {
    const vid = OwnedVid.new_did_peer(
      `https://tsp-test.org/user/${label.toLowerCase()}`
    );
    const id = { label, vid: JSON.parse(vid.to_json()) };
    store.current.add_private_vid(vid.create_clone());
    dispatch({ type: 'setId', id });
  };

  const addContact = (vidString: string, label: string) => {
    const vid = verify_did_peer(vidString);
    const contact = {
      label,
      vid: JSON.parse(vid.to_json()),
      messages: [],
      verified: false,
    };

    if (state.contacts.find((c) => c.vid.id === contact.vid)) {
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

  const sendMessage = async (vid: string, message: string) => {
    if (state.id) {
      const body = new TextEncoder().encode(message);
      const unencrypted = new TextEncoder().encode(state.id.label);
      const { url, sealed } = store.current.seal_message(
        state.id.vid.id,
        vid,
        unencrypted,
        body
      );
      await fetch(url, {
        method: 'POST',
        body: sealed,
      });
      const encoded = await bufferToBase64(sealed);
      dispatch({
        type: 'addMessage',
        contactVid: vid,
        encoded,
        message,
        me: true,
      });
    }
  };

  // populate the store
  useEffect(() => {
    if (store.current) {
      state.contacts.forEach((contact) => {
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
      ws.current = new WebSocket(`wss://tsp-test.org/vid/${state.id.vid.id}`);
      const wsCurrent = ws.current;
      ws.current.onmessage = async (e) => {
        try {
          const bytes = new Uint8Array(await e.data.arrayBuffer());
          const envelope = JSON.parse(probe_message(bytes));

          if (!state.contacts.find((c) => c.vid.id === envelope.sender)) {
            addContact(envelope.sender, envelope.nonconfidential_data);
          }

          const encoded = await bufferToBase64(bytes);
          const plaintext = store.current.open_message(bytes);
          const body = new Uint8Array(plaintext.message);
          const message = new TextDecoder().decode(body);
          const contactVid = plaintext.sender as string;

          dispatch({
            type: 'addMessage',
            contactVid,
            message,
            encoded,
            me: false,
          });
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
    deleteContact,
    verifyContact,
    deleteMessage,
    initialized: state.id !== null,
    ...state,
  };
}
