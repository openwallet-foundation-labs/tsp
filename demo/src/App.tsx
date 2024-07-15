import useStore, { Contact, Identity } from './useStore';
import { Burger, Drawer } from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import Initialize from './Initialize';
import Profile from './Profile';
import Contacts from './Contacts';
import Chat from './Chat';

interface ContentProps {
  active: number | null;
  contacts: Contact[];
  createIdentity: (name: string) => void;
  deleteContact: (index: number) => void;
  deleteIdentity: () => void;
  deleteMessage: (contactIndex: number, index: number) => void;
  id: Identity | null;
  initialized: boolean;
  sendMessage: (vid: string, message: string) => void;
}

function Content({
  active,
  contacts,
  createIdentity,
  deleteContact,
  deleteIdentity,
  deleteMessage,
  id,
  initialized,
  sendMessage,
}: ContentProps) {
  if (!initialized) {
    return <Initialize onClick={(name: string) => createIdentity(name)} />;
  }

  if (active !== null) {
    return (
      <Chat
        index={active}
        contact={contacts[active]}
        sendMessage={sendMessage}
        deleteContact={deleteContact}
        deleteMessage={deleteMessage}
      />
    );
  }

  return <Profile id={id} deleteIdentity={deleteIdentity} />;
}

export default function App() {
  const {
    active,
    addContact,
    contacts,
    createIdentity,
    deleteContact,
    deleteIdentity,
    deleteMessage,
    id,
    initialized,
    sendMessage,
    setActive,
  } = useStore();
  const [opened, { toggle }] = useDisclosure();

  return (
    <>
      <Drawer opened={opened} onClose={toggle} position="right">
        <Contacts
          contacts={contacts}
          addContact={addContact}
          setActive={setActive}
          active={active}
          toggle={toggle}
        />
      </Drawer>
      {initialized && (
        <Burger
          opened={opened}
          onClick={toggle}
          size="sm"
          style={{ position: 'fixed', top: 16, right: 16., zIndex: 10 }}
        />
      )}
      <Content
        {...{
          active,
          contacts,
          createIdentity,
          deleteContact,
          deleteIdentity,
          deleteMessage,
          id,
          initialized,
          sendMessage,
        }}
      />
    </>
  );
}
