import useStore, { Contact, Identity } from './useStore';
import { Box, Burger, Drawer, Flex } from '@mantine/core';
import { useDisclosure, useMediaQuery } from '@mantine/hooks';
import Initialize from './Initialize';
import Profile from './Profile';
import Contacts from './Contacts';
import Chat from './Chat';
import ScanContact from './ScanContact';

interface ContentProps {
  active: number | null;
  mobile: boolean;
  contacts: Contact[];
  createIdentity: (name: string) => void;
  deleteContact: (index: number) => void;
  deleteIdentity: () => void;
  deleteMessage: (contactIndex: number, index: number) => void;
  id: Identity | null;
  initialized: boolean;
  openScan: () => void;
  sendFile: (vid: string, file: File) => void;
  sendMessage: (vid: string, message: string) => void;
  verifyContact: (vid: string) => void;
}

function Content({
  active,
  mobile,
  contacts,
  createIdentity,
  deleteContact,
  deleteIdentity,
  deleteMessage,
  id,
  initialized,
  openScan,
  sendMessage,
  sendFile,
  verifyContact,
}: ContentProps) {
  if (!initialized) {
    return <Initialize onClick={(name: string) => createIdentity(name)} />;
  }

  if (active !== null) {
    return (
      <Chat
        index={active}
        mobile={mobile}
        contact={contacts[active]}
        sendMessage={sendMessage}
        sendFile={sendFile}
        verifyContact={verifyContact}
        deleteContact={deleteContact}
        deleteMessage={deleteMessage}
      />
    );
  }

  return (
    <Profile id={id} deleteIdentity={deleteIdentity} openScan={openScan} />
  );
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
    sendFile,
    setActive,
    verifyContact,
  } = useStore();
  const mobile = useMediaQuery('(max-width: 768px)') ?? true;
  const [opened, { toggle }] = useDisclosure();
  const [scanOpened, { open: openScan, close: closeScan }] =
    useDisclosure(false);

  return (
    <Flex justify="stretch" wrap="nowrap" h="100%">
      {mobile ? (
        <Drawer opened={opened} onClose={toggle} position="left">
          <Contacts
            contacts={contacts}
            openScan={openScan}
            setActive={setActive}
            active={active}
            toggle={toggle}
          />
        </Drawer>
      ) : (
        initialized && (
          <Box w="20rem" p="md" bg="gray.0">
            <Contacts
              contacts={contacts}
              openScan={openScan}
              setActive={setActive}
              active={active}
              toggle={toggle}
            />
          </Box>
        )
      )}
      <Box flex="1">
        <ScanContact
          opened={scanOpened}
          close={closeScan}
          addContact={(url: string) => {
            closeScan();
            addContact(url);
          }}
        />
        {initialized && mobile && (
          <Burger
            opened={opened}
            onClick={toggle}
            size="sm"
            style={{ position: 'fixed', top: '1rem', left: '1rem', zIndex: 10 }}
          />
        )}
        <Content
          {...{
            active,
            mobile,
            contacts,
            createIdentity,
            deleteContact,
            deleteIdentity,
            deleteMessage,
            id,
            initialized,
            sendMessage,
            sendFile,
            openScan,
            verifyContact,
          }}
        />
      </Box>
    </Flex>
  );
}
