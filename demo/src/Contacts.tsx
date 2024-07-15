import { Box, Button, NavLink, Stack, Title } from '@mantine/core';
import { Contact } from './useStore';
import { useDisclosure } from '@mantine/hooks';
import { IconUserPlus, IconUser, IconQrcode } from '@tabler/icons-react';
import ScanContact from './ScanContact';

interface ContactsProps {
  contacts: Contact[];
  active: number | null;
  addContact: (url: string) => void;
  setActive: (contact: number | null) => void;
  toggle: () => void;
}

export default function Contacts({
  contacts,
  active,
  addContact,
  setActive,
  toggle,
}: ContactsProps) {
  const [opened, { open, close }] = useDisclosure(false);

  return (
    <Stack justify="strech">
      <ScanContact
        opened={opened}
        close={close}
        addContact={(url: string) => {
          close();
          addContact(url);
        }}
      />
      {contacts.length > 0 && (
        <Box>
          <Title order={3} mb="sm">Contacts</Title>
          {contacts.map((contact, index) => (
            <NavLink
              key={contact.vid.id}
              href={`#${contact.label}`}
              label={contact.label}
              description={`${contact.messages.length || 'No'} messages`}
              leftSection={<IconUser />}
              onClick={(e) => {
                e.preventDefault();
                setActive(index);
                toggle();
              }}
              active={active === index}
            />
          ))}
        </Box>
      )}
      <Title order={3} mt="lg">Connect</Title>
      <Button
        onClick={() => {
          setActive(null);
          toggle();
        }}
        color="blue"
        leftSection={<IconQrcode size={16} />}
        variant="outline"
      >
        Profile
      </Button>
      <Button
        onClick={() => {
          open();
        }}
        color="green"
        leftSection={<IconUserPlus size={16} />}
        variant="outline"
      >
        Add contact
      </Button>
    </Stack>
  );
}
