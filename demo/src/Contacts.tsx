import {
  Box,
  Button,
  NavLink,
  Stack,
  Title,
  Text,
  Badge,
  Flex,
} from '@mantine/core';
import { Contact } from './useStore';
import {
  IconUserPlus,
  IconUser,
  IconQrcode,
  IconAlertTriangle,
} from '@tabler/icons-react';

interface ContactsProps {
  contacts: Contact[];
  active: number | null;
  openScan: () => void;
  setActive: (contact: number | null) => void;
  toggle: () => void;
}

export default function Contacts({
  contacts,
  active,
  openScan,
  setActive,
  toggle,
}: ContactsProps) {
  return (
    <Stack justify="strech">
      {contacts.length > 0 && (
        <Box>
          <Title order={3} mb="sm">
            Contacts
          </Title>
          {contacts.map((contact, index) => (
            <NavLink
              key={contact.vid.id}
              href={`#${contact.label}`}
              label={
                <Flex justify="space-between">
                  <Text size="sm">{contact.label}</Text>
                  {contact.verified && (
                    <Badge color="green" size="xs">
                      verified
                    </Badge>
                  )}
                </Flex>
              }
              bg={active === index ? 'blue.0' : 'gray.2'}
              description={
                contact.verified ? (
                  `${contact.messages.length || 'No'} messages`
                ) : (
                  <Text c="red" size="xs">
                    Not verified
                  </Text>
                )
              }
              leftSection={
                contact.verified ? <IconUser /> : <IconAlertTriangle />
              }
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
      <Title order={3} mt="lg">
        Connect
      </Title>
      <Button
        onClick={() => {
          setActive(null);
          toggle();
        }}
        color="blue"
        leftSection={<IconQrcode size={16} />}
        variant={active === null ? 'filled' : 'outline'}
      >
        Profile
      </Button>
      <Button
        onClick={() => {
          openScan();
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
