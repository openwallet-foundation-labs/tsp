import {
  ActionIcon,
  Alert,
  Box,
  Flex,
  Menu,
  Stack,
  Title,
  rem,
  Modal,
  Center,
  Button,
} from '@mantine/core';
import { Contact } from './useStore';
import {
  IconMessages,
  IconDotsVertical,
  IconTrash,
  IconCodeCircle,
  IconAlertTriangle,
  IconChecklist,
} from '@tabler/icons-react';
import { useDisclosure } from '@mantine/hooks';
import ChatMessage from './ChatMessage';
import ChatInput from './ChatInput';

interface ChatProps {
  contact: Contact;
  mobile: boolean;
  sendMessage: (vid: string, message: string) => void;
  sendFile: (vid: string, file: File) => void;
  deleteContact: (index: number) => void;
  deleteMessage: (contactIndex: number, index: number) => void;
  index: number;
  verifyContact: (vid: string) => void;
}

export default function Chat({
  contact,
  index,
  mobile,
  sendMessage,
  sendFile,
  deleteContact,
  deleteMessage,
  verifyContact,
}: ChatProps) {
  const [opened, { open, close }] = useDisclosure(false);

  return (
    <Stack h="100dvh" justify="space-between" gap={0} align="stretch">
      <Modal
        opened={opened}
        onClose={close}
        title={<strong>{`VID of ${contact.label}`}</strong>}
        size="lg"
      >
        <code style={{ wordWrap: 'break-word', wordBreak: 'break-all' }}>
          {contact.vid.id}
        </code>
        {!contact.verified && (
          <Box>
            <Button
              onClick={() => {
                close();
                verifyContact(contact.vid.id);
              }}
              mt="md"
              leftSection={<IconChecklist size={16} />}
              color="orange"
            >
              Verify
            </Button>
          </Box>
        )}
      </Modal>
      <Box bg="gray.2" p="md" pl={mobile ? '4rem' : 'md'}>
        <Flex justify="space-between">
          <Flex gap="xs" align="center">
            {contact.verified ? (
              <IconMessages size={24} />
            ) : (
              <IconAlertTriangle size={24} />
            )}
            <Title size={24}>{contact.label}</Title>
          </Flex>
          <Menu shadow="md" width={180}>
            <Menu.Target>
              <ActionIcon variant="transparent" color="black" mr="sm">
                <IconDotsVertical size={20} />
              </ActionIcon>
            </Menu.Target>
            <Menu.Dropdown>
              <Menu.Item
                onClick={open}
                leftSection={
                  <IconCodeCircle style={{ width: rem(14), height: rem(14) }} />
                }
              >
                Show VID
              </Menu.Item>
              <Menu.Label>Danger zone</Menu.Label>
              <Menu.Item
                color="red"
                onClick={() => deleteContact(index)}
                leftSection={
                  <IconTrash style={{ width: rem(14), height: rem(14) }} />
                }
              >
                Delete contact
              </Menu.Item>
            </Menu.Dropdown>
          </Menu>
        </Flex>
      </Box>
      {contact.verified ? (
        <>
          <Box
            flex={1}
            style={{
              overflowY: 'auto',
              display: 'flex',
              flexDirection: 'column-reverse',
            }}
          >
            <Flex
              style={{ flex: 1 }}
              px="md"
              justify="flex-start"
              direction="column"
              gap="sm"
              py="sm"
            >
              {contact.messages.map(({ date, me, message, encoded }, i) => (
                <ChatMessage
                  key={date}
                  date={date}
                  me={me}
                  message={message}
                  encoded={encoded}
                  deleteMessage={() => deleteMessage(index, i)}
                />
              ))}
            </Flex>
          </Box>
          <ChatInput
            contact={contact}
            sendMessage={sendMessage}
            sendFile={sendFile}
          />
        </>
      ) : (
        <Box flex={1}>
          <Center>
            <Alert
              color="red"
              variant="light"
              m="xl"
              w="400px"
              icon={<IconAlertTriangle />}
              title="This contact is not verified"
            >
              {contact.label} is not verified. You can view the VID and verify
              this contact by clicking the button below.
              <Box>
                <Button
                  onClick={open}
                  variant="filled"
                  mt="sm"
                  color="orange"
                  leftSection={<IconChecklist size={16} />}
                >
                  Verify
                </Button>
              </Box>
            </Alert>
          </Center>
        </Box>
      )}
    </Stack>
  );
}
