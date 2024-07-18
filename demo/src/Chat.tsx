import {
  ActionIcon,
  Alert,
  Box,
  Flex,
  Menu,
  Stack,
  TextInput,
  Title,
  Text,
  rem,
  Modal,
  Center,
  Button,
} from '@mantine/core';
import { Contact } from './useStore';
import {
  IconSend,
  IconMessages,
  IconDotsVertical,
  IconTrash,
  IconCode,
  IconCodeCircle,
  IconAlertTriangle,
  IconChecklist,
} from '@tabler/icons-react';
import { useState } from 'react';
import { useDisclosure, useFocusTrap, useHover } from '@mantine/hooks';

interface ChatProps {
  contact: Contact;
  mobile: boolean;
  sendMessage: (vid: string, message: string) => void;
  deleteContact: (index: number) => void;
  deleteMessage: (contactIndex: number, index: number) => void;
  index: number;
  verifyContact: (vid: string) => void;
}

interface ChatMessageProps {
  date: string;
  me: boolean;
  deleteMessage: () => void;
  message: string;
  encoded: string;
}

function ChatMessage({
  date,
  me,
  message,
  encoded,
  deleteMessage,
}: ChatMessageProps) {
  const { hovered, ref } = useHover();
  const [opened, { open, close }] = useDisclosure(false);

  return (
    <Stack align={me ? 'flex-end' : 'flex-start'}>
      <Alert
        miw={200}
        variant="light"
        color={me ? 'green' : 'blue'}
        style={{ textAlign: 'right' }}
        pr={24}
        py="sm"
        ref={ref}
      >
        <Flex align="center" justify="flex-end">
          <Text c="gray" size="xs">
            {date.slice(11, 16)}
          </Text>
          <Modal
            opened={opened}
            onClose={close}
            title={<strong>CESR encoded message</strong>}
            size="lg"
          >
            <code style={{ wordWrap: 'break-word', wordBreak: 'break-all' }}>
              {encoded}
            </code>
          </Modal>
          <Menu shadow="md" width={180}>
            <Menu.Target>
              <ActionIcon
                variant="transparent"
                color="light"
                size="md"
                style={{
                  position: 'absolute',
                  top: 0,
                  right: 0,
                  visibility: hovered ? 'visible' : 'hidden',
                }}
              >
                <IconDotsVertical size={14} />
              </ActionIcon>
            </Menu.Target>
            <Menu.Dropdown>
              <Menu.Item
                onClick={open}
                leftSection={
                  <IconCode style={{ width: rem(14), height: rem(14) }} />
                }
              >
                CESR message
              </Menu.Item>
              <Menu.Item
                color="red"
                onClick={() => deleteMessage()}
                leftSection={
                  <IconTrash style={{ width: rem(14), height: rem(14) }} />
                }
              >
                Delete message
              </Menu.Item>
            </Menu.Dropdown>
          </Menu>
        </Flex>
        {message}
      </Alert>
    </Stack>
  );
}

export default function Chat({
  contact,
  index,
  mobile,
  sendMessage,
  deleteContact,
  deleteMessage,
  verifyContact,
}: ChatProps) {
  const focusTrapRef = useFocusTrap();
  const [opened, { open, close }] = useDisclosure(false);
  const [message, setMessage] = useState<string>('');
  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    sendMessage(contact.vid.id, message);
    setMessage('');
  };

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
          <Box bg="gray.2" p="md">
            <form onSubmit={onSubmit} ref={focusTrapRef}>
              <Flex gap="md" align="stretch">
                <TextInput
                  size="md"
                  radius="md"
                  placeholder="Type a message..."
                  flex={1}
                  data-autofocus
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                />
                <ActionIcon
                  variant="filled"
                  size="42"
                  radius="md"
                  disabled={message.length === 0}
                  type="submit"
                >
                  <IconSend size="20" />
                </ActionIcon>
              </Flex>
            </form>
          </Box>
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
