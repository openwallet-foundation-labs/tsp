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
} from '@mantine/core';
import { Contact } from './useStore';
import {
  IconSend,
  IconMessages,
  IconDotsVertical,
  IconTrash,
} from '@tabler/icons-react';
import { useState } from 'react';
import { useFocusTrap, useHover } from '@mantine/hooks';

interface ChatProps {
  contact: Contact;
  sendMessage: (vid: string, message: string) => void;
  deleteContact: (index: number) => void;
  deleteMessage: (contactIndex: number, index: number) => void;
  index: number;
}

interface ChatMessageProps {
  date: string;
  me: boolean;
  deleteMessage: () => void;
  message: string;
}

function ChatMessage({ date, me, message, deleteMessage }: ChatMessageProps) {
  const { hovered, ref } = useHover();

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
  sendMessage,
  deleteContact,
  deleteMessage,
}: ChatProps) {
  const focusTrapRef = useFocusTrap();
  const [message, setMessage] = useState<string>('');
  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    sendMessage(contact.vid.id, message);
    setMessage('');
  };

  return (
    <Stack
      h="100dvh"
      justify="space-between"
      gap={0}
      align="stretch"
    >
      <Box bg="gray.1" p="md">
        <Flex justify="space-between">
          <Flex gap="xs" align="center">
            <IconMessages size={24} />
            <Title size={24}>{contact.label}</Title>
          </Flex>
          <Menu shadow="md" width={180}>
            <Menu.Target>
              <ActionIcon variant="transparent" color="black" mr={32}>
                <IconDotsVertical size={20} />
              </ActionIcon>
            </Menu.Target>
            <Menu.Dropdown>
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
          {contact.messages.map(({ date, me, message }, i) => (
            <ChatMessage
              key={date}
              date={date}
              me={me}
              message={message}
              deleteMessage={() => deleteMessage(index, i)}
            />
          ))}
        </Flex>
      </Box>
      <Box bg="gray.1" p="md">
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
    </Stack>
  );
}
