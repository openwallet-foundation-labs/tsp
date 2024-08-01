import {
  ActionIcon,
  Alert,
  Flex,
  Menu,
  Stack,
  rem,
  Modal,
  Badge,
  Box,
  CheckIcon,
} from '@mantine/core';
import {
  IconDotsVertical,
  IconTrash,
  IconCode,
  IconCheck,
} from '@tabler/icons-react';
import { useDisclosure, useHover } from '@mantine/hooks';
import EncodedMessage from './EncodedMessage';

interface ChatMessageProps {
  date: string;
  me: boolean;
  deleteMessage: () => void;
  message: string;
  timestampSignature: string;
  encoded:
    | string
    | {
        name: string;
        href: string;
        size: string;
      };
}

export default function ChatMessage({
  date,
  me,
  message,
  encoded,
  timestampSignature,
  deleteMessage,
}: ChatMessageProps) {
  const { hovered, ref } = useHover();
  const [opened, { open, close }] = useDisclosure(false);

  return (
    <Stack align={me ? 'flex-end' : 'flex-start'}>
      <Alert
        miw={200}
        variant="light"
        color={me ? 'blue.3' : 'gray.5'}
        style={{ textAlign: 'right' }}
        px="sm"
        py="xs"
        ref={ref}
      >
        <Flex align="center" justify="flex-end">
          <Badge
            leftSection={<IconCheck size={10} stroke={4} />}
            color="green"
            variant="light"
            size="sm"
            radius="sm"
            mb="xs"
            onClick={open}
            style={{ cursor: 'pointer' }}
          >
            {date.slice(11, 19)}
          </Badge>

          <Modal
            opened={opened}
            onClose={close}
            title={<strong>TSP message</strong>}
            size="lg"
          >
            <Box c="green" mb="lg">
              <CheckIcon size={14} color="green" />
              &nbsp; Verified by the time server
            </Box>
            <Box c="dimmed">Full date</Box>
            <Box mb="lg">{date.replace('T', ' ').slice(0, 19)}</Box>
            {typeof encoded === 'string' && (
              <>
                <Box c="dimmed">Signature</Box>
                <Box mb="lg">
                  <code
                    style={{
                      display: 'block',
                      wordWrap: 'break-word',
                      wordBreak: 'break-all',
                    }}
                  >
                    {timestampSignature}
                  </code>
                </Box>
              </>
            )}
            <EncodedMessage encoded={encoded} plain={message} />
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
                  left: 0,
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
        {typeof encoded === 'object' && encoded.href ? (
          <a href={encoded.href} download={encoded.name}>
            {message}
          </a>
        ) : (
          message
        )}
      </Alert>
    </Stack>
  );
}
