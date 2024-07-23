import {
  ActionIcon,
  Box,
  Button,
  Flex,
  Group,
  LoadingOverlay,
  Modal,
  Paper,
  rem,
  Table,
  Text,
  TextInput,
} from '@mantine/core';
import { Contact } from './useStore';
import {
  IconSend,
  IconFileUpload,
  IconUpload,
  IconX,
  IconCheck,
} from '@tabler/icons-react';
import { useState } from 'react';
import { Dropzone } from '@mantine/dropzone';
import { useDisclosure, useFocusTrap } from '@mantine/hooks';
import { humanFileSize } from './util';

interface ChatInputProps {
  contact: Contact;
  sendFile: (vid: string, file: File) => void;
  sendMessage: (vid: string, message: string) => void;
}

export default function ChatInput({
  contact,
  sendMessage,
  sendFile,
}: ChatInputProps) {
  const focusTrapRef = useFocusTrap();
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState<string[]>([]);
  const [opened, { open, close }] = useDisclosure(false);
  const [files, setFiles] = useState<File[] | null>(null);
  const [message, setMessage] = useState<string>('');
  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    sendMessage(contact.vid.id, message);
    setMessage('');
  };

  const sendFiles = async () => {
    setLoading(true);
    for (const file of files || []) {
      await sendFile(contact.vid.id, file);
      setDone((current) => [...current, file.name]);
    }
  };

  const finish = () => {
    setFiles(null);
    setLoading(false);
    setDone([]);
    close();
  };

  return (
    <Box bg="gray.2" p="md">
      <Modal
        opened={opened}
        onClose={close}
        title={<strong>Send a file</strong>}
        size="lg"
        portalProps={{ color: 'red' }}
      >
        {files ? (
          <>
            {files.map((file) => (
              <Box pos="relative" key={file.name}>
                <LoadingOverlay
                  visible={loading && !done.includes(file.name)}
                  zIndex={1000}
                  overlayProps={{ radius: 'sm', blur: 1 }}
                />
                <Paper
                  withBorder
                  p="sm"
                  mb="md"
                  bg={done.includes(file.name) ? 'green.0' : 'white'}
                >
                  <Table>
                    <Table.Tbody>
                      <Table.Tr>
                        <Table.Th scope="row" w="5rem">
                          Name
                        </Table.Th>
                        <Table.Td>{file.name}</Table.Td>
                      </Table.Tr>
                      <Table.Tr>
                        <Table.Th scope="row" w="5rem">
                          Size
                        </Table.Th>
                        <Table.Td>{humanFileSize(file.size)}</Table.Td>
                      </Table.Tr>
                      <Table.Tr>
                        <Table.Th scope="row" w="5rem">
                          Type
                        </Table.Th>
                        <Table.Td>{file.type}</Table.Td>
                      </Table.Tr>
                    </Table.Tbody>
                  </Table>
                </Paper>
              </Box>
            ))}
            {(!loading || done.length !== files.length) && (
              <Button
                leftSection={<IconSend />}
                mb="sm"
                onClick={sendFiles}
                loading={loading}
              >
                Send file{files.length > 1 ? 's' : ''}
              </Button>
            )}
            {loading && done.length === files.length && (
              <Button
                leftSection={<IconCheck />}
                mb="sm"
                color="green"
                onClick={finish}
              >
                Finish
              </Button>
            )}
          </>
        ) : (
          <div>
            <Dropzone
              onDrop={setFiles}
              maxSize={50 * 1024 ** 2}
              autoFocus={true}
              activateOnClick={true}
            >
              <Group
                justify="center"
                gap="xl"
                mih={220}
                style={{ pointerEvents: 'none' }}
              >
                <Dropzone.Accept>
                  <IconUpload
                    style={{
                      width: rem(52),
                      height: rem(52),
                      color: 'var(--mantine-color-blue-6)',
                    }}
                    stroke={1.5}
                  />
                </Dropzone.Accept>
                <Dropzone.Reject>
                  <IconX
                    style={{
                      width: rem(52),
                      height: rem(52),
                      color: 'var(--mantine-color-red-6)',
                    }}
                    stroke={1.5}
                  />
                </Dropzone.Reject>
                <Dropzone.Idle>
                  <IconUpload
                    style={{
                      width: rem(52),
                      height: rem(52),
                      color: 'var(--mantine-color-dimmed)',
                    }}
                    stroke={1.5}
                  />
                </Dropzone.Idle>
                <div>
                  <Text size="xl" inline>
                    Drag files here or click to select files
                  </Text>
                  <Text size="sm" c="dimmed" inline mt={7}>
                    Each file should not exceed 50mb
                  </Text>
                </div>
              </Group>
            </Dropzone>
          </div>
        )}
      </Modal>
      <form onSubmit={onSubmit} ref={focusTrapRef}>
        <Flex gap="md" align="stretch">
          <ActionIcon
            variant="filled"
            size="42"
            radius="md"
            type="button"
            onClick={open}
          >
            <IconFileUpload size="20" />
          </ActionIcon>
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
  );
}
