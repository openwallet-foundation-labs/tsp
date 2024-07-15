import { Button, Center, Flex, Input, Modal, Title } from '@mantine/core';
import { useDisclosure, useFocusTrap } from '@mantine/hooks';
import { IconUserPlus } from '@tabler/icons-react';
import { useState } from 'react';
import logo from './trust-over-ip.svg';

interface InitializeProps {
  onClick: (name: string) => void;
}

export default function Initialize({ onClick }: InitializeProps) {
  const [opened, { open, close }] = useDisclosure(false);
  const [label, setLabel] = useState<string>('');
  const [error, setError] = useState<string>('');
  const focusTrapRef = useFocusTrap();

  const save = () => {
    if (label.length > 0) {
      onClick(label);
      setLabel('');
      setError('');
      close();
    } else {
      setError('Label is required');
    }
  };

  return (
    <>
      <Modal
        opened={opened}
        onClose={close}
        centered
        title={<strong>Create identity</strong>}
        overlayProps={{
          backgroundOpacity: 0.55,
          blur: 3,
        }}
      >
        <form onSubmit={save} ref={focusTrapRef}>
          <Input.Wrapper label="Label" error={error}>
            <Input
              placeholder="Your name or nickname"
              value={label}
              required
              error={error}
              data-autofocus
              onChange={(e) => setLabel(e.target.value)}
            />
          </Input.Wrapper>
          <Flex mih={60} gap="md" justify="flex-end" align="flex-end">
            <Button size="md" variant="filled" type="submit">
              Create
            </Button>
          </Flex>
        </form>
      </Modal>
      <Flex align="center" justify="center" bg="gray.1" p="md">
        <img src={logo} alt="Trust Over IP" style={{ height: 24 }} />
        <Title order={2} ml="md" c="#0031B6">
          TSP Chat
        </Title>
      </Flex>
      <Center h="200">
        <Button
          size="xl"
          variant="gradient"
          onClick={open}
          gradient={{
            from: 'indigo',
            to: 'cyan',
            deg: 90,
          }}
          leftSection={<IconUserPlus />}
        >
          Create identity
        </Button>
      </Center>
    </>
  );
}
