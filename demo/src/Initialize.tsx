import { Button, Center, Flex, Input, Modal, Title } from '@mantine/core';
import { useDisclosure, useFocusTrap } from '@mantine/hooks';
import { IconUserPlus } from '@tabler/icons-react';
import { FormEvent, useState } from 'react';
import logo from './trust-over-ip.svg';
import { DidType } from './useStore';

interface InitializeProps {
  onClick: (name: string, didType: DidType) => Promise<boolean>;
}

export default function Initialize({ onClick }: InitializeProps) {
  const [opened, { open, close }] = useDisclosure(false);
  const [label, setLabel] = useState<string>('');
  const [didType, setDidType] = useState<DidType>('web');
  const [error, setError] = useState<string>('');
  const focusTrapRef = useFocusTrap();

  const save = (e: FormEvent) => {
    e.preventDefault();

    if (label.length > 0) {
      onClick(label, didType).then((result) => {
        if (!result) {
          setError("This username is already taken");
        } else {
          setLabel('');
          setError('');
          close();
        }
      });
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
        size="lg"
        overlayProps={{
          backgroundOpacity: 0.55,
          blur: 3,
        }}
        mod={{
          miw: 500,
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
            <Button
                size="md"
                variant="filled"
                type="submit"
                onClick={() => setDidType('tdw')}
              >
              Create did:tdw
            </Button>
            <Button
              size="md"
              variant="filled"
              type="submit"
              onClick={() => setDidType('web')}
            >
              Create did:web
            </Button>
            <Button
              size="md"
              variant="filled"
              type="submit"
              onClick={() => setDidType('peer')}
            >
              Create did:peer
            </Button>
          </Flex>
        </form>
      </Modal>
      <Flex align="center" justify="center" bg="gray.2" p="md">
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
