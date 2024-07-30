import { QRCode } from 'react-qrcode-logo';
import { Identity } from './useStore';
import { Box, Button, CopyButton, Flex, Stack, Title } from '@mantine/core';
import { useElementSize } from '@mantine/hooks';
import { identityToUrl } from './util';
import logo from './trust-over-ip.svg';
import {
  IconTrash,
  IconClipboard,
  IconIdBadge2,
  IconUserPlus,
} from '@tabler/icons-react';

interface ProfileProps {
  id: Identity | null;
  deleteIdentity: () => void;
  openScan: () => void;
}

export default function Profile({
  id,
  deleteIdentity,
  openScan,
}: ProfileProps) {
  const { ref, width } = useElementSize();

  if (id === null) {
    return null;
  }

  const url = identityToUrl(id);

  return (
    <Stack ref={ref}>
      <Flex align="center" justify="center" bg="gray.2" p="md">
        <img src={logo} alt="Trust Over IP" style={{ height: 24 }} />
        <Title order={2} ml="md" c="#0031B6">
          TSP Chat
        </Title>
      </Flex>
      <Flex gap="lg" align="center" direction="column" p="md">
        <Flex align="center">
          <IconIdBadge2 size={28} />
          <Title order={2} size={30} ml={6}>
            {id.label}
          </Title>
        </Flex>
        {width !== null && (
          <QRCode quietZone={0} value={url} size={Math.min(width * 0.8, 512)} />
        )}
        <Box>{id.vid.id.length < 128 && <pre>{id.vid.id}</pre>}</Box>
        <Flex gap="md" align="center">
          <CopyButton value={url}>
            {({ copied, copy }) => (
              <Button
                color={copied ? 'teal' : 'blue'}
                variant="outline"
                onClick={copy}
                leftSection={<IconClipboard size={16} />}
              >
                {copied ? 'Copied url' : 'Copy my url'}
              </Button>
            )}
          </CopyButton>
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
          <Button
            onClick={deleteIdentity}
            color="red"
            variant="outline"
            leftSection={<IconTrash size={16} />}
          >
            Delete identity
          </Button>
        </Flex>
      </Flex>
    </Stack>
  );
}
