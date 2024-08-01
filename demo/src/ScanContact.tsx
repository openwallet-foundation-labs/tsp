import {
  Box,
  Button,
  Flex,
  Group,
  Input,
  Loader,
  Modal,
  Text,
} from '@mantine/core';
import { IconUserPlus } from '@tabler/icons-react';
import { Html5Qrcode } from 'html5-qrcode';
import { useEffect, useState } from 'react';

interface ScanContactProps {
  opened: boolean;
  close: () => void;
  addContact: (url: string) => void;
}

interface ScannerProps {
  addContact: (url: string) => void;
}

const qrcodeRegionId = 'html5qr-code-full-region';

function Scanner({ addContact }: ScannerProps) {
  useEffect(() => {
    Html5Qrcode.getCameras()
      .then((devices) => {
        if (devices && devices.length) {
          const qrCode = new Html5Qrcode(qrcodeRegionId);
          qrCode.start(
            { facingMode: "environment" },
            { fps: 10, qrbox: {width: 200, height: 200}, aspectRatio: 1, disableFlip: true },
            (decodedText: string) => {
              qrCode.stop();
              addContact(decodedText);
            },
            () => {}
          );
        }
      })
      .catch(console.error);
  }, []);

  return (
    <Box id={qrcodeRegionId}>
      <Group justify="center">
        <Loader color="blue" size="xl" />
      </Group>
    </Box>
  );
}

export default function ScanContact({
  addContact,
  opened,
  close,
}: ScanContactProps) {
  const [url, setUrl] = useState<string>('');

  return (
    <Modal
      opened={opened}
      onClose={close}
      centered
      title={<strong>Add contact</strong>}
      overlayProps={{
        backgroundOpacity: 0.55,
        blur: 3,
      }}
    >
      <Text mb={4} size="sm">
        Scan a QR code:
      </Text>
      <Scanner addContact={addContact} />
      <form onSubmit={() => addContact(url)}>
        <Input.Wrapper mt="md" label="Or paste a URL:">
          <Input
            value={url}
            required
            data-autofocus
            onChange={(e) => setUrl(e.target.value)}
          />
        </Input.Wrapper>
        <Flex justify="flex-end" align="flex-end" mt="sm">
          <Button
            size="sm"
            variant="outline"
            type="submit"
            leftSection={<IconUserPlus size={16} />}
          >
            Add
          </Button>
        </Flex>
      </form>
    </Modal>
  );
}
