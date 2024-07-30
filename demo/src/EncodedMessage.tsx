import { useEffect, useState } from 'react';
import { message_parts } from '../pkg/tsp_demo';
import { base64ToBuffer, bufferToBase64 } from './util';
import { Box } from '@mantine/core';

interface EncodedMessageProps {
  plain: string;
  encoded:
    | string
    | {
        name: string;
        href: string;
        size: string;
      };
}

// render a TSP message with debug information
function EncodedMessageParts({ message }: { message: any }) {
  const parts = [
    'prefix',
    'sender',
    'receiver',
    'nonconfidentialData',
    'ciphertext',
    'signature',
  ];
  const colors = [
    '#800000',
    '#911eb4',
    '#000075',
    '#3cb44b',
    '#9A6324',
    '#469990',
  ];

  return (
    <code style={{ wordWrap: 'break-word', wordBreak: 'break-all' }}>
      {parts
        .map((part, index) => [part, message[part], index])
        .filter(([_part, messagePart, _index]) => messagePart)
        .map(([part, messagePart, index]) => (
          <span
            key={part}
            className="message-part"
            style={{ color: colors[index] }}
          >
            {bufferToBase64(messagePart.data)}
          </span>
        ))}
    </code>
  );
}

export default function EncodedMessage({ encoded }: EncodedMessageProps) {
  const [parts, setParts] = useState<null | any>(null);

  useEffect(() => {
    const getParts = async () => {
      if (typeof encoded === 'string') {
        const data = base64ToBuffer(encoded);
        setParts(JSON.parse(message_parts(data)));
      }
    };
    getParts();
  }, [encoded]);

  if (typeof encoded === 'object') {
    return <code>{encoded.size}</code>;
  }

  if (parts) {
    return (
      <>
        <Box c="dimmed">CECR encoded message</Box>
        <EncodedMessageParts message={parts} />
      </>
    );
  }

  return (
    <code style={{ wordWrap: 'break-word', wordBreak: 'break-all' }}>
      {encoded}
    </code>
  );
}
