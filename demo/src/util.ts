import { Identity } from './useStore';

export async function bufferToBase64(buffer: Uint8Array) {
  const base64url: string = await new Promise((r) => {
    const reader = new FileReader();
    reader.onload = () => r(reader.result as string);
    reader.readAsDataURL(new Blob([buffer]));
  });

  return base64url
    .slice(base64url.indexOf(',') + 1)
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

export function identityToUrl(id: Identity) {
  const params = new URLSearchParams();
  params.append('label', id.label);
  params.append('vid', id.vid.id);

  return `${window.location.href}#${params}`;
}
