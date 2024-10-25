import { Identity } from './useStore';
import { base58btc } from "multiformats/bases/base58";

export function bufferToBase64(buffer: Uint8Array): string {
  const base64url = btoa(String.fromCodePoint(...buffer));

  return base64url.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64ToBuffer(base64url: string): Uint8Array {
  const base64Encoded = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const padding =
    base64url.length % 4 === 0 ? '' : '='.repeat(4 - (base64url.length % 4));
  const base64WithPadding = base64Encoded + padding;

  const text = atob(base64WithPadding);
  const length = text.length;
  const bytes = new Uint8Array(length);

  for (let i = 0; i < length; i++) {
    bytes[i] = text.charCodeAt(i);
  }

  return bytes;
}

export function identityToUrl(id: Identity) {
  const params = new URLSearchParams();
  params.append('label', id.label);
  params.append('vid', id.vid.id);

  return `${window.location.href}#${params}`;
}

export function humanFileSize(size: number) {
  const i = size == 0 ? 0 : Math.floor(Math.log(size) / Math.log(1024));
  const unit = ['B', 'kB', 'MB', 'GB', 'TB'][i];
  const value = (size / Math.pow(1024, i)).toFixed(1);

  return `${value} ${unit}`;
}

export function decode58btc(input: string): string {
  const buffer = base58btc.decode(input);

  return bufferToBase64(buffer.slice(2));
}