import useStore from './useStore';

async function bufferToBase64(buffer: Uint8Array) {
  const base64url: string = await new Promise((r) => {
    const reader = new FileReader();
    reader.onload = () => r(reader.result as string);
    reader.readAsDataURL(new Blob([buffer]));
  });

  return base64url.slice(base64url.indexOf(',') + 1)
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function App() {
  const { id, other, store } = useStore();

  if (id !== null && other !== null) {
    const body = new Uint8Array([1, 2, 3, 4, 5]);
    const message = store.seal_message(id.identifier(), other.identifier(), undefined, body);
    console.log(message.url);
    bufferToBase64(message.bytes).then(console.log);
  }

  return (
    <>
      <h1>TSP Demo</h1>
      <pre></pre>
    </>
  )
}

export default App
