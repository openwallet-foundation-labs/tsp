import useStore from './useStore';

function App() {
  const { id, other, store } = useStore();

  if (id !== null && other !== null) {
    const body = new Uint8Array([1, 2, 3, 4, 5]);
    const message = store.seal_message(id.identifier(), other.identifier(), undefined, body);
    console.log(message);
  }

  return (
    <>
      <h1>TSP Demo</h1>
      <pre></pre>
    </>
  )
}

export default App
