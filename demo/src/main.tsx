import ReactDOM from 'react-dom/client';
import App from './App.tsx';
import '@mantine/core/styles.css';
import './overrides.css';
import { MantineProvider } from '@mantine/core';

const root = document.getElementById('root');

ReactDOM.createRoot(root!).render(
  <MantineProvider>
    <App />
  </MantineProvider>
);
