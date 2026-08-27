// Ensure fetch on window is configurable with a setter in all environments
try {
  let _fetch = window.fetch;
  Object.defineProperty(window, 'fetch', {
    get() {
      return _fetch;
    },
    set(newFetch) {
      _fetch = newFetch;
    },
    configurable: true,
    enumerable: true,
  });
} catch {
  // Ignore descriptor errors
}

import {StrictMode} from 'react';
import {createRoot} from 'react-dom/client';
import App from './App.tsx';
import './index.css';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
