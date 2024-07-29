import React, { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';

if (process.env.NODE_ENV !== 'production') {
  (async () => {
    const ReactDOM = await import('react-dom');
    const axe = await import('@axe-core/react');
    axe.default(React, ReactDOM);
  })();
}

const container = document.getElementById('root');
const root = createRoot(container);
root.render(
  <StrictMode>
    <App />
  </StrictMode>,
);
