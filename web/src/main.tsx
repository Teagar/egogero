import '@fontsource/big-shoulders-display/latin-800';
import '@fontsource/public-sans/latin-400';
import '@fontsource/public-sans/latin-700';
import '@fontsource/ibm-plex-mono/latin-500';
import '@fontsource/ibm-plex-mono/latin-600';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import { App } from './App';
import './styles.css';

createRoot(document.getElementById('root')!).render(<StrictMode><App /></StrictMode>);
