import { registerPlugin } from '@capacitor/core';

import type { CieNfcPluginPlugin } from './definitions';

const CieNfcPlugin = registerPlugin<CieNfcPluginPlugin>('CieNfcPlugin', {
  web: () => import('./web').then(m => new m.CieNfcPluginWeb()),
});

export * from './definitions';
export { CieNfcPlugin };

