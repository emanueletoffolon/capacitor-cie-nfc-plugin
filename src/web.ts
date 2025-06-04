import { WebPlugin, PluginListenerHandle } from '@capacitor/core';

import type {
  CieNfcPluginPlugin,
  ReadCieOptions,
  CieReadResult,
  NfcEvent
} from './definitions';


export class CieNfcPluginWeb extends WebPlugin implements CieNfcPluginPlugin {

  async isNfcAvailable(): Promise<{ available: boolean }> {
    // NFC non supportato su web
    return { available: false };
  }

  async enableNfc(): Promise<void> {
    throw new Error('NFC non supportato su piattaforma web');
  }

  async readCie(options: ReadCieOptions): Promise<CieReadResult> {
    console.log('readCie chiamato con opzioni:', options);

    // Simulazione per testing su web
    return {
      success: false,
      error: 'NFC non supportato su piattaforma web',
      errorCode: 'WEB_NOT_SUPPORTED'
    };
  }

  async startNfcSession(): Promise<void> {
    throw new Error('NFC non supportato su piattaforma web');
  }

  async stopNfcSession(): Promise<void> {
    throw new Error('NFC non supportato su piattaforma web');
  }

  // @ts-ignore
  async addListener(
    eventName: 'nfcTagDetected' | 'nfcProgress' | 'nfcError',
    listenerFunc: (event: NfcEvent) => void,
  ): Promise<PluginListenerHandle> {
    return super.addListener(eventName, listenerFunc);
  }


  async removeAllListeners(): Promise<void> {
    super.removeAllListeners();
  }
}

