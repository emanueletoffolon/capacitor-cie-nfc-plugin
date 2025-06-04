import { WebPlugin, PluginListenerHandle } from '@capacitor/core';
import type { CieNfcPluginPlugin, ReadCieOptions, CieReadResult, NfcEvent } from './definitions';
export declare class CieNfcPluginWeb extends WebPlugin implements CieNfcPluginPlugin {
    isNfcAvailable(): Promise<{
        available: boolean;
    }>;
    enableNfc(): Promise<void>;
    readCie(options: ReadCieOptions): Promise<CieReadResult>;
    startNfcSession(): Promise<void>;
    stopNfcSession(): Promise<void>;
    addListener(eventName: 'nfcTagDetected' | 'nfcProgress' | 'nfcError', listenerFunc: (event: NfcEvent) => void): Promise<PluginListenerHandle>;
    removeAllListeners(): Promise<void>;
}
//# sourceMappingURL=web.d.ts.map