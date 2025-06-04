"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CieNfcPluginWeb = void 0;
const core_1 = require("@capacitor/core");
class CieNfcPluginWeb extends core_1.WebPlugin {
    async isNfcAvailable() {
        // NFC non supportato su web
        return { available: false };
    }
    async enableNfc() {
        throw new Error('NFC non supportato su piattaforma web');
    }
    async readCie(options) {
        console.log('readCie chiamato con opzioni:', options);
        // Simulazione per testing su web
        return {
            success: false,
            error: 'NFC non supportato su piattaforma web',
            errorCode: 'WEB_NOT_SUPPORTED'
        };
    }
    async startNfcSession() {
        throw new Error('NFC non supportato su piattaforma web');
    }
    async stopNfcSession() {
        throw new Error('NFC non supportato su piattaforma web');
    }
    // @ts-ignore
    async addListener(eventName, listenerFunc) {
        return super.addListener(eventName, listenerFunc);
    }
    async removeAllListeners() {
        super.removeAllListeners();
    }
}
exports.CieNfcPluginWeb = CieNfcPluginWeb;
