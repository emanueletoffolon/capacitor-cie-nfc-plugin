# Capacitor CIE NFC Plugin

Plugin Capacitor per la lettura di Carte di Identità Elettroniche italiane tramite NFC con autenticazione CAN.

## Caratteristiche

- ✅ Lettura NFC completa delle CIE italiane
- ✅ Autenticazione PACE con CAN
- ✅ Estrazione dati anagrafici e documento
- ✅ Supporto fotografia e indirizzo (se autorizzati)
- ✅ Validazione checksum e integrità dati
- ✅ Gestione errori completa
- ✅ Interfaccia TypeScript type-safe

## Installazione

```bash
npm install capacitor-cie-nfc-plugin
npx cap sync
```

## Configurazione Android

Aggiungi i permessi in `android/app/src/main/AndroidManifest.xml`:

```xml
<uses-permission android:name="android.permission.NFC" />
<uses-feature android:name="android.hardware.nfc" android:required="true" />
```

## Utilizzo

```typescript
import { CieNfcPlugin } from 'capacitor-cie-nfc-plugin';

// Verifica disponibilità NFC
const { available } = await CieNfcPlugin.isNfcAvailable();

// Lettura CIE con CAN
const result = await CieNfcPlugin.readCie({
  can: '12345678',
  readPhoto: true,
  readAddress: true,
  timeout: 30000
});

if (result.success) {
  console.log('Dati CIE:', result.data);
} else {
  console.error('Errore:', result.error);
}
```

## API

### Metodi

#### `isNfcAvailable()`
Verifica se NFC è disponibile e attivo.

#### `readCie(options: ReadCieOptions)`
Legge i dati dalla CIE tramite NFC.

#### `startNfcSession()`
Avvia una sessione NFC.

#### `stopNfcSession()`
Ferma la sessione NFC attiva.

### Eventi

#### `nfcTagDetected`
Emesso quando viene rilevata una CIE.

#### `nfcProgress`
Emesso durante il processo di lettura.

#### `nfcError`
Emesso in caso di errori NFC.

## Licenza

MIT

