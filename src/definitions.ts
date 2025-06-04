import { PluginListenerHandle } from '@capacitor/core';

export interface CieNfcPluginPlugin {
  /**
   * Verifica se NFC è disponibile e attivo sul dispositivo
   */
  isNfcAvailable(): Promise<{ available: boolean }>;

  /**
   * Abilita NFC se disabilitato (reindirizza alle impostazioni)
   */
  enableNfc(): Promise<void>;

  /**
   * Legge i dati dalla CIE tramite NFC con autenticazione CAN
   */
  readCie(options: ReadCieOptions): Promise<CieReadResult>;

  /**
   * Avvia una sessione NFC per la lettura
   */
  startNfcSession(): Promise<void>;

  /**
   * Ferma la sessione NFC attiva
   */
  stopNfcSession(): Promise<void>;

  /**
   * Aggiunge un listener per eventi NFC
   */
  addListener(
    eventName: 'nfcTagDetected' | 'nfcProgress' | 'nfcError',
    listenerFunc: (event: NfcEvent) => void,
  ): Promise<PluginListenerHandle> & PluginListenerHandle;

  /**
   * Rimuove tutti i listener
   */
  removeAllListeners(): Promise<void>;
}

export interface ReadCieOptions {
  /**
   * CAN (Card Access Number) - 6 o 8 cifre stampate sulla CIE
   * (6 cifre per CIE versioni precedenti, 8 cifre per CIE 3.0)
   */
  can: string;

  /**
   * Se leggere la fotografia (richiede CAN valido)
   * @default false
   */
  readPhoto?: boolean;

  /**
   * Se leggere l'indirizzo di residenza (richiede CAN valido)
   * @default false
   */
  readAddress?: boolean;

  /**
   * Timeout in millisecondi per la lettura
   * @default 30000
   */
  timeout?: number;

  /**
   * Se validare i checksum dei dati letti
   * @default true
   */
  validateChecksum?: boolean;
}

export interface CieReadResult {
  /**
   * Indica se la lettura è avvenuta con successo
   */
  success: boolean;

  /**
   * Dati della CIE (solo se success = true)
   */
  data?: CieData;

  /**
   * Messaggio di errore (solo se success = false)
   */
  error?: string;

  /**
   * Codice di errore specifico
   */
  errorCode?: string;

  /**
   * Tempo impiegato per la lettura in millisecondi
   */
  readingTime?: number;
}

export interface CieData {
  // Dati anagrafici base
  nome: string;
  cognome: string;
  codiceFiscale: string;
  dataNascita: string; // YYYY-MM-DD
  luogoNascita: string;
  sesso: 'M' | 'F';

  // Dati documento
  numeroDocumento: string;
  dataRilascio: string; // YYYY-MM-DD
  dataScadenza: string; // YYYY-MM-DD
  comuneRilascio: string;
  
  // Dati opzionali (se autorizzati con CAN)
  fotografia?: string; // Base64 encoded JPEG
  indirizzoResidenza?: {
    via: string;
    civico: string;
    cap: string;
    comune: string;
    provincia: string;
  };

  // Metadati lettura
  accessLevel: 'basic' | 'advanced';
  readTimestamp: number;
  nfcSessionId: string;
  
  // Dati tecnici
  chipSerialNumber?: string;
  documentVersion?: string;
  issuerCountry: string;
}

export interface NfcEvent {
  /**
   * Tipo di evento
   */
  type: 'tagDetected' | 'progress' | 'error';

  /**
   * Messaggio descrittivo
   */
  message: string;

  /**
   * Dati aggiuntivi dell'evento
   */
  data?: any;

  /**
   * Timestamp dell'evento
   */
  timestamp: number;
}

export interface NfcTagDetectedEvent extends NfcEvent {
  type: 'tagDetected';
  data: {
    tagId: string;
    tagType: string;
    isoCie: boolean;
  };
}

export interface NfcProgressEvent extends NfcEvent {
  type: 'progress';
  data: {
    step: string;
    progress: number; // 0-100
  };
}

export interface NfcErrorEvent extends NfcEvent {
  type: 'error';
  data: {
    errorCode: string;
    errorMessage: string;
  };
}

