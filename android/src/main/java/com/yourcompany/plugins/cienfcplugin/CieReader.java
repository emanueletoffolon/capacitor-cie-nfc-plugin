package com.yourcompany.plugins.cienfcplugin;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.AsyncTask;
import android.util.Log;

import java.util.UUID;

/**
 * Lettore principale per CIE con supporto NFC
 */
public class CieReader {

    private static final String TAG = "CieReader";

    private final Activity activity;
    private final CieNfcPluginPlugin plugin;
    private NfcAdapter nfcAdapter;
    private PendingIntent pendingIntent;
    private IntentFilter[] intentFilters;
    private String[][] techLists;

    // Stato della sessione
    private boolean sessionActive = false;
    private String currentSessionId;
    private CieReadCallback currentCallback;

    // Parametri di lettura correnti
    private String currentCan;
    private MrzData currentMrz;
    private boolean readPhoto;
    private boolean readAddress;
    private int timeout;
    private boolean validateChecksum;

    /**
     * Interfaccia callback per eventi di lettura
     */
    public interface CieReadCallback {
        void onSuccess(CieData data);
        void onError(String error, String errorCode);
        void onProgress(String step, int progress);
        void onTagDetected(String tagId, String tagType);
    }

    public CieReader(Activity activity, CieNfcPluginPlugin plugin) {
        this.activity = activity;
        this.plugin = plugin;
        this.nfcAdapter = plugin.getNfcAdapter();
        initializeNfc();
    }

    /**
     * Inizializza i componenti NFC
     */
    private void initializeNfc() {
        if (nfcAdapter == null) {
            Log.w(TAG, "NFC non disponibile su questo dispositivo");
            return;
        }

        // Configura PendingIntent per catturare i tag NFC
        Intent intent = new Intent(activity, activity.getClass());
        intent.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
        pendingIntent = PendingIntent.getActivity(activity, 0, intent,
            PendingIntent.FLAG_MUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);

        // Configura filtri per ISO14443-4 (tecnologia usata dalle CIE)
        IntentFilter isoDepFilter = new IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED);
        intentFilters = new IntentFilter[] { isoDepFilter };

        techLists = new String[][] {
            new String[] { IsoDep.class.getName() }
        };

        Log.d(TAG, "NFC inizializzato correttamente");
    }

    /**
     * Avvia una sessione NFC
     */
    public void startNfcSession() {
        if (nfcAdapter == null) {
            throw new RuntimeException("NFC non disponibile");
        }

        if (!nfcAdapter.isEnabled()) {
            throw new RuntimeException("NFC non abilitato");
        }

        sessionActive = true;
        currentSessionId = UUID.randomUUID().toString();

        // Abilita il foreground dispatch
        nfcAdapter.enableForegroundDispatch(activity, pendingIntent, intentFilters, techLists);

        Log.d(TAG, "Sessione NFC avviata: " + currentSessionId);
    }

    /**
     * Ferma la sessione NFC
     */
    public void stopNfcSession() {
        if (nfcAdapter != null && sessionActive) {
            nfcAdapter.disableForegroundDispatch(activity);
            sessionActive = false;
            currentSessionId = null;
            Log.d(TAG, "Sessione NFC fermata");
        }
    }

    /**
     * Legge la CIE usando autenticazione CAN
     */
    public void readCieWithCan(String can, boolean readPhoto, boolean readAddress,
                              int timeout, boolean validateChecksum, CieReadCallback callback) {

        Log.d(TAG, "Avvio lettura CIE con CAN");

        // Memorizza i parametri per l'uso durante la lettura
        this.currentCan = can;
        this.currentMrz = null;
        this.readPhoto = readPhoto;
        this.readAddress = readAddress;
        this.timeout = timeout;
        this.validateChecksum = validateChecksum;
        this.currentCallback = callback;

        // Avvia la sessione NFC se non è già attiva
        if (!sessionActive) {
            startNfcSession();
        }

        callback.onProgress("In attesa di CIE...", 10);
    }

    /**
     * Legge la CIE usando autenticazione MRZ/BAC
     */
    public void readCieWithMrz(MrzData mrzData, boolean readPhoto, boolean readAddress,
                              int timeout, boolean validateChecksum, CieReadCallback callback) {

        Log.d(TAG, "Avvio lettura CIE con MRZ");

        // Memorizza i parametri per l'uso durante la lettura
        this.currentCan = null;
        this.currentMrz = mrzData;
        this.readPhoto = readPhoto;
        this.readAddress = readAddress;
        this.timeout = timeout;
        this.validateChecksum = validateChecksum;
        this.currentCallback = callback;

        // Avvia la sessione NFC se non è già attiva
        if (!sessionActive) {
            startNfcSession();
        }

        callback.onProgress("In attesa di CIE...", 10);
    }

    /**
     * Gestisce un nuovo Intent NFC (chiamato dall'Activity)
     */
public void handleNfcIntent(Intent intent) {
    Log.d(TAG, "=== handleNfcIntent chiamato ===");
    Log.d(TAG, "  - sessionActive: " + sessionActive);
    Log.d(TAG, "  - currentCallback: " + (currentCallback != null ? "presente" : "null"));
    Log.d(TAG, "  - currentSessionId: " + currentSessionId);

    if (!sessionActive || currentCallback == null) {
        Log.w(TAG, "Intent NFC ricevuto ma sessione non attiva o callback mancante");
        Log.w(TAG, "  - sessionActive: " + sessionActive);
        Log.w(TAG, "  - currentCallback: " + (currentCallback != null));
        return;
    }

    String action = intent.getAction();
    Log.d(TAG, "Action intent: " + action);

    if (!NfcAdapter.ACTION_TECH_DISCOVERED.equals(action)) {
        Log.w(TAG, "Action NFC non supportata: " + action);
        return;
    }

    Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
    if (tag == null) {
        Log.e(TAG, "Nessun tag NFC trovato nell'intent");
        currentCallback.onError("Tag NFC non valido", "INVALID_TAG");
        return;
    }

    String tagId = bytesToHex(tag.getId());
    Log.d(TAG, "Tag NFC rilevato: " + tagId);

    // Notifica rilevamento tag
    Log.d(TAG, "Notifica rilevamento tag al callback");
    currentCallback.onTagDetected(tagId, "IsoDep");

    // Verifica che sia un tag ISO14443-4
    IsoDep isoDep = IsoDep.get(tag);
    if (isoDep == null) {
        Log.e(TAG, "Tag non è ISO14443-4 compatibile");
        currentCallback.onError("CIE non compatibile", "INCOMPATIBLE_TAG");
        return;
    }

    Log.d(TAG, "Tag ISO14443-4 valido, avvio task di lettura");
    // Avvia la lettura in background
    new CieReadTask().execute(isoDep);
}


    /**
     * Task asincrono per la lettura della CIE
     */
    private class CieReadTask extends AsyncTask<IsoDep, Void, CieReadResult> {

        @Override
        protected CieReadResult doInBackground(IsoDep... params) {
            IsoDep isoDep = params[0];
            long startTime = System.currentTimeMillis();

            try {
                Log.d(TAG, "Connessione al tag ISO14443-4");
                currentCallback.onProgress("Connessione alla CIE...", 20);

                isoDep.connect();
                isoDep.setTimeout(timeout);

                Log.d(TAG, "Connesso. Max transceive length: " + isoDep.getMaxTransceiveLength());

                // Sceglie il metodo di autenticazione
                boolean authSuccess = false;
                if (currentCan != null) {
                    // Autenticazione con CAN/PACE
                    currentCallback.onProgress("Autenticazione CAN...", 30);
                    PaceAuthenticator paceAuth = new PaceAuthenticator();
                    authSuccess = paceAuth.authenticateWithCan(isoDep, currentCan, currentCallback);
                } else if (currentMrz != null) {
                      // Autenticazione con MRZ/BAC - Tentativo automatico M/F
                      currentCallback.onProgress("Autenticazione BAC (tentativo M/F)...", 30);
                      BacAuthenticator bacAuth = new BacAuthenticator();
                      authSuccess = bacAuth.authenticateWithMrz(isoDep, currentMrz, currentCallback);
                  }


                if (!authSuccess) {
                    return new CieReadResult(false, "Autenticazione fallita", "AUTH_FAILED");
                }

                currentCallback.onProgress("Lettura dati base...", 60);

                // Legge i dati base della CIE
                CieDataReader dataReader = new CieDataReader();
                CieData cieData = dataReader.readBasicData(isoDep, currentCallback);

                if (cieData == null) {
                    return new CieReadResult(false, "Impossibile leggere dati CIE", "READ_FAILED");
                }

                // Imposta metodo di autenticazione
                cieData.setAuthMethod(currentCan != null ? "CAN" : "BAC");
                cieData.setNfcSessionId(currentSessionId);

                // Legge dati opzionali se richiesti
                if (readPhoto) {
                    currentCallback.onProgress("Lettura fotografia...", 80);
                    String photo = dataReader.readPhoto(isoDep);
                    cieData.setFotografia(photo);
                }

                if (readAddress) {
                    currentCallback.onProgress("Lettura indirizzo...", 90);
                    CieData.IndirizzoResidenza address = dataReader.readAddress(isoDep);
                    cieData.setIndirizzoResidenza(address);
                }

                // Calcola tempo di lettura
                long readingTime = System.currentTimeMillis() - startTime;
                cieData.setReadingTime(readingTime);

                currentCallback.onProgress("Lettura completata", 100);

                return new CieReadResult(true, cieData);

            } catch (Exception e) {
                Log.e(TAG, "Errore durante lettura CIE", e);
                return new CieReadResult(false, "Errore lettura: " + e.getMessage(), "READ_ERROR");
            } finally {
                try {
                    if (isoDep.isConnected()) {
                        isoDep.close();
                    }
                } catch (Exception e) {
                    Log.e(TAG, "Errore chiusura connessione", e);
                }
            }
        }

        @Override
        protected void onPostExecute(CieReadResult result) {
            if (currentCallback != null) {
                if (result.isSuccess()) {
                    currentCallback.onSuccess(result.getData());
                } else {
                    currentCallback.onError(result.getError(), result.getErrorCode());
                }
            }

            // Pulisce lo stato
            currentCallback = null;
            stopNfcSession();
        }
    }

    /**
     * Converte array di byte in stringa esadecimale
     */
    private String bytesToHex(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02X", b));
        }
        return result.toString();
    }

    /**
     * Classe per il risultato della lettura
     */
    private static class CieReadResult {
        private final boolean success;
        private final CieData data;
        private final String error;
        private final String errorCode;

        public CieReadResult(boolean success, CieData data) {
            this.success = success;
            this.data = data;
            this.error = null;
            this.errorCode = null;
        }

        public CieReadResult(boolean success, String error, String errorCode) {
            this.success = success;
            this.data = null;
            this.error = error;
            this.errorCode = errorCode;
        }

        public boolean isSuccess() { return success; }
        public CieData getData() { return data; }
        public String getError() { return error; }
        public String getErrorCode() { return errorCode; }
    }
}