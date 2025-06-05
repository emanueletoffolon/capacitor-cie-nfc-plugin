package com.yourcompany.plugins.cienfcplugin;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CieReader {
    
    private static final String TAG = "CieReader";
    
    // AID della CIE (Application Identifier)
    private static final byte[][] CIE_AIDS = {
            // AID principale CIE italiana
            {(byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x30, (byte) 0x80, (byte) 0x00},

            // AID CIE versioni precedenti
            {(byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x30, (byte) 0x80},

            // AID CIE alternativo 1
            {(byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x30, (byte) 0x80, (byte) 0x31},

            // AID standard italiano per eID
            {(byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x30, (byte) 0x80, (byte) 0x00, (byte) 0x00},

            // AID per CIE 3.0
            {(byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x30, (byte) 0x80, (byte) 0x00, (byte) 0x01},

            // AID generico per documenti italiani
            {(byte) 0xE8, (byte) 0x28, (byte) 0xBD, (byte) 0x08, (byte) 0x0F},

            // AID per ePassport generale (some CIE might use this)
            {(byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x02, (byte) 0x47, (byte) 0x10, (byte) 0x01}
    };



    
    // Comandi APDU
    private static final byte[] SELECT_CIE_APP = {
        (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x0C, (byte) 0x07,
        (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x30, (byte) 0x80, (byte) 0x00
    };

    
    private Context context;
    private CieNfcPluginPlugin plugin;
    private NfcAdapter nfcAdapter;
    private boolean sessionActive = false;
    private CountDownLatch tagLatch;
    private Tag currentTag;
    private String sessionId;
    
    public interface CieReadCallback {
        void onSuccess(CieData cieData);
        void onError(String error, String errorCode);
        void onProgress(String step, int progress);
        void onTagDetected(String tagId, String tagType, boolean isoCie);
    }
    
    public CieReader(Context context, CieNfcPluginPlugin plugin) {
        this.context = context;
        this.plugin = plugin;
        this.nfcAdapter = NfcAdapter.getDefaultAdapter(context);
        this.sessionId = UUID.randomUUID().toString();
        
        Log.d(TAG, "CieReader inizializzato");
    }

    private boolean verifyCieCard(IsoDep isoDep) {
        try {
            // Comando per ottenere informazioni sulla carta
            byte[] atrCommand = {(byte) 0x00, (byte) 0xCA, (byte) 0x01, (byte) 0x00, (byte) 0x00};

            byte[] response = isoDep.transceive(atrCommand);
            Log.d(TAG, "ATR Response: " + bytesToHex(response));

            // Verifica se la risposta contiene indicatori di CIE
            // (questo dipende dalle specifiche della CIE)
            return isSuccessResponse(response);

        } catch (Exception e) {
            Log.w(TAG, "Impossibile verificare tipo carta: " + e.getMessage());
            return true; // Procedi comunque
        }
    }

    
    public void readCie(String can, boolean readPhoto, boolean readAddress, 
                       int timeout, boolean validateChecksum, CieReadCallback callback) {
        
        long startTime = System.currentTimeMillis();
        
        try {
            callback.onProgress("Inizializzazione lettura...", 0);
            
            // Validazione CAN
            if (!isValidCan(can)) {
                callback.onError("CAN non valido. Deve essere di 8 cifre numeriche.", "INVALID_CAN");
                return;
            }
            
            callback.onProgress("Attesa CIE...", 10);
            
            // Attesa tag NFC
            Tag tag = waitForNfcTag(timeout);
            if (tag == null) {
                callback.onError("Timeout: CIE non rilevata entro " + (timeout/1000) + " secondi", "TIMEOUT");
                return;
            }
            
            String tagId = bytesToHex(tag.getId());
            callback.onTagDetected(tagId, "IsoDep", true);
            callback.onProgress("CIE rilevata, connessione...", 20);
            
            // Connessione ISO-DEP
            IsoDep isoDep = IsoDep.get(tag);
            if (isoDep == null) {
                callback.onError("Tipo di tag non supportato", "UNSUPPORTED_TAG");
                return;
            }
            
            isoDep.connect();
            isoDep.setTimeout(timeout);
            
            try {
                callback.onProgress("Diagnostica carta...", 25);

                // DIAGNOSTICA COMPLETA
                diagnoseCard(isoDep);

                callback.onProgress("Scansione applicazioni...", 30);

                // SCANSIONE APPLICAZIONI
                scanCardApplications(isoDep);

                callback.onProgress("Tentativo selezione CIE...", 35);

                // Prova selezione con il metodo originale
                try {
                    selectCieApplication(isoDep);
                } catch (Exception e) {
                    // Se fallisce, proviamo un approccio alternativo
                    Log.w(TAG, "Selezione standard fallita, provo approccio alternativo");
                    callback.onProgress("Tentativo approccio alternativo...", 37);

                    if (!tryAlternativeSelection(isoDep)) {
                        throw new CieException("Impossibile selezionare applicazione CIE con nessun metodo", "NO_CIE_APP");
                    }
                }
                /*
                // Continua con il resto della lettura...
                callback.onProgress("Autenticazione PACE...", 40);

                
                // Autenticazione PACE con CAN
                PaceAuthenticator paceAuth = new PaceAuthenticator();
                boolean authSuccess = paceAuth.authenticateWithCan(isoDep, can, callback);
                
                if (!authSuccess) {
                    callback.onError("Autenticazione PACE fallita. Verifica il CAN.", "AUTH_FAILED");
                    return;
                }
                */

                // Inizializzazione
                CieNisReader nisReader = new CieNisReader(isoDep, can);

                // Lettura e verifica NIS
                CieNisReader.CieNisResult result = nisReader.readAndVerifyNis();

                // Controllo risultato
                if (result.success) {
                    System.out.println("NIS: " + result.nisNumber);
                    System.out.println("Originale: " + result.isOriginal);
                } else {
                    System.out.println("Errore: " + result.message);
                }

                callback.onProgress("Lettura dati anagrafici...", 60);
                
                // Lettura dati base
                CieData cieData = readBasicData(isoDep, validateChecksum);
                cieData.setAccessLevel(readPhoto || readAddress ? "advanced" : "basic");
                cieData.setReadTimestamp(System.currentTimeMillis());
                cieData.setNfcSessionId(sessionId);
                cieData.setReadingTime(System.currentTimeMillis() - startTime);
                
                // Lettura dati avanzati se richiesti
                if (readPhoto || readAddress) {
                    callback.onProgress("Lettura dati avanzati...", 80);
                    readAdvancedData(isoDep, cieData, readPhoto, readAddress, callback);
                }
                
                callback.onProgress("Completamento lettura...", 100);
                callback.onSuccess(cieData);
                
            } finally {
                try {
                    isoDep.close();
                } catch (IOException e) {
                    Log.w(TAG, "Errore chiusura connessione IsoDep", e);
                }
            }
            
        } catch (Exception e) {
            Log.e(TAG, "Errore durante lettura CIE", e);
            callback.onError("Errore durante lettura: " + e.getMessage(), "READ_ERROR");
        }
    }

    private boolean tryAlternativeSelection(IsoDep isoDep) {
        Log.d(TAG, "=== TENTATIVO SELEZIONE ALTERNATIVA ===");

        try {
            // Metodo 1: Select by File ID (se è un'applicazione con ID fisso)
            byte[] selectByFID = {(byte) 0x00, (byte) 0xA4, (byte) 0x02, (byte) 0x0C, (byte) 0x02, (byte) 0x01, (byte) 0x00};
            byte[] response = isoDep.transceive(selectByFID);

            if (isSuccessResponse(response)) {
                Log.d(TAG, "✅ Selezione alternativa riuscita con File ID");
                return true;
            }

        } catch (Exception e) {
            Log.d(TAG, "Selezione alternativa fallita: " + e.getMessage());
        }

        return false;
    }





    private boolean isValidCan(String can) {
        if (can == null) {
            return false;
        }
        
        // Supporta CAN a 6 o 8 cifre (diverse versioni CIE)
        int length = can.length();
        if (length != 6 && length != 8) {
            return false;
        }
        
        try {
            Long.parseLong(can);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private Tag waitForNfcTag(int timeout) throws InterruptedException {
        tagLatch = new CountDownLatch(1);
        currentTag = null;

        Log.d(TAG, "Avvio attesa tag NFC con timeout: " + timeout + "ms");

        // Verifica stato NFC
        if (nfcAdapter == null) {
            Log.e(TAG, "NfcAdapter è null!");
            return null;
        }

        if (!nfcAdapter.isEnabled()) {
            Log.e(TAG, "NFC non è abilitato!");
            return null;
        }

        Log.d(TAG, "NFC è disponibile e abilitato");

        // Abilita foreground dispatch
        enableForegroundDispatch();

        try {
            Log.d(TAG, "Inizio attesa per il tag NFC...");
            boolean tagReceived = tagLatch.await(timeout, TimeUnit.MILLISECONDS);

            if (tagReceived) {
                Log.d(TAG, "Tag ricevuto con successo!");
                return currentTag;
            } else {
                Log.w(TAG, "Timeout durante l'attesa del tag NFC.");
                return null;
            }
        } finally {
            disableForegroundDispatch();
        }
    }

    
    private void enableForegroundDispatch() {
        if (nfcAdapter != null && context instanceof Activity) {
            Activity activity = (Activity) context;

            // IMPLEMENTAZIONE CORRETTA NECESSARIA
            IntentFilter[] intentFilters = new IntentFilter[]{};
            String[][] techLists = new String[][]{
                new String[]{IsoDep.class.getName()}
            };

            Intent intent = new Intent(activity, activity.getClass())
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
            PendingIntent pendingIntent = PendingIntent.getActivity(
                activity, 0, intent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_MUTABLE
            );

            nfcAdapter.enableForegroundDispatch(activity, pendingIntent, intentFilters, techLists);
            Log.d(TAG, "Foreground dispatch abilitato correttamente");
        }
    }

    
    private void disableForegroundDispatch() {
        if (nfcAdapter != null && context instanceof Activity) {
            Activity activity = (Activity) context;
            nfcAdapter.disableForegroundDispatch(activity);
            Log.d(TAG, "Foreground dispatch disabilitato");
        }
    }

    
    // Metodo chiamato quando viene rilevato un tag NFC
    public void onTagDetected(Tag tag) {
        currentTag = tag;
        if (tagLatch != null) {
            tagLatch.countDown();
        }
    }

    private void scanCardApplications(IsoDep isoDep) throws IOException {
        Log.d(TAG, "=== SCANSIONE APPLICAZIONI CARTA ===");

        // Prova tutti gli AID conosciuti per vedere cosa risponde
        for (int i = 0; i < CIE_AIDS.length; i++) {
            byte[] aid = CIE_AIDS[i];

            byte[] selectCommand = new byte[5 + aid.length];
            selectCommand[0] = (byte) 0x00; // CLA
            selectCommand[1] = (byte) 0xA4; // INS SELECT
            selectCommand[2] = (byte) 0x04; // P1 - Select by DF name
            selectCommand[3] = (byte) 0x0C; // P2 - Return FCI template
            selectCommand[4] = (byte) aid.length; // Lc
            System.arraycopy(aid, 0, selectCommand, 5, aid.length);

            try {
                Log.d(TAG, "Test AID " + (i + 1) + "/" + CIE_AIDS.length + ": " + bytesToHex(aid));

                byte[] response = isoDep.transceive(selectCommand);

                int sw1 = response[response.length - 2] & 0xFF;
                int sw2 = response[response.length - 1] & 0xFF;
                int statusWord = (sw1 << 8) | sw2;

                Log.d(TAG, "Risposta AID " + (i + 1) + ": " + bytesToHex(response));
                Log.d(TAG, "Status: " + String.format("0x%04X", statusWord));

                if (statusWord == 0x9000) {
                    Log.d(TAG, "✅ AID " + (i + 1) + " ACCETTATO!");
                    return; // Successo!
                } else if (sw1 == 0x61) {
                    Log.d(TAG, "⚠️ AID " + (i + 1) + " accettato con dati aggiuntivi");
                    return; // Anche questo è un successo
                } else {
                    Log.d(TAG, "❌ AID " + (i + 1) + " rifiutato");
                }

            } catch (Exception e) {
                Log.w(TAG, "Errore AID " + (i + 1) + ": " + e.getMessage());
            }
        }

        Log.e(TAG, "=== NESSUN AID ACCETTATO ===");
    }


    private void diagnoseCard(IsoDep isoDep) {
        try {
            Log.d(TAG, "=== DIAGNOSTICA CARTA NFC ===");

            // Informazioni di base
            Log.d(TAG, "Timeout: " + isoDep.getTimeout() + "ms");
            Log.d(TAG, "Max Transceive: " + isoDep.getMaxTransceiveLength() + " bytes");
            Log.d(TAG, "Extended Length: " + isoDep.isExtendedLengthApduSupported());

            // Test comando di base - Get Response
            try {
                byte[] getResponse = {(byte) 0x00, (byte) 0xC0, (byte) 0x00, (byte) 0x00, (byte) 0x00};
                byte[] response = isoDep.transceive(getResponse);
                Log.d(TAG, "Get Response: " + bytesToHex(response));
            } catch (Exception e) {
                Log.d(TAG, "Get Response non supportato: " + e.getMessage());
            }

            // Test comando ATR/Historical bytes se disponibile
            try {
                byte[] getATR = {(byte) 0x00, (byte) 0xCA, (byte) 0x01, (byte) 0x00, (byte) 0x00};
                byte[] response = isoDep.transceive(getATR);
                Log.d(TAG, "ATR: " + bytesToHex(response));
            } catch (Exception e) {
                Log.d(TAG, "ATR non disponibile: " + e.getMessage());
            }

            // Prova SELECT MF (Master File)
            try {
                byte[] selectMF = {(byte) 0x00, (byte) 0xA4, (byte) 0x00, (byte) 0x0C, (byte) 0x02, (byte) 0x3F, (byte) 0x00};
                byte[] response = isoDep.transceive(selectMF);
                Log.d(TAG, "SELECT MF: " + bytesToHex(response));
            } catch (Exception e) {
                Log.d(TAG, "SELECT MF fallito: " + e.getMessage());
            }

            Log.d(TAG, "=== FINE DIAGNOSTICA ===");

        } catch (Exception e) {
            Log.e(TAG, "Errore durante diagnostica", e);
        }
    }


    private void selectCieApplication(IsoDep isoDep) throws IOException, CieException {
        Log.d(TAG, "Tentativo selezione applicazione CIE con multipli AID...");

        for (int i = 0; i < CIE_AIDS.length; i++) {
            byte[] aid = CIE_AIDS[i];

            byte[] selectCommand = new byte[5 + aid.length];
            selectCommand[0] = (byte) 0x00; // CLA
            selectCommand[1] = (byte) 0xA4; // INS SELECT
            selectCommand[2] = (byte) 0x04; // P1 - Select by DF name
            selectCommand[3] = (byte) 0x0C; // P2 - Return FCI template
            selectCommand[4] = (byte) aid.length; // Lc
            System.arraycopy(aid, 0, selectCommand, 5, aid.length);

            Log.d(TAG, "Provo AID " + (i + 1) + ": " + bytesToHex(aid));

            try {
                byte[] response = isoDep.transceive(selectCommand);
                Log.d(TAG, "Risposta SELECT AID " + (i + 1) + ": " + bytesToHex(response));

                if (isSuccessResponse(response)) {
                    Log.d(TAG, "Applicazione CIE selezionata con successo usando AID " + (i + 1));
                    return; // Successo!
                }

            } catch (Exception e) {
                Log.w(TAG, "Errore tentativo AID " + (i + 1) + ": " + e.getMessage());
            }
        }

        // Se arriviamo qui, nessun AID ha funzionato
        throw new CieException("Nessun AID CIE supportato dalla carta", "NO_COMPATIBLE_AID");
    }


    
    private CieData readBasicData(IsoDep isoDep, boolean validateChecksum) 
            throws IOException, CieException {
        
        CieData cieData = new CieData();
        
        // Lettura DG1 (dati anagrafici)
        byte[] dg1Data = readDataGroup(isoDep, 0x01);
        parseDG1(dg1Data, cieData, validateChecksum);
        
        // Lettura DG2 (dati documento)
        byte[] dg2Data = readDataGroup(isoDep, 0x02);
        parseDG2(dg2Data, cieData, validateChecksum);
        
        // Lettura DG15 (chiave pubblica)
        try {
            byte[] dg15Data = readDataGroup(isoDep, 0x0F);
            parseDG15(dg15Data, cieData);
        } catch (Exception e) {
            Log.w(TAG, "DG15 non disponibile o non leggibile", e);
        }
        
        return cieData;
    }
    
    private void readAdvancedData(IsoDep isoDep, CieData cieData, boolean readPhoto, 
                                 boolean readAddress, CieReadCallback callback) 
            throws IOException, CieException {
        
        if (readPhoto) {
            try {
                callback.onProgress("Lettura fotografia...", 85);
                byte[] dg2Data = readDataGroup(isoDep, 0x02);
                String photoBase64 = extractPhotoFromDG2(dg2Data);
                cieData.setFotografia(photoBase64);
            } catch (Exception e) {
                Log.w(TAG, "Errore lettura fotografia", e);
            }
        }
        
        if (readAddress) {
            try {
                callback.onProgress("Lettura indirizzo...", 90);
                byte[] dg11Data = readDataGroup(isoDep, 0x0B);
                CieData.IndirizzoResidenza indirizzo = parseAddressFromDG11(dg11Data);
                cieData.setIndirizzoResidenza(indirizzo);
            } catch (Exception e) {
                Log.w(TAG, "Errore lettura indirizzo", e);
            }
        }
    }
    
    private byte[] readDataGroup(IsoDep isoDep, int dgNumber) throws IOException, CieException {
        // Comando READ BINARY per Data Group specifico
        byte[] readCommand = {
            (byte) 0x00, (byte) 0xB0, (byte) (0x80 | dgNumber), (byte) 0x00, (byte) 0x00
        };
        
        byte[] response = isoDep.transceive(readCommand);
        
        if (!isSuccessResponse(response)) {
            throw new CieException("Lettura Data Group " + dgNumber + " fallita", "DG_READ_FAILED");
        }
        
        // Rimuovi status bytes (ultimi 2 byte)
        return Arrays.copyOf(response, response.length - 2);
    }
    
    private void parseDG1(byte[] data, CieData cieData, boolean validateChecksum) {
        // Parsing semplificato DG1 - in implementazione reale usare ASN.1 parser
        try {
            // Estrazione dati anagrafici da DG1
            // Questo è un esempio semplificato - la struttura reale è più complessa
            
            String dataString = new String(data, "UTF-8");
            
            // Parsing dei campi (implementazione semplificata)
            cieData.setNome(extractField(dataString, "NOME"));
            cieData.setCognome(extractField(dataString, "COGNOME"));
            cieData.setCodiceFiscale(extractField(dataString, "CF"));
            cieData.setDataNascita(extractField(dataString, "DATA_NASCITA"));
            cieData.setLuogoNascita(extractField(dataString, "LUOGO_NASCITA"));
            cieData.setSesso(extractField(dataString, "SESSO"));
            
        } catch (Exception e) {
            Log.e(TAG, "Errore parsing DG1", e);
        }
    }
    
    private void parseDG2(byte[] data, CieData cieData, boolean validateChecksum) {
        try {
            // Parsing DG2 per dati documento
            String dataString = new String(data, "UTF-8");
            
            cieData.setNumeroDocumento(extractField(dataString, "DOC_NUM"));
            cieData.setDataRilascio(extractField(dataString, "DATA_RILASCIO"));
            cieData.setDataScadenza(extractField(dataString, "DATA_SCADENZA"));
            cieData.setComuneRilascio(extractField(dataString, "COMUNE_RILASCIO"));
            cieData.setIssuerCountry("ITA");
            
        } catch (Exception e) {
            Log.e(TAG, "Errore parsing DG2", e);
        }
    }
    
    private void parseDG15(byte[] data, CieData cieData) {
        try {
            // Estrazione metadati chip
            cieData.setChipSerialNumber(bytesToHex(Arrays.copyOf(data, 8)));
            cieData.setDocumentVersion("3.0");
            
        } catch (Exception e) {
            Log.e(TAG, "Errore parsing DG15", e);
        }
    }
    
    private String extractPhotoFromDG2(byte[] data) {
        // Estrazione fotografia da DG2 (formato JPEG)
        // Implementazione semplificata
        try {
            // Cerca header JPEG (0xFFD8)
            for (int i = 0; i < data.length - 1; i++) {
                if (data[i] == (byte) 0xFF && data[i + 1] == (byte) 0xD8) {
                    // Trova fine JPEG (0xFFD9)
                    for (int j = i + 2; j < data.length - 1; j++) {
                        if (data[j] == (byte) 0xFF && data[j + 1] == (byte) 0xD9) {
                            byte[] jpegData = Arrays.copyOfRange(data, i, j + 2);
                            return android.util.Base64.encodeToString(jpegData, android.util.Base64.DEFAULT);
                        }
                    }
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Errore estrazione fotografia", e);
        }
        
        return null;
    }
    
    private CieData.IndirizzoResidenza parseAddressFromDG11(byte[] data) {
        try {
            String dataString = new String(data, "UTF-8");
            
            CieData.IndirizzoResidenza indirizzo = new CieData.IndirizzoResidenza();
            indirizzo.setVia(extractField(dataString, "VIA"));
            indirizzo.setCivico(extractField(dataString, "CIVICO"));
            indirizzo.setCap(extractField(dataString, "CAP"));
            indirizzo.setComune(extractField(dataString, "COMUNE"));
            indirizzo.setProvincia(extractField(dataString, "PROVINCIA"));
            
            return indirizzo;
            
        } catch (Exception e) {
            Log.e(TAG, "Errore parsing indirizzo", e);
            return null;
        }
    }
    
    private String extractField(String data, String fieldName) {
        // Implementazione semplificata per estrazione campi
        // In un'implementazione reale dovresti usare un parser ASN.1 appropriato
        return "CAMPO_" + fieldName; // Placeholder
    }
    
    private boolean isSuccessResponse(byte[] response) {
        return response.length >= 2 && 
               response[response.length - 2] == (byte) 0x90 && 
               response[response.length - 1] == (byte) 0x00;
    }
    

    public void startSession() {
        sessionActive = true;
        sessionId = UUID.randomUUID().toString();
        Log.d(TAG, "Sessione NFC avviata: " + sessionId);
    }
    
    public void stopSession() {
        sessionActive = false;
        if (tagLatch != null) {
            tagLatch.countDown();
        }
        Log.d(TAG, "Sessione NFC fermata");
    }
    
    public void cleanup() {
        stopSession();
        Log.d(TAG, "CieReader cleanup completato");
    }

    private String bytesToHex(byte[] bytes) {
        if (bytes == null) return "null";

        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString().trim();
    }
}

