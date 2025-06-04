package com.yourcompany.plugins.cienfcplugin;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.NfcManager;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.provider.Settings;
import android.util.Log;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@CapacitorPlugin(name = "CieNfcPlugin")
public class CieNfcPluginPlugin extends Plugin {

    private static final String TAG = "CieNfcPlugin";
    
    private CieReader cieReader;
    private NfcAdapter nfcAdapter;
    private ExecutorService executorService;
    private boolean sessionActive = false;

    @Override
    public void load() {
        super.load();
        
        Context context = getContext();
        NfcManager nfcManager = (NfcManager) context.getSystemService(Context.NFC_SERVICE);
        
        if (nfcManager != null) {
            nfcAdapter = nfcManager.getDefaultAdapter();
        }
        
        cieReader = new CieReader(context, this);
        executorService = Executors.newSingleThreadExecutor();
        
        Log.d(TAG, "Plugin caricato con successo");
    }

    @PluginMethod
    public void isNfcAvailable(PluginCall call) {
        try {
            boolean available = nfcAdapter != null && nfcAdapter.isEnabled();
            
            JSObject result = new JSObject();
            result.put("available", available);
            
            Log.d(TAG, "NFC disponibile: " + available);
            call.resolve(result);
            
        } catch (Exception e) {
            Log.e(TAG, "Errore verifica NFC", e);
            call.reject("Errore durante verifica NFC: " + e.getMessage());
        }
    }

    @PluginMethod
    public void enableNfc(PluginCall call) {
        try {
            if (nfcAdapter == null) {
                call.reject("NFC non supportato su questo dispositivo");
                return;
            }

            if (!nfcAdapter.isEnabled()) {
                // Reindirizza alle impostazioni NFC
                Intent intent = new Intent(Settings.ACTION_NFC_SETTINGS);
                getActivity().startActivity(intent);
                call.reject("NFC disabilitato. Attiva NFC nelle impostazioni.");
            } else {
                call.resolve();
            }
            
        } catch (Exception e) {
            Log.e(TAG, "Errore abilitazione NFC", e);
            call.reject("Errore durante abilitazione NFC: " + e.getMessage());
        }
    }

    @PluginMethod
    public void readCie(PluginCall call) {
        try {
            String can = call.getInt("can").toString();
            boolean readPhoto = call.getBoolean("readPhoto", false);
            boolean readAddress = call.getBoolean("readAddress", false);
            int timeout = call.getInt("timeout", 30000);
            boolean validateChecksum = call.getBoolean("validateChecksum", true);

            if (can == null || (can.length() != 6 && can.length() != 8)) {
                call.reject("CAN deve essere di 6 o 8 cifre numeriche", "INVALID_CAN");
                return;
            }

            // Validazione formato numerico
            try {
                Long.parseLong(can);
            } catch (NumberFormatException e) {
                call.reject("CAN deve contenere solo cifre numeriche", "INVALID_CAN_FORMAT");
                return;
            }

            if (nfcAdapter == null || !nfcAdapter.isEnabled()) {
                call.reject("NFC non disponibile o disabilitato", "NFC_NOT_AVAILABLE");
                return;
            }

            // Log sicuro del CAN (maschera le cifre sensibili)
            String maskedCan = can.length() == 6 ? 
                can.substring(0, 2) + "****" : 
                can.substring(0, 4) + "****";
            Log.d(TAG, "Avvio lettura CIE con CAN: " + maskedCan);

            // Esegui lettura in background
            executorService.execute(() -> {
                cieReader.readCie(can, readPhoto, readAddress, timeout, validateChecksum, 
                    new CieReader.CieReadCallback() {
                        @Override
                        public void onSuccess(CieData cieData) {
                            JSObject result = new JSObject();
                            result.put("success", true);
                            result.put("data", cieDataToJSObject(cieData));
                            result.put("readingTime", cieData.getReadingTime());
                            
                            Log.d(TAG, "Lettura CIE completata con successo");
                            call.resolve(result);
                        }

                        @Override
                        public void onError(String error, String errorCode) {
                            JSObject result = new JSObject();
                            result.put("success", false);
                            result.put("error", error);
                            result.put("errorCode", errorCode);
                            
                            Log.e(TAG, "Errore lettura CIE: " + error + " (" + errorCode + ")");
                            call.resolve(result);
                        }

                        @Override
                        public void onProgress(String step, int progress) {
                            JSObject event = new JSObject();
                            event.put("type", "progress");
                            event.put("message", step);
                            
                            JSObject data = new JSObject();
                            data.put("step", step);
                            data.put("progress", progress);
                            event.put("data", data);
                            event.put("timestamp", System.currentTimeMillis());
                            
                            notifyListeners("nfcProgress", event);
                        }

                        @Override
                        public void onTagDetected(String tagId, String tagType, boolean isoCie) {
                            JSObject event = new JSObject();
                            event.put("type", "tagDetected");
                            event.put("message", "CIE rilevata");
                            
                            JSObject data = new JSObject();
                            data.put("tagId", tagId);
                            data.put("tagType", tagType);
                            data.put("isoCie", isoCie);
                            event.put("data", data);
                            event.put("timestamp", System.currentTimeMillis());
                            
                            notifyListeners("nfcTagDetected", event);
                        }
                    });
            });

        } catch (Exception e) {
            Log.e(TAG, "Errore durante readCie", e);
            call.reject("Errore durante lettura CIE: " + e.getMessage());
        }
    }

    @PluginMethod
    public void startNfcSession(PluginCall call) {
        try {
            sessionActive = true;
            cieReader.startSession();
            
            Log.d(TAG, "Sessione NFC avviata");
            call.resolve();
            
        } catch (Exception e) {
            Log.e(TAG, "Errore avvio sessione NFC", e);
            call.reject("Errore durante avvio sessione NFC: " + e.getMessage());
        }
    }

    @PluginMethod
    public void stopNfcSession(PluginCall call) {
        try {
            sessionActive = false;
            cieReader.stopSession();
            
            Log.d(TAG, "Sessione NFC fermata");
            call.resolve();
            
        } catch (Exception e) {
            Log.e(TAG, "Errore stop sessione NFC", e);
            call.reject("Errore durante stop sessione NFC: " + e.getMessage());
        }
    }

    private JSObject cieDataToJSObject(CieData cieData) {
        JSObject jsObject = new JSObject();
        
        // Dati anagrafici
        jsObject.put("nome", cieData.getNome());
        jsObject.put("cognome", cieData.getCognome());
        jsObject.put("codiceFiscale", cieData.getCodiceFiscale());
        jsObject.put("dataNascita", cieData.getDataNascita());
        jsObject.put("luogoNascita", cieData.getLuogoNascita());
        jsObject.put("sesso", cieData.getSesso());
        
        // Dati documento
        jsObject.put("numeroDocumento", cieData.getNumeroDocumento());
        jsObject.put("dataRilascio", cieData.getDataRilascio());
        jsObject.put("dataScadenza", cieData.getDataScadenza());
        jsObject.put("comuneRilascio", cieData.getComuneRilascio());
        jsObject.put("issuerCountry", cieData.getIssuerCountry());
        
        // Dati opzionali
        if (cieData.getFotografia() != null) {
            jsObject.put("fotografia", cieData.getFotografia());
        }
        
        if (cieData.getIndirizzoResidenza() != null) {
            JSObject indirizzo = new JSObject();
            CieData.IndirizzoResidenza addr = cieData.getIndirizzoResidenza();
            indirizzo.put("via", addr.getVia());
            indirizzo.put("civico", addr.getCivico());
            indirizzo.put("cap", addr.getCap());
            indirizzo.put("comune", addr.getComune());
            indirizzo.put("provincia", addr.getProvincia());
            jsObject.put("indirizzoResidenza", indirizzo);
        }
        
        // Metadati
        jsObject.put("accessLevel", cieData.getAccessLevel());
        jsObject.put("readTimestamp", cieData.getReadTimestamp());
        jsObject.put("nfcSessionId", cieData.getNfcSessionId());
        jsObject.put("chipSerialNumber", cieData.getChipSerialNumber());
        jsObject.put("documentVersion", cieData.getDocumentVersion());
        
        return jsObject;
    }

    @Override
    protected void handleOnDestroy() {
        super.handleOnDestroy();
        
        if (executorService != null && !executorService.isShutdown()) {
            executorService.shutdown();
        }
        
        if (cieReader != null) {
            cieReader.cleanup();
        }
        
        Log.d(TAG, "Plugin distrutto");
    }

    @Override
    protected void handleOnNewIntent(Intent intent) {
        super.handleOnNewIntent(intent);

        if (NfcAdapter.ACTION_TECH_DISCOVERED.equals(intent.getAction()) ||
            NfcAdapter.ACTION_TAG_DISCOVERED.equals(intent.getAction())) {

            Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
            if (tag != null && cieReader != null) {
                Log.d(TAG, "Tag NFC rilevato: " + tag.toString());
                cieReader.onTagDetected(tag);
            }
        }
    }

    @PluginMethod
    public void testNfcDetection(PluginCall call) {
        try {
            if (nfcAdapter == null || !nfcAdapter.isEnabled()) {
                call.reject("NFC non disponibile", "NFC_NOT_AVAILABLE");
                return;
            }

            Log.d(TAG, "Test rilevamento NFC avviato");

            // Test semplice di rilevamento
            executorService.execute(() -> {
                try {
                    Thread.sleep(1000); // Breve pausa

                    JSObject result = new JSObject();
                    result.put("nfcReady", true);
                    result.put("adapterEnabled", nfcAdapter.isEnabled());
                    result.put("message", "NFC pronto per il rilevamento");

                    call.resolve(result);

                } catch (InterruptedException e) {
                    call.reject("Test interrotto", "TEST_INTERRUPTED");
                }
            });

        } catch (Exception e) {
            Log.e(TAG, "Errore test NFC", e);
            call.reject("Errore durante test NFC: " + e.getMessage());
        }
    }


@PluginMethod
public void diagnosticCard(PluginCall call) {
    try {
        if (nfcAdapter == null || !nfcAdapter.isEnabled()) {
            call.reject("NFC non disponibile", "NFC_NOT_AVAILABLE");
            return;
        }

        Log.d(TAG, "Avvio diagnostica carta NFC");

        executorService.execute(() -> {
            cieReader.readCie("00000000", false, false, 30000, false,
                new CieReader.CieReadCallback() {
                    @Override
                    public void onSuccess(CieData cieData) {
                        // Non ci aspettiamo successo con CAN fittizio
                        JSObject result = new JSObject();
                        result.put("diagnostic", "completed");
                        call.resolve(result);
                    }

                    @Override
                    public void onError(String error, String errorCode) {
                        JSObject result = new JSObject();
                        result.put("diagnostic", "completed");
                        result.put("lastError", error);
                        result.put("lastErrorCode", errorCode);
                        call.resolve(result);
                    }

                    @Override
                    public void onProgress(String step, int progress) {
                        // Log dei progressi per debug
                        Log.d(TAG, "Diagnostica: " + step + " (" + progress + "%)");
                    }

                    @Override
                    public void onTagDetected(String tagId, String tagType, boolean isoCie) {
                        Log.d(TAG, "Diagnostica - Tag rilevato: " + tagId);
                    }
                });
        });

    } catch (Exception e) {
        Log.e(TAG, "Errore diagnostica", e);
        call.reject("Errore durante diagnostica: " + e.getMessage());
    }
}


}

