package com.yourcompany.plugins.cienfcplugin;

import android.app.Activity;
import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.NfcManager;
import android.provider.Settings;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

@CapacitorPlugin(name = "CieNfcPlugin")
public class CieNfcPluginPlugin extends Plugin {

   private static final String TAG = "CieNfcPlugin";
   private CieReader cieReader;
   private NfcAdapter nfcAdapter;

   @Override
   public void load() {
       super.load();

       // Inizializza NFC adapter
       NfcManager nfcManager = (NfcManager) getActivity().getSystemService(Activity.NFC_SERVICE);
       if (nfcManager != null) {
           nfcAdapter = nfcManager.getDefaultAdapter();
       }

       // Inizializza CIE reader con il plugin come parametro
       cieReader = new CieReader(getActivity(), this);
   }

   @PluginMethod
   public void isNfcAvailable(PluginCall call) {
       try {
           boolean available = nfcAdapter != null && nfcAdapter.isEnabled();

           JSObject result = new JSObject();
           result.put("available", available);
           call.resolve(result);

       } catch (Exception e) {
           call.reject("Errore verifica NFC: " + e.getMessage());
       }
   }

   @PluginMethod
   public void enableNfc(PluginCall call) {
       try {
           if (nfcAdapter == null) {
               call.reject("NFC non supportato su questo dispositivo");
               return;
           }

           Intent intent = new Intent(Settings.ACTION_NFC_SETTINGS);
           getActivity().startActivity(intent);
           call.resolve();

       } catch (Exception e) {
           call.reject("Errore apertura impostazioni NFC: " + e.getMessage());
       }
   }

   @PluginMethod
   public void readCie(PluginCall call) {
       try {
           String can = call.getString("can");
           Boolean readPhoto = call.getBoolean("readPhoto", false);
           Boolean readAddress = call.getBoolean("readAddress", false);
           Integer timeout = call.getInt("timeout", 30000);
           Boolean validateChecksum = call.getBoolean("validateChecksum", true);

           if (can == null || can.isEmpty()) {
               call.reject("CAN richiesto per lettura CIE", "MISSING_CAN");
               return;
           }

           // Configura callback per eventi
           CieReader.CieReadCallback callback = new CieReader.CieReadCallback() {
               @Override
               public void onSuccess(CieData data) {
                   JSObject result = new JSObject();
                   result.put("success", true);
                   result.put("data", cieDataToJSObject(data));
                   result.put("readingTime", data.getReadingTime());
                   result.put("authMethod", "CAN");
                   call.resolve(result);
               }

               @Override
               public void onError(String error, String errorCode) {
                   JSObject result = new JSObject();
                   result.put("success", false);
                   result.put("error", error);
                   result.put("errorCode", errorCode);
                   result.put("authMethod", "CAN");
                   call.resolve(result);
               }

               @Override
               public void onProgress(String step, int progress) {
                   JSObject eventData = new JSObject();
                   eventData.put("step", step);
                   eventData.put("progress", progress);

                   JSObject event = new JSObject();
                   event.put("type", "progress");
                   event.put("message", step);
                   event.put("data", eventData);
                   event.put("timestamp", System.currentTimeMillis());

                   notifyListeners("nfcProgress", event);
               }

               @Override
               public void onTagDetected(String tagId, String tagType) {
                   JSObject eventData = new JSObject();
                   eventData.put("tagId", tagId);
                   eventData.put("tagType", tagType);
                   eventData.put("isoCie", true);

                   JSObject event = new JSObject();
                   event.put("type", "tagDetected");
                   event.put("message", "CIE rilevata");
                   event.put("data", eventData);
                   event.put("timestamp", System.currentTimeMillis());

                   notifyListeners("nfcTagDetected", event);
               }
           };

           // Avvia lettura con CAN
           cieReader.readCieWithCan(can, readPhoto, readAddress, timeout, validateChecksum, callback);

       } catch (Exception e) {
           call.reject("Errore lettura CIE: " + e.getMessage(), "READ_ERROR");
       }
   }

    @PluginMethod
    public void readCieWithMrz(PluginCall call) {
        android.util.Log.d(TAG, "=== Inizio readCieWithMrz ===");

        try {
            // Verifica stato NFC e foreground dispatch
            android.util.Log.d(TAG, "Verifica stato NFC...");
            if (nfcAdapter == null) {
                android.util.Log.e(TAG, "NFC Adapter è null");
                call.reject("NFC non disponibile", "NFC_NOT_AVAILABLE");
                return;
            }

            android.util.Log.d(TAG, "NFC Adapter stato:");
            android.util.Log.d(TAG, "  - isEnabled: " + nfcAdapter.isEnabled());
            android.util.Log.d(TAG, "  - Activity in foreground: " + (getActivity().hasWindowFocus()));

            // Verifica se il CieReader ha il foreground dispatch attivo
            android.util.Log.d(TAG, "Verifica CieReader...");
            if (cieReader == null) {
                android.util.Log.e(TAG, "CieReader è null");
                call.reject("CieReader non inizializzato", "READER_NOT_INITIALIZED");
                return;
            }

            String documentNumber = call.getString("documentNumber");
            String dateOfBirth = call.getString("dateOfBirth");
            String dateOfExpiry = call.getString("dateOfExpiry");
            Boolean readPhoto = call.getBoolean("readPhoto", false);
            Boolean readAddress = call.getBoolean("readAddress", false);
            Integer timeout = call.getInt("timeout", 30000);
            Boolean validateChecksum = call.getBoolean("validateChecksum", true);

            android.util.Log.d(TAG, "Parametri ricevuti:");
            android.util.Log.d(TAG, "  - documentNumber: " + (documentNumber != null ? documentNumber.length() + " caratteri" : "null"));
            android.util.Log.d(TAG, "  - dateOfBirth: " + dateOfBirth);
            android.util.Log.d(TAG, "  - dateOfExpiry: " + dateOfExpiry);
            android.util.Log.d(TAG, "  - readPhoto: " + readPhoto);
            android.util.Log.d(TAG, "  - readAddress: " + readAddress);
            android.util.Log.d(TAG, "  - timeout: " + timeout + "ms");
            android.util.Log.d(TAG, "  - validateChecksum: " + validateChecksum);

            if (documentNumber == null || dateOfBirth == null || dateOfExpiry == null) {
                android.util.Log.e(TAG, "Errore: Dati MRZ incompleti");
                call.reject("Dati MRZ incompleti", "MISSING_MRZ_DATA");
                return;
            }

            android.util.Log.d(TAG, "Validazione dati MRZ...");
            if (!isValidMrzData(documentNumber, dateOfBirth, dateOfExpiry)) {
                android.util.Log.e(TAG, "Errore: Dati MRZ non validi");
                call.reject("Dati MRZ non validi", "INVALID_MRZ_DATA");
                return;
            }
            android.util.Log.d(TAG, "Validazione MRZ completata con successo");

            // Assicurati che l'app sia in foreground prima di iniziare
            android.util.Log.d(TAG, "Controllo stato applicazione...");
            if (!getActivity().hasWindowFocus()) {
                android.util.Log.w(TAG, "Attenzione: L'app potrebbe non essere in foreground");
            }

            android.util.Log.d(TAG, "Configurazione callback...");
            CieReader.CieReadCallback callback = new CieReader.CieReadCallback() {
                @Override
                public void onSuccess(CieData data) {
                    android.util.Log.d(TAG, "Callback onSuccess chiamato");
                    android.util.Log.d(TAG, "  - Tempo di lettura: " + data.getReadingTime() + "ms");

                    JSObject result = new JSObject();
                    result.put("success", true);
                    result.put("data", cieDataToJSObject(data));
                    result.put("readingTime", data.getReadingTime());
                    result.put("authMethod", "BAC");

                    call.resolve(result);
                }

                @Override
                public void onError(String error, String errorCode) {
                    android.util.Log.e(TAG, "Callback onError chiamato");
                    android.util.Log.e(TAG, "  - Errore: " + error);
                    android.util.Log.e(TAG, "  - Codice errore: " + errorCode);

                    JSObject result = new JSObject();
                    result.put("success", false);
                    result.put("error", error);
                    result.put("errorCode", errorCode);
                    result.put("authMethod", "BAC");

                    call.resolve(result);
                }

                @Override
                public void onProgress(String step, int progress) {
                    android.util.Log.d(TAG, "Progress: " + step + " (" + progress + "%)");

                    JSObject eventData = new JSObject();
                    eventData.put("step", step);
                    eventData.put("progress", progress);

                    JSObject event = new JSObject();
                    event.put("type", "progress");
                    event.put("message", step);
                    event.put("data", eventData);
                    event.put("timestamp", System.currentTimeMillis());

                    notifyListeners("nfcProgress", event);
                }

                @Override
                public void onTagDetected(String tagId, String tagType) {
                    android.util.Log.d(TAG, "Tag NFC rilevato nell'app");
                    android.util.Log.d(TAG, "  - Tag ID: " + tagId);
                    android.util.Log.d(TAG, "  - Tag Type: " + tagType);
                    android.util.Log.d(TAG, "  - Timestamp: " + System.currentTimeMillis());

                    JSObject eventData = new JSObject();
                    eventData.put("tagId", tagId);
                    eventData.put("tagType", tagType);
                    eventData.put("isoCie", true);

                    JSObject event = new JSObject();
                    event.put("type", "tagDetected");
                    event.put("message", "CIE rilevata");
                    event.put("data", eventData);
                    event.put("timestamp", System.currentTimeMillis());

                    notifyListeners("nfcTagDetected", event);
                }
            };

            android.util.Log.d(TAG, "Creazione oggetto MrzData...");
            MrzData mrzData = new MrzData(documentNumber, dateOfBirth, dateOfExpiry);

            android.util.Log.d(TAG, "Avvio lettura CIE con MRZ/BAC...");
            android.util.Log.d(TAG, "Timestamp avvio: " + System.currentTimeMillis());

            cieReader.readCieWithMrz(mrzData, readPhoto, readAddress, timeout, validateChecksum, callback);
            android.util.Log.d(TAG, "Comando lettura inviato al CieReader");

        } catch (Exception e) {
            android.util.Log.e(TAG, "Eccezione in readCieWithMrz: " + e.getMessage(), e);
            call.reject("Errore lettura CIE con MRZ: " + e.getMessage(), "READ_MRZ_ERROR");
        }

        android.util.Log.d(TAG, "=== Fine readCieWithMrz ===");
    }



   @PluginMethod
   public void startNfcSession(PluginCall call) {
       try {
           cieReader.startNfcSession();
           call.resolve();
       } catch (Exception e) {
           call.reject("Errore avvio sessione NFC: " + e.getMessage());
       }
   }

   @PluginMethod
   public void stopNfcSession(PluginCall call) {
       try {
           cieReader.stopNfcSession();
           call.resolve();
       } catch (Exception e) {
           call.reject("Errore stop sessione NFC: " + e.getMessage());
       }
   }

   /**
    * Converte CieData in JSObject per il ritorno a JavaScript
    */
   private JSObject cieDataToJSObject(CieData data) {
       JSObject jsData = new JSObject();

       // Dati anagrafici base
       jsData.put("nome", data.getNome());
       jsData.put("cognome", data.getCognome());
       jsData.put("codiceFiscale", data.getCodiceFiscale());
       jsData.put("dataNascita", data.getDataNascita());
       jsData.put("luogoNascita", data.getLuogoNascita());
       jsData.put("sesso", data.getSesso());

       // Dati documento
       jsData.put("numeroDocumento", data.getNumeroDocumento());
       jsData.put("dataRilascio", data.getDataRilascio());
       jsData.put("dataScadenza", data.getDataScadenza());
       jsData.put("comuneRilascio", data.getComuneRilascio());
       jsData.put("issuerCountry", data.getIssuerCountry());

       // Dati opzionali
       if (data.getFotografia() != null) {
           jsData.put("fotografia", data.getFotografia());
       }

       if (data.getIndirizzoResidenza() != null) {
           JSObject indirizzo = new JSObject();
           indirizzo.put("via", data.getIndirizzoResidenza().getVia());
           indirizzo.put("civico", data.getIndirizzoResidenza().getCivico());
           indirizzo.put("cap", data.getIndirizzoResidenza().getCap());
           indirizzo.put("comune", data.getIndirizzoResidenza().getComune());
           indirizzo.put("provincia", data.getIndirizzoResidenza().getProvincia());
           jsData.put("indirizzoResidenza", indirizzo);
       }

       // Metadati lettura
       jsData.put("accessLevel", data.getAccessLevel());
       jsData.put("readTimestamp", data.getReadTimestamp());
       jsData.put("nfcSessionId", data.getNfcSessionId());
       jsData.put("authMethod", data.getAuthMethod());

       // Dati tecnici
       if (data.getChipSerialNumber() != null) {
           jsData.put("chipSerialNumber", data.getChipSerialNumber());
       }
       jsData.put("documentVersion", data.getDocumentVersion());

       return jsData;
   }

   /**
    * Valida i dati MRZ
    */
   private boolean isValidMrzData(String documentNumber, String dateOfBirth, String dateOfExpiry) {
       // Validazione numero documento (9 caratteri alfanumerici)
       if (documentNumber == null || !documentNumber.matches("^[A-Z0-9]{9}$")) {
           return false;
       }

       // Validazione data di nascita (6 cifre YYMMDD)
       if (dateOfBirth == null || !dateOfBirth.matches("^\\d{6}$")) {
           return false;
       }

       // Validazione data di scadenza (6 cifre YYMMDD)
       if (dateOfExpiry == null || !dateOfExpiry.matches("^\\d{6}$")) {
           return false;
       }

       return true;
   }

   /**
    * Ottiene l'NfcAdapter
    */
   public NfcAdapter getNfcAdapter() {
       return nfcAdapter;
   }

    /**
     * Ottiene l'istanza del CieReader
     */
    public CieReader getCieReader() {
        android.util.Log.d(TAG, "Richiesta CieReader: " + (cieReader != null ? "disponibile" : "null"));
        return cieReader;
    }


}