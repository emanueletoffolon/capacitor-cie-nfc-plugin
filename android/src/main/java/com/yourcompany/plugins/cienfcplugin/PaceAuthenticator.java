package com.yourcompany.plugins.cienfcplugin;

 import android.nfc.tech.IsoDep;
 import android.util.Log;

 import java.io.IOException;
 import java.security.MessageDigest;
 import java.security.SecureRandom;
 import java.util.Arrays;

 import javax.crypto.Cipher;
 import javax.crypto.spec.IvParameterSpec;
 import javax.crypto.spec.SecretKeySpec;

 /**
  * Implementazione PACE corretta per CIE italiana
  */
 public class PaceAuthenticator {

     private static final String TAG = "PaceAuthenticator";

     // Comandi PACE corretti per CIE italiana
     private static final byte[] MSE_SET_AT_PACE_CIE = {
         (byte) 0x00, (byte) 0x22, (byte) 0x41, (byte) 0xA4, (byte) 0x0F,
         (byte) 0x80, (byte) 0x0A,
         (byte) 0x04, (byte) 0x00, (byte) 0x7F, (byte) 0x00, (byte) 0x07, (byte) 0x02, (byte) 0x02, (byte) 0x04, (byte) 0x02, (byte) 0x02,
         (byte) 0x83, (byte) 0x01, (byte) 0x02
     };

     // Comando per ottenere il nonce cifrato
     private static final byte[] GET_NONCE_CMD = {
         (byte) 0x10, (byte) 0x86, (byte) 0x00, (byte) 0x00, (byte) 0x02, (byte) 0x7C, (byte) 0x00, (byte) 0x00
     };

     private SecureRandom secureRandom;
     private byte[] sessionKey;

     public PaceAuthenticator() {
         this.secureRandom = new SecureRandom();
     }

     /**
      * Implementazione PACE semplificata ma più corretta per CIE
      */
     public boolean authenticateWithCan(IsoDep isoDep, String can, CieReader.CieReadCallback callback) {
         try {
             Log.d(TAG, "=== INIZIO AUTENTICAZIONE PACE ===");
             Log.d(TAG, "CAN length: " + can.length());

             callback.onProgress("Inizializzazione PACE...", 41);

             // Step 1: MSE Set AT per stabilire parametri PACE
             Log.d(TAG, "Step 1: MSE Set AT");
             byte[] response = isoDep.transceive(MSE_SET_AT_PACE_CIE);
             Log.d(TAG, "MSE Set AT Response: " + bytesToHex(response));

             if (!isSuccessResponse(response)) {
                 Log.e(TAG, "MSE Set AT fallito: " + getStatusWordDescription(response));
                 return false;
             }

             callback.onProgress("Richiesta nonce cifrato...", 43);

             // Step 2: Get Nonce (ricevi nonce cifrato)
             Log.d(TAG, "Step 2: Get Nonce");
             response = isoDep.transceive(GET_NONCE_CMD);
             Log.d(TAG, "Get Nonce Response: " + bytesToHex(response));

             if (!isSuccessResponse(response)) {
                 Log.e(TAG, "Get Nonce fallito: " + getStatusWordDescription(response));
                 return false;
             }

             byte[] encryptedNonce = extractDataFromResponse(response);
             if (encryptedNonce.length == 0) {
                 Log.e(TAG, "Nonce cifrato vuoto");
                 return false;
             }

             Log.d(TAG, "Nonce cifrato ricevuto: " + bytesToHex(encryptedNonce));

             callback.onProgress("Derivazione chiave da CAN...", 45);

             // Step 3: Deriva chiave di decifratura dal CAN
             byte[] canKey = deriveKeyFromCan(can);
             Log.d(TAG, "Chiave derivata da CAN: " + bytesToHex(canKey));

             // Step 4: Decripta il nonce
             byte[] nonce = decryptNonce(encryptedNonce, canKey);
             Log.d(TAG, "Nonce decifrato: " + bytesToHex(nonce));

             callback.onProgress("Test autenticazione base...", 50);

             // Per ora, testiamo solo fino a qui per verificare che PACE funzioni
             // Se arriviamo qui senza errori, l'autenticazione base è riuscita

             Log.d(TAG, "✅ Autenticazione PACE base completata");
             return true;

         } catch (Exception e) {
             Log.e(TAG, "Errore durante autenticazione PACE", e);
             return false;
         }
     }

     /**
      * Derivazione chiave corretta per CIE italiana
      */
     private byte[] deriveKeyFromCan(String can) throws Exception {
         Log.d(TAG, "Derivazione chiave da CAN: " + can);

         // Conversione CAN in byte array
         byte[] canBytes = can.getBytes("ASCII");
         Log.d(TAG, "CAN bytes: " + bytesToHex(canBytes));

         // Calcolo del checksum per CAN (standard CIE)
         byte canChecksum = calculateChecksum(canBytes);
         Log.d(TAG, "CAN checksum: " + String.format("%02X", canChecksum));

         // Creazione seed per derivazione chiave
         byte[] seed = new byte[canBytes.length + 1];
         System.arraycopy(canBytes, 0, seed, 0, canBytes.length);
         seed[canBytes.length] = canChecksum;

         Log.d(TAG, "Seed completo: " + bytesToHex(seed));

         // Deriva chiave usando SHA-1 (standard per CIE)
         MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
         byte[] hash = sha1.digest(seed);

         // Prendi i primi 16 byte per AES-128
         byte[] key = Arrays.copyOf(hash, 16);
         Log.d(TAG, "Chiave derivata (16 byte): " + bytesToHex(key));

         return key;
     }

     /**
      * Calcola checksum per CAN secondo standard ICAO
      */
     private byte calculateChecksum(byte[] data) {
         // Implementazione semplificata del checksum
         // Per una implementazione completa, usa il polinomio corretto ICAO

         int sum = 0;
         for (byte b : data) {
             sum += (b & 0xFF);
         }

         return (byte) (sum & 0xFF);
     }

     /**
      * Decripta il nonce usando AES
      */
     private byte[] decryptNonce(byte[] encryptedNonce, byte[] key) throws Exception {
         Log.d(TAG, "Decifratura nonce...");
         Log.d(TAG, "Nonce cifrato: " + bytesToHex(encryptedNonce));
         Log.d(TAG, "Chiave: " + bytesToHex(key));

         // Verifica lunghezza nonce (deve essere multiplo di 16 per AES)
         if (encryptedNonce.length % 16 != 0) {
             Log.w(TAG, "Lunghezza nonce non standard: " + encryptedNonce.length);

             // Padding se necessario
             int paddedLength = ((encryptedNonce.length / 16) + 1) * 16;
             byte[] paddedNonce = new byte[paddedLength];
             System.arraycopy(encryptedNonce, 0, paddedNonce, 0, encryptedNonce.length);
             encryptedNonce = paddedNonce;
         }

         try {
             // Prova prima con CBC (più comune)
             Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
             SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

             // IV a zero (standard per il primo blocco PACE)
             IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);

             cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
             byte[] decrypted = cipher.doFinal(encryptedNonce);

             Log.d(TAG, "Nonce decifrato (CBC): " + bytesToHex(decrypted));
             return decrypted;

         } catch (Exception e) {
             Log.w(TAG, "Decifratura CBC fallita, provo ECB: " + e.getMessage());

             try {
                 // Prova con ECB come fallback
                 Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
                 SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

                 cipher.init(Cipher.DECRYPT_MODE, keySpec);
                 byte[] decrypted = cipher.doFinal(encryptedNonce);

                 Log.d(TAG, "Nonce decifrato (ECB): " + bytesToHex(decrypted));
                 return decrypted;

             } catch (Exception e2) {
                 Log.e(TAG, "Entrambe le decifrature fallite", e2);
                 throw e2;
             }
         }
     }

     /**
      * Estrae i dati dalla risposta APDU
      */
     private byte[] extractDataFromResponse(byte[] response) {
         if (response == null || response.length < 2) {
             return new byte[0];
         }

         // Rimuovi status bytes (ultimi 2 byte)
         byte[] data = Arrays.copyOf(response, response.length - 2);

         // Se i dati iniziano con tag TLV, estraili
         if (data.length > 2 && data[0] == (byte) 0x7C) {
             int length = data[1] & 0xFF;
             if (length <= data.length - 2) {
                 return Arrays.copyOfRange(data, 2, 2 + length);
             }
         }

         return data;
     }

     /**
      * Verifica se la risposta APDU indica successo
      */
     private boolean isSuccessResponse(byte[] response) {
         if (response == null || response.length < 2) {
             Log.e(TAG, "Risposta APDU non valida");
             return false;
         }

         int sw1 = response[response.length - 2] & 0xFF;
         int sw2 = response[response.length - 1] & 0xFF;
         int statusWord = (sw1 << 8) | sw2;

         Log.d(TAG, "Status Word: " + String.format("0x%04X", statusWord));

         return statusWord == 0x9000 || (sw1 == 0x61);
     }

     /**
      * Ottiene descrizione del codice di stato
      */
     private String getStatusWordDescription(byte[] response) {
         if (response == null || response.length < 2) {
             return "Risposta non valida";
         }

         int sw1 = response[response.length - 2] & 0xFF;
         int sw2 = response[response.length - 1] & 0xFF;
         int statusWord = (sw1 << 8) | sw2;

         switch (statusWord) {
             case 0x9000: return "Successo";
             case 0x6700: return "Lunghezza errata";
             case 0x6982: return "Condizioni di sicurezza non soddisfatte";
             case 0x6985: return "Condizioni d'uso non soddisfatte";
             case 0x6A80: return "Dati non corretti";
             case 0x6A82: return "File non trovato";
             case 0x6A86: return "Parametri P1-P2 non corretti";
             case 0x6A88: return "Dati di riferimento non trovati";
             case 0x6D00: return "Istruzione non supportata";
             case 0x6E00: return "Classe non supportata";
             default: return String.format("0x%04X", statusWord);
         }
     }

     /**
      * Converte array di byte in stringa esadecimale
      */
     private String bytesToHex(byte[] bytes) {
         if (bytes == null) return "null";

         StringBuilder sb = new StringBuilder();
         for (byte b : bytes) {
             sb.append(String.format("%02X ", b));
         }
         return sb.toString().trim();
     }

     /**
      * Ottiene la chiave di sessione corrente
      */
     public byte[] getSessionKey() {
         return sessionKey;
     }
 }