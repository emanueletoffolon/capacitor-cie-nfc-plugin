package com.yourcompany.plugins.cienfcplugin;
import android.nfc.tech.IsoDep;
import android.util.Log;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Autenticatore BAC (Basic Access Control) per CIE
 * Implementa il protocollo di autenticazione usando i dati MRZ
 */
public class BacAuthenticator {

    private static final String TAG = "BacAuthenticator";

    // AID per la selezione dell'applicazione ePassport
    private static final byte[] EPASSPORT_AID = {
            (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x02, (byte) 0x47, (byte) 0x10, (byte) 0x01
    };

    // Comandi APDU per BAC
    private static final byte[] GET_CHALLENGE = {
            (byte) 0x00, (byte) 0x84, (byte) 0x00, (byte) 0x00, (byte) 0x08
    };

    /**
     * Autentica usando BAC con dati MRZ
     */
public boolean authenticateWithMrz(IsoDep isoDep, MrzData mrzData, CieReader.CieReadCallback callback) {
    try {
        Log.d(TAG, "=== AUTENTICAZIONE BAC CON DOPPIO TENTATIVO M/F ===");
        Log.d(TAG, "MRZ Data: " + mrzData.toString());

        if (!mrzData.isValid()) {
            callback.onError("Dati MRZ non validi", "INVALID_MRZ");
            return false;
        }

        callback.onProgress("Selezione applicazione ePassport...", 30);

        // Step 1: Selezione applicazione
        if (!selectEPassportApplication(isoDep)) {
            callback.onError("Impossibile selezionare applicazione ePassport", "APP_SELECTION_FAILED");
            return false;
        }

        // Step 2: Tentativo
        Log.d(TAG, "🔵 TENTATIVO");
        callback.onProgress("Tentativo autenticazione...", 35);

        boolean successAuth = attemptBacAuthentication(isoDep, mrzData, callback);

        if (successAuth) {
            Log.d(TAG, "✅ Autenticazione riuscita");
            return true;
        }

        Log.d(TAG, "❌ Tentativo fallito");
        return false;

    } catch (Exception e) {
        Log.e(TAG, "❌ Errore autenticazione BAC", e);
        callback.onError("Errore BAC: " + e.getMessage(), "BAC_ERROR");
        return false;
    }
}

/**
 * Singolo tentativo di autenticazione BAC
 */
private boolean attemptBacAuthentication(IsoDep isoDep, MrzData mrzData,
                                        CieReader.CieReadCallback callback) throws Exception {

    Log.d(TAG, "--- Tentativo BAC  ---");

    try {
        // Genera chiavi BAC con il sesso specificato
        BacKeys bacKeys = generateBacKeys(mrzData);
        Log.d(TAG, "Chiavi BAC generate ");

        // Esegue il protocollo BAC
        return executeBacProtocol(isoDep, bacKeys, callback);

    } catch (Exception e) {
        Log.w(TAG, "Tentativo BAC fallito: " + e.getMessage());
        // Non rilancia l'eccezione, permette il tentativo successivo
        return false;
    }
}


    /**
     * Seleziona l'applicazione ePassport
     */
    private boolean selectEPassportApplication(IsoDep isoDep) throws Exception {
        Log.d(TAG, "Selezione applicazione ePassport");

        byte[] selectCmd = new byte[6 + EPASSPORT_AID.length];
        selectCmd[0] = (byte) 0x00; // CLA
        selectCmd[1] = (byte) 0xA4; // INS (SELECT)
        selectCmd[2] = (byte) 0x04; // P1 (SELECT BY DF NAME)
        selectCmd[3] = (byte) 0x0C; // P2
        selectCmd[4] = (byte) EPASSPORT_AID.length; // Lc
        System.arraycopy(EPASSPORT_AID, 0, selectCmd, 5, EPASSPORT_AID.length);
        selectCmd[selectCmd.length - 1] = (byte) 0x00; // Le

        Log.d(TAG, "SELECT command: " + bytesToHex(selectCmd));

        byte[] response = isoDep.transceive(selectCmd);
        Log.d(TAG, "SELECT response: " + bytesToHex(response));

        return isSuccessResponse(response);
    }

    /**
     * Genera le chiavi BAC dai dati MRZ
     */
private BacKeys generateBacKeys(MrzData mrzData) throws Exception {
    Log.d(TAG, "Generazione chiavi BAC con formati multipli");

    String possibleKey = mrzData.generateBacKey();

    // Per ora usa il primo formato (quello attuale)
    Log.d(TAG, "Usando formato: " + possibleKey);

    // Hash SHA-1 della stringa MRZ
    MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
    byte[] hash = sha1.digest(possibleKey.getBytes(StandardCharsets.UTF_8));

    Log.d(TAG, "SHA-1 hash: " + bytesToHex(hash));

    // Estrae Ka e Kb
    byte[] ka = Arrays.copyOfRange(hash, 0, 8);
    byte[] kb = Arrays.copyOfRange(hash, 8, 16);
    byte[] seed = Arrays.copyOf(hash, 16);

    return new BacKeys(ka, kb, seed);
}


    /**
     * Esegue il protocollo BAC completo
     */
    private boolean executeBacProtocol(IsoDep isoDep, BacKeys keys, CieReader.CieReadCallback callback) throws Exception {
        Log.d(TAG, "=== PROTOCOLLO BAC ===");

        callback.onProgress("Richiesta challenge...", 45);

        // Step 1: Get Challenge
        byte[] rndIc = getChallenge(isoDep);
        if (rndIc == null) {
            return false;
        }

        Log.d(TAG, "RND.IC ricevuto: " + bytesToHex(rndIc));

        callback.onProgress("Generazione challenge locale...", 50);

        // Step 2: Genera RND.IFD e K.IFD
        SecureRandom random = new SecureRandom();
        byte[] rndIfd = new byte[8];
        byte[] kIfd = new byte[16];
        random.nextBytes(rndIfd);
        random.nextBytes(kIfd);

        Log.d(TAG, "RND.IFD generato: " + bytesToHex(rndIfd));
        Log.d(TAG, "K.IFD generato: " + bytesToHex(kIfd));

        callback.onProgress("Calcolo autenticazione mutua...", 55);

        // Step 3: Calcola S = RND.IFD || RND.IC || K.IFD
        byte[] s = new byte[32];
        System.arraycopy(rndIfd, 0, s, 0, 8);
        System.arraycopy(rndIc, 0, s, 8, 8);
        System.arraycopy(kIfd, 0, s, 16, 16);

        Log.d(TAG, "S: " + bytesToHex(s));

        // Step 4: Cifra S con 3DES usando Ka
        byte[] encryptedS = encrypt3Des(s, keys.getKa());
        Log.d(TAG, "S cifrato: " + bytesToHex(encryptedS));

        // Step 5: Calcola MAC di S cifrato usando Kb
        byte[] mac = calculateMac(encryptedS, keys.getKb());
        Log.d(TAG, "MAC calcolato: " + bytesToHex(mac));

        callback.onProgress("Invio comando External Authenticate...", 60);

        // Step 6: External Authenticate
        return sendExternalAuthenticate(isoDep, encryptedS, mac, rndIc, kIfd, keys, callback);
    }

    /**
     * Richiede un challenge dal chip
     */
    private byte[] getChallenge(IsoDep isoDep) throws Exception {
        Log.d(TAG, "Get Challenge");

        byte[] response = isoDep.transceive(GET_CHALLENGE);
        Log.d(TAG, "Get Challenge response: " + bytesToHex(response));

        if (!isSuccessResponse(response)) {
            Log.e(TAG, "❌ Get Challenge fallito");
            return null;
        }

        // Rimuove status word (ultimi 2 byte)
        return Arrays.copyOf(response, response.length - 2);
    }

    /**
     * Cifra con 3DES in modalità CBC
     */
    private byte[] encrypt3Des(byte[] data, byte[] key) throws Exception {
        // Prepara chiave 3DES (24 byte) da chiave 8 byte
        byte[] key3Des = new byte[24];
        System.arraycopy(key, 0, key3Des, 0, 8);
        System.arraycopy(key, 0, key3Des, 8, 8);
        System.arraycopy(key, 0, key3Des, 16, 8);

        Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key3Des, "DESede");
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[8]); // IV zero

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(data);
    }

    /**
     * Calcola MAC usando 3DES
     */
    private byte[] calculateMac(byte[] data, byte[] key) throws Exception {
        // Padding dei dati se necessario
        int paddingLength = 8 - (data.length % 8);
        if (paddingLength == 8) paddingLength = 0;

        byte[] paddedData = new byte[data.length + paddingLength];
        System.arraycopy(data, 0, paddedData, 0, data.length);
        // Il padding è zero per semplicità

        // Cifra con 3DES CBC
        byte[] encrypted = encrypt3Des(paddedData, key);

        // Il MAC sono gli ultimi 8 byte cifrati
        return Arrays.copyOfRange(encrypted, encrypted.length - 8, encrypted.length);
    }

    /**
     * Invia comando External Authenticate
     */
    private boolean sendExternalAuthenticate(IsoDep isoDep, byte[] encryptedS, byte[] mac,
                                             byte[] rndIc, byte[] kIfd, BacKeys keys,
                                             CieReader.CieReadCallback callback) throws Exception {
        Log.d(TAG, "External Authenticate");

        // Costruisce comando External Authenticate
        byte[] cmdData = new byte[encryptedS.length + mac.length];
        System.arraycopy(encryptedS, 0, cmdData, 0, encryptedS.length);
        System.arraycopy(mac, 0, cmdData, encryptedS.length, mac.length);

        byte[] cmd = new byte[5 + cmdData.length + 1];
        cmd[0] = (byte) 0x00; // CLA
        cmd[1] = (byte) 0x82; // INS (EXTERNAL AUTHENTICATE)
        cmd[2] = (byte) 0x00; // P1
        cmd[3] = (byte) 0x00; // P2
        cmd[4] = (byte) cmdData.length; // Lc
        System.arraycopy(cmdData, 0, cmd, 5, cmdData.length);
        cmd[cmd.length - 1] = (byte) 0x28; // Le (40 byte attesi)

        Log.d(TAG, "External Authenticate command: " + bytesToHex(cmd));

        byte[] response = isoDep.transceive(cmd);
        Log.d(TAG, "External Authenticate response: " + bytesToHex(response));

        if (!isSuccessResponse(response)) {
            Log.e(TAG, "❌ External Authenticate fallito");
            callback.onError("Autenticazione BAC fallita", "BAC_AUTH_FAILED");
            return false;
        }

        callback.onProgress("Verifica risposta autenticazione...", 70);

        // Verifica la risposta del chip
        return verifyAuthenticationResponse(response, rndIc, kIfd, keys, callback);
    }

    /**
     * Verifica la risposta di autenticazione dal chip
     */
    private boolean verifyAuthenticationResponse(byte[] response, byte[] rndIc, byte[] kIfd,
                                                 BacKeys keys, CieReader.CieReadCallback callback) throws Exception {
        Log.d(TAG, "Verifica risposta autenticazione");

        // Rimuove status word
        byte[] responseData = Arrays.copyOf(response, response.length - 2);

        if (responseData.length < 40) {
            Log.e(TAG, "❌ Risposta troppo corta");
            callback.onError("Risposta autenticazione non valida", "INVALID_AUTH_RESPONSE");
            return false;
        }

        // Estrae dati cifrati e MAC dalla risposta
        byte[] encryptedResponse = Arrays.copyOf(responseData, 32);
        byte[] responseMac = Arrays.copyOfRange(responseData, 32, 40);

        Log.d(TAG, "Risposta cifrata: " + bytesToHex(encryptedResponse));
        Log.d(TAG, "MAC risposta: " + bytesToHex(responseMac));

        // Verifica MAC
        byte[] calculatedMac = calculateMac(encryptedResponse, keys.getKb());
        if (!Arrays.equals(responseMac, calculatedMac)) {
            Log.e(TAG, "❌ MAC non valido");
            callback.onError("MAC autenticazione non valido", "INVALID_MAC");
            return false;
        }

        // Decifra la risposta
        byte[] decryptedResponse = decrypt3Des(encryptedResponse, keys.getKa());
        Log.d(TAG, "Risposta decifrata: " + bytesToHex(decryptedResponse));

        // Verifica che contenga RND.IC
        byte[] responseRndIc = Arrays.copyOf(decryptedResponse, 8);
        if (!Arrays.equals(rndIc, responseRndIc)) {
            Log.e(TAG, "❌ RND.IC non corrisponde");
            callback.onError("Challenge di risposta non valido", "INVALID_CHALLENGE");
            return false;
        }

        Log.d(TAG, "✅ Autenticazione BAC completata con successo");
        callback.onProgress("Autenticazione BAC completata", 80);
        return true;
    }

    /**
     * Decifra con 3DES
     */
    private byte[] decrypt3Des(byte[] data, byte[] key) throws Exception {
        // Prepara chiave 3DES (24 byte) da chiave 8 byte
        byte[] key3Des = new byte[24];
        System.arraycopy(key, 0, key3Des, 0, 8);
        System.arraycopy(key, 0, key3Des, 8, 8);
        System.arraycopy(key, 0, key3Des, 16, 8);

        Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key3Des, "DESede");
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[8]); // IV zero

        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(data);
    }

    /**
     * Verifica se la risposta APDU indica successo
     */
    private boolean isSuccessResponse(byte[] response) {
        if (response == null || response.length < 2) {
            return false;
        }
        int statusWord = ((response[response.length - 2] & 0xFF) << 8) |
                (response[response.length - 1] & 0xFF);
        return statusWord == 0x9000;
    }

    /**
     * Converte array di byte in stringa esadecimale
     */
    private String bytesToHex(byte[] bytes) {
        if (bytes == null) return "null";
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02X ", b));
        }
        return result.toString().trim();
    }

    /**
     * Classe per le chiavi BAC
     */
    private static class BacKeys {
        private final byte[] ka;  // Authentication Key
        private final byte[] kb;  // MAC Key
        private final byte[] seed; // Seed per derivazione chiavi di sessione

        public BacKeys(byte[] ka, byte[] kb, byte[] seed) {
            this.ka = ka.clone();
            this.kb = kb.clone();
            this.seed = seed.clone();
        }

        public byte[] getKa() { return ka.clone(); }
        public byte[] getKb() { return kb.clone(); }
        public byte[] getSeed() { return seed.clone(); }
    }
}
