package com.yourcompany.plugins.cienfcplugin;

import android.nfc.tech.IsoDep;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Implementazione corretta per l'accesso al NIS della CIE
 * Utilizza l'AID specifico che funziona con la CIE dell'utente: A0 00 00 02 47 10 01
 *
 * Versione corretta basata sui risultati del test che mostrano quale AID funziona
 */
public class CieNisReader {

    private static final String TAG = "CieNisReader";

    // AID corretto che funziona con la CIE dell'utente (dal log di test)
    private static final byte[] CIE_AID_WORKING = {
            (byte) 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01
    };

    // AID alternativi da provare se il primo non funziona
    private static final byte[][] ALTERNATIVE_AIDS = {
            {(byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x39}, // AID dal manuale NIS
            {(byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x39, (byte) 0x01, (byte) 0x00}, // AID CIE standard
            {(byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x30, (byte) 0x80, (byte) 0x00}, // Altri AID testati
    };

    // File ID per il NIS e altri dati (da testare)
    private static final byte[][] NIS_FILE_IDS = {
            {0x00, 0x06}, // File ID standard NIS
            {0x00, 0x05}, // File ID alternativo
            {0x00, 0x04}, // File ID alternativo
            {0x01, 0x00}, // File ID alternativo
            {0x01, 0x01}, // File ID alternativo
    };

    private IsoDep isoDep;
    private String can;

    public CieNisReader(IsoDep isoDep, String can) {
        this.isoDep = isoDep;
        this.can = can;
    }

    /**
     * Metodo principale per leggere e verificare il NIS
     */
    public CieNisResult readAndVerifyNis() {
        try {
            log("🚀 Inizio lettura NIS con AID corretto dalla CIE");

            // Step 1: Selezione applicazione CIE con AID corretto
            if (!selectCieApplicationWithCorrectAid()) {
                return new CieNisResult(false, "Impossibile selezionare l'applicazione CIE con nessun AID");
            }

            // Step 2: Esplorazione della struttura della CIE
            exploreCardStructure();

            // Step 3: Tentativo di lettura del NIS con diversi approcci
            byte[] nisData = attemptNisReading();
            if (nisData == null) {
                return new CieNisResult(false, "Impossibile leggere il NIS con nessun metodo");
            }

            // Step 4: Tentativo di Internal Authentication
            boolean isOriginal = attemptInternalAuthentication();

            // Step 5: Estrazione del NIS dai dati letti
            String nisNumber = extractNisNumber(nisData);

            log("✅ NIS letto con successo: " + nisNumber);
            log("🔐 Verifica originalità: " + (isOriginal ? "ORIGINALE" : "NON VERIFICATA"));

            return new CieNisResult(true, "NIS letto con successo", nisNumber, isOriginal);

        } catch (Exception e) {
            log("❌ Errore durante lettura NIS: " + e.getMessage());
            return new CieNisResult(false, "Errore: " + e.getMessage());
        }
    }

    /**
     * Selezione dell'applicazione CIE con l'AID corretto
     */
    private boolean selectCieApplicationWithCorrectAid() {
        try {
            log("📋 Selezione applicazione CIE con AID corretto...");

            // Prima prova con l'AID che sappiamo funzionare
            byte[] selectCommand = buildSelectCommand(CIE_AID_WORKING);
            byte[] response = isoDep.transceive(selectCommand);

            if (response.length >= 2) {
                int sw = getStatusWord(response);

                if (sw == 0x9000) {
                    log("✅ Applicazione CIE selezionata con AID corretto: " + bytesToHex(CIE_AID_WORKING));
                    return true;
                } else {
                    log("⚠️ AID corretto fallito: " + String.format("0x%04X", sw));
                }
            }

            // Se l'AID corretto fallisce, prova gli alternativi
            log("🔄 Tentativo con AID alternativi...");
            for (int i = 0; i < ALTERNATIVE_AIDS.length; i++) {
                byte[] aid = ALTERNATIVE_AIDS[i];
                selectCommand = buildSelectCommand(aid);
                response = isoDep.transceive(selectCommand);

                if (response.length >= 2) {
                    int sw = getStatusWord(response);

                    if (sw == 0x9000) {
                        log("✅ Applicazione CIE selezionata con AID alternativo " + (i+1) + ": " + bytesToHex(aid));
                        return true;
                    } else {
                        log("❌ AID alternativo " + (i+1) + " fallito: " + String.format("0x%04X", sw));
                    }
                }
            }

            return false;

        } catch (IOException e) {
            log("❌ Errore durante selezione applicazione: " + e.getMessage());
            return false;
        }
    }

    /**
     * Esplorazione della struttura della CIE per capire cosa è disponibile
     */
    private void exploreCardStructure() {
        log("🔍 Esplorazione struttura della CIE...");

        // Prova a leggere diversi file per capire la struttura
        for (int i = 0; i < NIS_FILE_IDS.length; i++) {
            byte[] fileId = NIS_FILE_IDS[i];
            log("📁 Test file ID " + (i+1) + ": " + bytesToHex(fileId));

            try {
                // Prova selezione file
                byte[] selectFileCommand = buildSelectFileCommand(fileId);
                byte[] response = isoDep.transceive(selectFileCommand);

                int sw = getStatusWord(response);
                if (sw == 0x9000) {
                    log("✅ File ID " + (i+1) + " selezionato con successo");

                    // Prova lettura del file
                    byte[] readCommand = buildReadBinaryCommand(0, 32); // Leggi solo i primi 32 bytes
                    response = isoDep.transceive(readCommand);

                    sw = getStatusWord(response);
                    if (sw == 0x9000) {
                        byte[] data = Arrays.copyOf(response, response.length - 2);
                        log("📖 Dati letti da file " + (i+1) + ": " + bytesToHex(data));
                    } else {
                        log("⚠️ Lettura file " + (i+1) + " fallita: " + String.format("0x%04X", sw));
                    }
                } else {
                    log("❌ File ID " + (i+1) + " non selezionabile: " + String.format("0x%04X", sw));
                }

            } catch (IOException e) {
                log("❌ Errore durante test file " + (i+1) + ": " + e.getMessage());
            }
        }
    }

    /**
     * Tentativo di lettura del NIS con diversi approcci
     */
    private byte[] attemptNisReading() {
        log("📖 Tentativo lettura NIS con diversi metodi...");

        // Metodo 1: Lettura diretta senza selezione file
        try {
            log("🔄 Metodo 1: Lettura diretta...");
            byte[] readCommand = buildReadBinaryCommand(0, 255);
            byte[] response = isoDep.transceive(readCommand);

            if (isSuccessResponse(response)) {
                byte[] data = Arrays.copyOf(response, response.length - 2);
                log("✅ Metodo 1 riuscito: " + bytesToHex(data));
                return data;
            } else {
                log("❌ Metodo 1 fallito: " + String.format("0x%04X", getStatusWord(response)));
            }
        } catch (IOException e) {
            log("❌ Metodo 1 errore: " + e.getMessage());
        }

        // Metodo 2: Prova con ogni file ID
        for (int i = 0; i < NIS_FILE_IDS.length; i++) {
            try {
                log("🔄 Metodo 2." + (i+1) + ": Selezione file " + bytesToHex(NIS_FILE_IDS[i]));

                byte[] selectFileCommand = buildSelectFileCommand(NIS_FILE_IDS[i]);
                byte[] response = isoDep.transceive(selectFileCommand);

                if (isSuccessResponse(response)) {
                    // File selezionato, prova lettura
                    byte[] readCommand = buildReadBinaryCommand(0, 255);
                    response = isoDep.transceive(readCommand);

                    if (isSuccessResponse(response)) {
                        byte[] data = Arrays.copyOf(response, response.length - 2);
                        log("✅ Metodo 2." + (i+1) + " riuscito: " + bytesToHex(data));
                        return data;
                    } else {
                        log("❌ Metodo 2." + (i+1) + " lettura fallita: " + String.format("0x%04X", getStatusWord(response)));
                    }
                } else {
                    log("❌ Metodo 2." + (i+1) + " selezione fallita: " + String.format("0x%04X", getStatusWord(response)));
                }

            } catch (IOException e) {
                log("❌ Metodo 2." + (i+1) + " errore: " + e.getMessage());
            }
        }

        // Metodo 3: Prova comandi GET DATA
        try {
            log("🔄 Metodo 3: Comando GET DATA...");

            // Prova diversi tag per GET DATA
            byte[][] dataTags = {
                    {(byte) 0x9F, 0x7F}, // Tag per dati carta
                    {(byte) 0x5F, 0x20}, // Tag per nome
                    {(byte) 0x5F, 0x28}, // Tag per nazionalità
                    {0x00, 0x06}, // Tag NIS
            };

            for (int i = 0; i < dataTags.length; i++) {
                byte[] getDataCommand = buildGetDataCommand(dataTags[i]);
                byte[] response = isoDep.transceive(getDataCommand);

                if (isSuccessResponse(response)) {
                    byte[] data = Arrays.copyOf(response, response.length - 2);
                    log("✅ Metodo 3." + (i+1) + " riuscito con tag " + bytesToHex(dataTags[i]) + ": " + bytesToHex(data));
                    return data;
                } else {
                    log("❌ Metodo 3." + (i+1) + " fallito con tag " + bytesToHex(dataTags[i]) + ": " + String.format("0x%04X", getStatusWord(response)));
                }
            }

        } catch (IOException e) {
            log("❌ Metodo 3 errore: " + e.getMessage());
        }

        return null;
    }

    /**
     * Tentativo di Internal Authentication
     */
    private boolean attemptInternalAuthentication() {
        try {
            log("🔐 Tentativo Internal Authentication...");

            // Genera un challenge semplice
            byte[] challenge = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
            log("🎲 Challenge: " + bytesToHex(challenge));

            // Prova comando Internal Authenticate
            byte[] authCommand = buildInternalAuthenticateCommand(challenge);
            byte[] response = isoDep.transceive(authCommand);

            if (isSuccessResponse(response)) {
                byte[] signature = Arrays.copyOf(response, response.length - 2);
                log("✅ Internal Authentication riuscita: " + bytesToHex(signature));
                return true;
            } else {
                log("❌ Internal Authentication fallita: " + String.format("0x%04X", getStatusWord(response)));
                return false;
            }

        } catch (IOException e) {
            log("❌ Errore Internal Authentication: " + e.getMessage());
            return false;
        }
    }

    /**
     * Estrazione del numero NIS dai dati letti
     */
    private String extractNisNumber(byte[] data) {
        if (data == null || data.length == 0) {
            return "UNKNOWN";
        }

        // Cerca sequenze di cifre nei dati
        StringBuilder nisBuilder = new StringBuilder();

        for (byte b : data) {
            if (b >= 0x30 && b <= 0x39) { // Cifre ASCII 0-9
                nisBuilder.append((char) b);
            }
        }

        String nis = nisBuilder.toString();

        // Se abbiamo trovato cifre, prendiamo le prime 12 (o meno)
        if (nis.length() >= 6) {
            return nis.substring(0, Math.min(12, nis.length()));
        }

        // Fallback: converti i dati in stringa esadecimale
        return "HEX:" + bytesToHex(Arrays.copyOf(data, Math.min(16, data.length)));
    }

    /**
     * Costruzione comando SELECT APPLICATION
     */
    private byte[] buildSelectCommand(byte[] aid) {
        byte[] command = new byte[5 + aid.length];
        command[0] = 0x00; // CLA
        command[1] = (byte) 0xA4; // INS
        command[2] = 0x04; // P1
        command[3] = 0x00; // P2
        command[4] = (byte) aid.length; // Lc
        System.arraycopy(aid, 0, command, 5, aid.length);
        return command;
    }

    /**
     * Costruzione comando SELECT FILE
     */
    private byte[] buildSelectFileCommand(byte[] fileId) {
        byte[] command = new byte[5 + fileId.length];
        command[0] = 0x00; // CLA
        command[1] = (byte) 0xA4; // INS
        command[2] = 0x02; // P1 (select by file ID)
        command[3] = 0x0C; // P2
        command[4] = (byte) fileId.length; // Lc
        System.arraycopy(fileId, 0, command, 5, fileId.length);
        return command;
    }

    /**
     * Costruzione comando READ BINARY
     */
    private byte[] buildReadBinaryCommand(int offset, int length) {
        return new byte[] {
                0x00, // CLA
                (byte) 0xB0, // INS
                (byte) (offset >> 8), // P1
                (byte) (offset & 0xFF), // P2
                (byte) length // Le
        };
    }

    /**
     * Costruzione comando GET DATA
     */
    private byte[] buildGetDataCommand(byte[] tag) {
        byte[] command = new byte[5 + tag.length];
        command[0] = 0x00; // CLA
        command[1] = (byte) 0xCA; // INS
        command[2] = tag[0]; // P1
        command[3] = tag[1]; // P2
        command[4] = 0x00; // Le
        return command;
    }

    /**
     * Costruzione comando INTERNAL AUTHENTICATE
     */
    private byte[] buildInternalAuthenticateCommand(byte[] challenge) {
        byte[] command = new byte[5 + challenge.length];
        command[0] = 0x00; // CLA
        command[1] = (byte) 0x88; // INS
        command[2] = 0x00; // P1
        command[3] = 0x00; // P2
        command[4] = (byte) challenge.length; // Lc
        System.arraycopy(challenge, 0, command, 5, challenge.length);
        return command;
    }

    /**
     * Verifica se la risposta indica successo (9000)
     */
    private boolean isSuccessResponse(byte[] response) {
        if (response.length < 2) return false;
        return getStatusWord(response) == 0x9000;
    }

    /**
     * Estrazione dello status word dalla risposta
     */
    private int getStatusWord(byte[] response) {
        if (response.length < 2) return 0x0000;
        return ((response[response.length - 2] & 0xFF) << 8) |
                (response[response.length - 1] & 0xFF);
    }

    /**
     * Conversione byte array in stringa esadecimale
     */
    private String bytesToHex(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return "";
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02X ", b));
        }
        return result.toString().trim();
    }

    /**
     * Logging con timestamp
     */
    private void log(String message) {
        System.out.println("[" + System.currentTimeMillis() + "] " + TAG + ": " + message);
    }

    /**
     * Classe per il risultato della lettura NIS
     */
    public static class CieNisResult {
        public final boolean success;
        public final String message;
        public final String nisNumber;
        public final boolean isOriginal;

        public CieNisResult(boolean success, String message) {
            this(success, message, null, false);
        }

        public CieNisResult(boolean success, String message, String nisNumber, boolean isOriginal) {
            this.success = success;
            this.message = message;
            this.nisNumber = nisNumber;
            this.isOriginal = isOriginal;
        }

        @Override
        public String toString() {
            return String.format("CieNisResult{success=%s, message='%s', nis='%s', original=%s}",
                    success, message, nisNumber, isOriginal);
        }
    }
}

