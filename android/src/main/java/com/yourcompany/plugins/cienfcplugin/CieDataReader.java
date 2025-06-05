package com.yourcompany.plugins.cienfcplugin;

import android.nfc.tech.IsoDep;
import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Lettore per estrarre i dati dalla CIE autenticata
 */
public class CieDataReader {

    private static final String TAG = "CieDataReader";

    // File identifiers per i dati della CIE
    private static final byte[] EF_DG1 = {0x61, 0x01}; // MRZ data
    private static final byte[] EF_DG2 = {0x61, 0x02}; // Photo
    private static final byte[] EF_DG11 = {0x61, 0x0B}; // Additional personal data
    private static final byte[] EF_DG12 = {0x61, 0x0C}; // Additional document data

    /**
     * Legge i dati base dalla CIE
     */
    public CieData readBasicData(IsoDep isoDep, CieReader.CieReadCallback callback) throws Exception {
        Log.d(TAG, "Lettura dati base CIE");

        CieData cieData = new CieData();

        // Legge DG1 (MRZ - dati base del documento)
        callback.onProgress("Lettura dati documento...", 65);
        byte[] dg1Data = readDataGroup(isoDep, EF_DG1);
        if (dg1Data != null) {
            parseDG1(dg1Data, cieData);
        }

        // Legge DG11 (dati personali aggiuntivi)
        callback.onProgress("Lettura dati personali...", 70);
        byte[] dg11Data = readDataGroup(isoDep, EF_DG11);
        if (dg11Data != null) {
            parseDG11(dg11Data, cieData);
        }

        // Legge DG12 (dati documento aggiuntivi)
        callback.onProgress("Lettura dati documento aggiuntivi...", 75);
        byte[] dg12Data = readDataGroup(isoDep, EF_DG12);
        if (dg12Data != null) {
            parseDG12(dg12Data, cieData);
        }

        // Imposta livello di accesso
        cieData.setAccessLevel("basic");

        Log.d(TAG, "Dati base letti: " + cieData.toString());
        return cieData;
    }

    /**
     * Legge la fotografia dalla CIE
     */
    public String readPhoto(IsoDep isoDep) throws Exception {
        Log.d(TAG, "Lettura fotografia");

        byte[] dg2Data = readDataGroup(isoDep, EF_DG2);
        if (dg2Data == null) {
            Log.w(TAG, "DG2 non disponibile");
            return null;
        }

        // Estrae l'immagine JPEG dal DG2
        byte[] jpegData = extractJpegFromDG2(dg2Data);
        if (jpegData != null) {
            return Base64.encodeToString(jpegData, Base64.DEFAULT);
        }

        return null;
    }

    /**
     * Legge l'indirizzo di residenza dalla CIE
     */
    public CieData.IndirizzoResidenza readAddress(IsoDep isoDep) throws Exception {
        Log.d(TAG, "Lettura indirizzo residenza");

        // L'indirizzo potrebbe essere in DG11 o in un file separato
        // Per ora implementiamo una versione base
        return null; // TODO: implementare lettura indirizzo specifico
    }

    /**
     * Legge un Data Group specifico
     */
    private byte[] readDataGroup(IsoDep isoDep, byte[] fileId) throws Exception {
        // SELECT FILE
        byte[] selectCmd = {
            (byte) 0x00, (byte) 0xA4, (byte) 0x02, (byte) 0x0C,
            (byte) fileId.length
        };
        byte[] fullSelectCmd = new byte[selectCmd.length + fileId.length];
        System.arraycopy(selectCmd, 0, fullSelectCmd, 0, selectCmd.length);
        System.arraycopy(fileId, 0, fullSelectCmd, selectCmd.length, fileId.length);

        Log.d(TAG, "SELECT FILE: " + bytesToHex(fullSelectCmd));

        byte[] response = isoDep.transceive(fullSelectCmd);
        Log.d(TAG, "SELECT response: " + bytesToHex(response));

        if (!isSuccessResponse(response)) {
            Log.w(TAG, "SELECT FILE fallito per: " + bytesToHex(fileId));
            return null;
        }

        // READ BINARY - legge tutto il file
        return readBinaryFile(isoDep);
    }

    /**
     * Legge un file binario completamente
     */
    private byte[] readBinaryFile(IsoDep isoDep) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int offset = 0;
        int maxLength = 200; // Legge al massimo 200 byte per volta

        while (true) {
            byte[] readCmd = {
                (byte) 0x00, (byte) 0xB0,
                (byte) ((offset >> 8) & 0xFF), (byte) (offset & 0xFF),
                (byte) maxLength
            };

            byte[] response = isoDep.transceive(readCmd);

            if (!isSuccessResponse(response)) {
                if (getStatusWord(response) == 0x6B00) {
                    // Wrong parameters - fine del file
                    break;
                } else {
                    Log.w(TAG, "READ BINARY fallito, status: " +
                          String.format("0x%04X", getStatusWord(response)));
                    break;
                }
            }

            // Rimuove status word e aggiunge i dati
            byte[] data = Arrays.copyOf(response, response.length - 2);
            baos.write(data);

            if (data.length < maxLength) {
                // Fine del file raggiunta
                break;
            }

            offset += data.length;
        }

        return baos.toByteArray();
    }

    /**
     * Analizza i dati DG1 (MRZ)
     */
    private void parseDG1(byte[] data, CieData cieData) {
        Log.d(TAG, "Parsing DG1: " + bytesToHex(data));

        try {
            // Il DG1 contiene i dati MRZ in formato ASCII
            String mrzData = new String(data, StandardCharsets.UTF_8);

            // Parser base per MRZ italiano
            // Formato esempio: IDITA[DocumentNumber]<<<<<<<<<
            //                  [DateOfBirth][Sex][DateOfExpiry]ITA[Names]<<<

            String[] lines = mrzData.split("\n");
            if (lines.length >= 2) {
                String line1 = lines[0];
                String line2 = lines[1];

                // Estrae numero documento dalla prima riga
                if (line1.length() >= 14) {
                    String docNumber = line1.substring(5, 14).replace("<", "").trim();
                    cieData.setNumeroDocumento(docNumber);
                }

                // Estrae dati dalla seconda riga
                if (line2.length() >= 30) {
                    // Data di nascita (posizioni 0-5)
                    String birthDate = line2.substring(0, 6);
                    cieData.setDataNascita(formatDate(birthDate));

                    // Sesso (posizione 6)
                    String sex = line2.substring(6, 7);
                    cieData.setSesso(sex);

                    // Data di scadenza (posizioni 7-12)
                    String expiryDate = line2.substring(7, 13);
                    cieData.setDataScadenza(formatDate(expiryDate));

                    // Nomi (dal carattere 15 in poi)
                    if (line2.length() > 15) {
                        String names = line2.substring(15).replace("<", " ").trim();
                        parseNames(names, cieData);
                    }
                }
            }

        } catch (Exception e) {
            Log.e(TAG, "Errore parsing DG1", e);
        }
    }

    /**
     * Analizza i dati DG11 (dati personali aggiuntivi)
     */
    private void parseDG11(byte[] data, CieData cieData) {
        Log.d(TAG, "Parsing DG11: " + bytesToHex(data));

        try {
            // DG11 contiene dati aggiuntivi come codice fiscale, luogo di nascita, ecc.
            String personalData = new String(data, StandardCharsets.UTF_8);

            // Parser base - implementazione da completare
            // Per ora estrae solo il codice fiscale se presente

            Log.d(TAG, "Dati personali DG11: " + personalData);

        } catch (Exception e) {
            Log.e(TAG, "Errore parsing DG11", e);
        }
    }

    /**
     * Analizza i dati DG12 (dati documento aggiuntivi)
     */
    private void parseDG12(byte[] data, CieData cieData) {
        Log.d(TAG, "Parsing DG12: " + bytesToHex(data));

        try {
            // DG12 contiene dati aggiuntivi del documento
            String docData = new String(data, StandardCharsets.UTF_8);

            Log.d(TAG, "Dati documento DG12: " + docData);

        } catch (Exception e) {
            Log.e(TAG, "Errore parsing DG12", e);
        }
    }

    /**
     * Estrae l'immagine JPEG dal DG2
     */
    private byte[] extractJpegFromDG2(byte[] dg2Data) {
        // Cerca la signature JPEG (FF D8 FF)
        for (int i = 0; i < dg2Data.length - 3; i++) {
            if (dg2Data[i] == (byte) 0xFF &&
                dg2Data[i + 1] == (byte) 0xD8 &&
                dg2Data[i + 2] == (byte) 0xFF) {

                // Trova la fine del JPEG (FF D9)
                for (int j = i + 3; j < dg2Data.length - 1; j++) {
                    if (dg2Data[j] == (byte) 0xFF && dg2Data[j + 1] == (byte) 0xD9) {
                        return Arrays.copyOfRange(dg2Data, i, j + 2);
                    }
                }
            }
        }
        return null;
    }

    /**
     * Formatta una data da YYMMDD a YYYY-MM-DD
     */
    private String formatDate(String yymmdd) {
        if (yymmdd == null || yymmdd.length() != 6) {
            return null;
        }

        try {
            int yy = Integer.parseInt(yymmdd.substring(0, 2));
            int mm = Integer.parseInt(yymmdd.substring(2, 4));
            int dd = Integer.parseInt(yymmdd.substring(4, 6));

            // Assume che anni < 50 siano 20xx, altrimenti 19xx
            int yyyy = yy < 50 ? 2000 + yy : 1900 + yy;

            return String.format("%04d-%02d-%02d", yyyy, mm, dd);
        } catch (NumberFormatException e) {
            Log.e(TAG, "Errore formato data: " + yymmdd, e);
            return null;
        }
    }

    /**
     * Analizza il campo nomi dal MRZ
     */
    private void parseNames(String names, CieData cieData) {
        String[] parts = names.trim().split("\\s+");
        if (parts.length >= 2) {
            cieData.setCognome(parts[0]);
            cieData.setNome(parts[1]);
        } else if (parts.length == 1) {
            cieData.setCognome(parts[0]);
        }
    }

    /**
     * Verifica se la risposta APDU indica successo
     */
    private boolean isSuccessResponse(byte[] response) {
        return response != null && response.length >= 2 &&
               getStatusWord(response) == 0x9000;
    }

    /**
     * Estrae lo status word dalla risposta
     */
    private int getStatusWord(byte[] response) {
        if (response == null || response.length < 2) {
            return 0x0000;
        }
        return ((response[response.length - 2] & 0xFF) << 8) |
               (response[response.length - 1] & 0xFF);
    }

    /**
     * Converte array di byte in stringa esadecimale
     */
    private String bytesToHex(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02X ", b));
        }
        return result.toString().trim();
    }
}