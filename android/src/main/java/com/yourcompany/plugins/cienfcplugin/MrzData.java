package com.yourcompany.plugins.cienfcplugin;

import android.util.Log;

public class MrzData {
    private static final String TAG = "MrzData";

    private String documentNumber;
    private String dateOfBirth;
    private String dateOfExpiry;

    public MrzData(String documentNumber, String dateOfBirth, String dateOfExpiry) {
        this.documentNumber = documentNumber;
        this.dateOfBirth = dateOfBirth;
        this.dateOfExpiry = dateOfExpiry;
    }

    /**
     * Restituisce il numero documento portato a 9 caratteri con padding '<'
     */
    private String getDocumentNumberPadded() {
        if (documentNumber == null) return "";
        String padded = documentNumber;
        if (padded.length() < 9) {
            StringBuilder sb = new StringBuilder(padded);
            while (sb.length() < 9) sb.append('<');
            padded = sb.toString();
        } else if (padded.length() > 9) {
            padded = padded.substring(0, 9);
        }
        return padded;
    }

    /**
     * Calcola il checksum ICAO 9303 per una stringa fornita
     */
    public static int calculateChecksum(String input) {
        final int[] weights = {7, 3, 1};
        final String chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ<";
        int sum = 0;
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            int v;
            if (c >= '0' && c <= '9') v = c - '0';
            else if (c >= 'A' && c <= 'Z') v = c - 'A' + 10;
            else if (c == '<') v = 0;
            else v = 0; // Altro trattato come 0 secondo specifica
            sum += v * weights[i % 3];
        }
        return sum % 10;
    }

    /**
     * Genera la stringa BAC secondo formato ICAO 9303 standard per CIE
     * Struttura: [NumeroDocumento9][Checksum][DataNascita6][Checksum][DataScadenza6][Checksum]
     */
    public String generateBacKey() {
        Log.d(TAG, "=== GENERAZIONE CHIAVE BAC FORMATO ICAO ===");

        // Padding a 9 caratteri con '<'
        String docPadded = getDocumentNumberPadded();

        int docChecksum = calculateChecksum(docPadded);
        int birthChecksum = calculateChecksum(dateOfBirth);
        int expiryChecksum = calculateChecksum(dateOfExpiry);

        Log.d(TAG, "Document: " + docPadded + " → checksum: " + docChecksum);
        Log.d(TAG, "Birth: " + dateOfBirth + " → checksum: " + birthChecksum);
        Log.d(TAG, "Expiry: " + dateOfExpiry + " → checksum: " + expiryChecksum);

        String builder =
                docPadded +
                docChecksum +
                dateOfBirth +
                birthChecksum +
                dateOfExpiry +
                expiryChecksum;

        Log.d(TAG, "Chiave BAC generata: " + builder + " (lunghezza: " + builder.length() + ")");

        return builder;
    }

    public boolean isValid() {
        return documentNumber != null && !documentNumber.isEmpty()
               && dateOfBirth != null && dateOfBirth.length() == 6
               && dateOfExpiry != null && dateOfExpiry.length() == 6;
    }

    @Override
    public String toString() {
        return "MrzData{" +
                "documentNumber='" + documentNumber + '\'' +
                ", dateOfBirth='" + dateOfBirth + '\'' +
                ", dateOfExpiry='" + dateOfExpiry + '\'' +
                '}';
    }
}