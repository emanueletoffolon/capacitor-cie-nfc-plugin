package com.yourcompany.plugins.cienfcplugin;

/**
 * Classe per rappresentare i dati estratti dalla CIE
 */
public class CieData {

    // Dati anagrafici base
    private String nome;
    private String cognome;
    private String codiceFiscale;
    private String dataNascita; // YYYY-MM-DD
    private String luogoNascita;
    private String sesso; // M/F

    // Dati documento
    private String numeroDocumento;
    private String dataRilascio; // YYYY-MM-DD
    private String dataScadenza; // YYYY-MM-DD
    private String comuneRilascio;
    private String issuerCountry;

    // Dati opzionali (richiedono CAN)
    private String fotografia; // Base64 encoded JPEG
    private IndirizzoResidenza indirizzoResidenza;

    // Metadati lettura
    private String accessLevel; // "basic" o "advanced"
    private long readTimestamp;
    private String nfcSessionId;
    private long readingTime; // millisecondi
    private String authMethod; // "CAN" o "BAC"

    // Dati tecnici
    private String chipSerialNumber;
    private String documentVersion;

    // Costruttore
    public CieData() {
        this.issuerCountry = "ITA";
        this.documentVersion = "3.0";
        this.readTimestamp = System.currentTimeMillis();
    }

    // Getters e Setters
    public String getNome() { return nome; }
    public void setNome(String nome) { this.nome = nome; }

    public String getCognome() { return cognome; }
    public void setCognome(String cognome) { this.cognome = cognome; }

    public String getCodiceFiscale() { return codiceFiscale; }
    public void setCodiceFiscale(String codiceFiscale) { this.codiceFiscale = codiceFiscale; }

    public String getDataNascita() { return dataNascita; }
    public void setDataNascita(String dataNascita) { this.dataNascita = dataNascita; }

    public String getLuogoNascita() { return luogoNascita; }
    public void setLuogoNascita(String luogoNascita) { this.luogoNascita = luogoNascita; }

    public String getSesso() { return sesso; }
    public void setSesso(String sesso) { this.sesso = sesso; }

    public String getNumeroDocumento() { return numeroDocumento; }
    public void setNumeroDocumento(String numeroDocumento) { this.numeroDocumento = numeroDocumento; }

    public String getDataRilascio() { return dataRilascio; }
    public void setDataRilascio(String dataRilascio) { this.dataRilascio = dataRilascio; }

    public String getDataScadenza() { return dataScadenza; }
    public void setDataScadenza(String dataScadenza) { this.dataScadenza = dataScadenza; }

    public String getComuneRilascio() { return comuneRilascio; }
    public void setComuneRilascio(String comuneRilascio) { this.comuneRilascio = comuneRilascio; }

    public String getIssuerCountry() { return issuerCountry; }
    public void setIssuerCountry(String issuerCountry) { this.issuerCountry = issuerCountry; }

    public String getFotografia() { return fotografia; }
    public void setFotografia(String fotografia) { this.fotografia = fotografia; }

    public IndirizzoResidenza getIndirizzoResidenza() { return indirizzoResidenza; }
    public void setIndirizzoResidenza(IndirizzoResidenza indirizzoResidenza) {
        this.indirizzoResidenza = indirizzoResidenza;
    }

    public String getAccessLevel() { return accessLevel; }
    public void setAccessLevel(String accessLevel) { this.accessLevel = accessLevel; }

    public long getReadTimestamp() { return readTimestamp; }
    public void setReadTimestamp(long readTimestamp) { this.readTimestamp = readTimestamp; }

    public String getNfcSessionId() { return nfcSessionId; }
    public void setNfcSessionId(String nfcSessionId) { this.nfcSessionId = nfcSessionId; }

    public long getReadingTime() { return readingTime; }
    public void setReadingTime(long readingTime) { this.readingTime = readingTime; }

    public String getAuthMethod() { return authMethod; }
    public void setAuthMethod(String authMethod) { this.authMethod = authMethod; }

    public String getChipSerialNumber() { return chipSerialNumber; }
    public void setChipSerialNumber(String chipSerialNumber) { this.chipSerialNumber = chipSerialNumber; }

    public String getDocumentVersion() { return documentVersion; }
    public void setDocumentVersion(String documentVersion) { this.documentVersion = documentVersion; }

    /**
     * Classe interna per rappresentare l'indirizzo di residenza
     */
    public static class IndirizzoResidenza {
        private String via;
        private String civico;
        private String cap;
        private String comune;
        private String provincia;

        public String getVia() { return via; }
        public void setVia(String via) { this.via = via; }

        public String getCivico() { return civico; }
        public void setCivico(String civico) { this.civico = civico; }

        public String getCap() { return cap; }
        public void setCap(String cap) { this.cap = cap; }

        public String getComune() { return comune; }
        public void setComune(String comune) { this.comune = comune; }

        public String getProvincia() { return provincia; }
        public void setProvincia(String provincia) { this.provincia = provincia; }

        @Override
        public String toString() {
            return via + " " + civico + ", " + cap + " " + comune + " (" + provincia + ")";
        }
    }

    /**
     * Valida i dati base della CIE
     */
    public boolean isValid() {
        return nome != null && !nome.isEmpty() &&
                cognome != null && !cognome.isEmpty() &&
                codiceFiscale != null && codiceFiscale.length() == 16 &&
                numeroDocumento != null && !numeroDocumento.isEmpty();
    }

    /**
     * Restituisce il nome completo
     */
    public String getNomeCompleto() {
        return (nome != null ? nome : "") + " " + (cognome != null ? cognome : "");
    }

    @Override
    public String toString() {
        return "CieData{" +
                "nome='" + nome + '\'' +
                ", cognome='" + cognome + '\'' +
                ", codiceFiscale='" + codiceFiscale + '\'' +
                ", numeroDocumento='" + numeroDocumento + '\'' +
                ", accessLevel='" + accessLevel + '\'' +
                ", authMethod='" + authMethod + '\'' +
                '}';
    }
}

