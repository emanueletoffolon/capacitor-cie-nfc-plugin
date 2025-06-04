# Esempio di Utilizzo del Plugin CIE NFC

Questo esempio mostra come integrare e utilizzare il plugin `capacitor-cie-nfc-plugin` in un'app Ionic.

## Installazione

```bash
npm install capacitor-cie-nfc-plugin
npx cap sync
```

## Configurazione

### Android

Aggiungi i permessi in `android/app/src/main/AndroidManifest.xml`:

```xml
<uses-permission android:name="android.permission.NFC" />
<uses-feature android:name="android.hardware.nfc" android:required="true" />
```

## Implementazione

### Service Angular

```typescript
// src/app/core/services/cie-nfc.service.ts
import { Injectable } from '@angular/core';
import { CieNfcPlugin, CieData, ReadCieOptions } from 'capacitor-cie-nfc-plugin';
import { BehaviorSubject, Observable } from 'rxjs';

export interface CieReadState {
  isReading: boolean;
  progress: number;
  step: string;
  error?: string;
}

@Injectable({
  providedIn: 'root'
})
export class CieNfcService {

  private readStateSubject = new BehaviorSubject<CieReadState>({
    isReading: false,
    progress: 0,
    step: ''
  });

  public readState$ = this.readStateSubject.asObservable();

  constructor() {
    this.setupEventListeners();
  }

  async isNfcAvailable(): Promise<boolean> {
    try {
      const result = await CieNfcPlugin.isNfcAvailable();
      return result.available;
    } catch (error) {
      console.error('Errore verifica NFC:', error);
      return false;
    }
  }

  async enableNfc(): Promise<void> {
    try {
      await CieNfcPlugin.enableNfc();
    } catch (error) {
      console.error('Errore abilitazione NFC:', error);
      throw error;
    }
  }

  async readCie(can: string, options: Partial<ReadCieOptions> = {}): Promise<CieData> {
    try {
      this.updateReadState({ isReading: true, progress: 0, step: 'Inizializzazione...' });

      const readOptions: ReadCieOptions = {
        can,
        readPhoto: options.readPhoto || false,
        readAddress: options.readAddress || false,
        timeout: options.timeout || 30000,
        validateChecksum: options.validateChecksum !== false
      };

      const result = await CieNfcPlugin.readCie(readOptions);

      if (result.success && result.data) {
        this.updateReadState({ isReading: false, progress: 100, step: 'Completato' });
        return result.data;
      } else {
        this.updateReadState({ 
          isReading: false, 
          progress: 0, 
          step: 'Errore', 
          error: result.error 
        });
        throw new Error(result.error || 'Errore sconosciuto durante lettura CIE');
      }

    } catch (error) {
      this.updateReadState({ 
        isReading: false, 
        progress: 0, 
        step: 'Errore', 
        error: error.message 
      });
      throw error;
    }
  }

  async startSession(): Promise<void> {
    await CieNfcPlugin.startNfcSession();
  }

  async stopSession(): Promise<void> {
    await CieNfcPlugin.stopNfcSession();
  }

  private setupEventListeners(): void {
    // Listener per progresso lettura
    CieNfcPlugin.addListener('nfcProgress', (event) => {
      this.updateReadState({
        isReading: true,
        progress: event.data.progress,
        step: event.data.step
      });
    });

    // Listener per tag rilevato
    CieNfcPlugin.addListener('nfcTagDetected', (event) => {
      console.log('CIE rilevata:', event.data);
      this.updateReadState({
        isReading: true,
        progress: 25,
        step: 'CIE rilevata'
      });
    });

    // Listener per errori
    CieNfcPlugin.addListener('nfcError', (event) => {
      console.error('Errore NFC:', event.data);
      this.updateReadState({
        isReading: false,
        progress: 0,
        step: 'Errore',
        error: event.data.errorMessage
      });
    });
  }

  private updateReadState(newState: Partial<CieReadState>): void {
    const currentState = this.readStateSubject.value;
    this.readStateSubject.next({ ...currentState, ...newState });
  }

  ngOnDestroy(): void {
    CieNfcPlugin.removeAllListeners();
  }
}
```

### Componente di Lettura

```typescript
// src/app/pages/cie-reader/cie-reader.page.ts
import { Component, OnInit, OnDestroy } from '@angular/core';
import { AlertController, LoadingController, ToastController } from '@ionic/angular';
import { CieNfcService, CieReadState } from '../../core/services/cie-nfc.service';
import { CieData } from 'capacitor-cie-nfc-plugin';
import { Subscription } from 'rxjs';

@Component({
  selector: 'app-cie-reader',
  templateUrl: './cie-reader.page.html',
  styleUrls: ['./cie-reader.page.scss'],
})
export class CieReaderPage implements OnInit, OnDestroy {

  can: string = '';
  readPhoto: boolean = false;
  readAddress: boolean = false;
  nfcAvailable: boolean = false;
  cieData: CieData | null = null;
  readState: CieReadState = { isReading: false, progress: 0, step: '' };

  private readStateSubscription: Subscription;

  constructor(
    private cieNfcService: CieNfcService,
    private alertController: AlertController,
    private loadingController: LoadingController,
    private toastController: ToastController
  ) {}

  async ngOnInit() {
    await this.checkNfcAvailability();
    
    this.readStateSubscription = this.cieNfcService.readState$.subscribe(
      state => this.readState = state
    );
  }

  ngOnDestroy() {
    if (this.readStateSubscription) {
      this.readStateSubscription.unsubscribe();
    }
  }

  async checkNfcAvailability() {
    try {
      this.nfcAvailable = await this.cieNfcService.isNfcAvailable();
      
      if (!this.nfcAvailable) {
        await this.showNfcNotAvailableAlert();
      }
    } catch (error) {
      console.error('Errore verifica NFC:', error);
      await this.showErrorToast('Errore durante verifica NFC');
    }
  }

  async enableNfc() {
    try {
      await this.cieNfcService.enableNfc();
      await this.checkNfcAvailability();
    } catch (error) {
      console.error('Errore abilitazione NFC:', error);
      await this.showErrorToast('Impossibile abilitare NFC');
    }
  }

  async readCie() {
    if (!this.isValidCan()) {
      await this.showErrorToast('CAN deve essere di 8 cifre numeriche');
      return;
    }

    if (!this.nfcAvailable) {
      await this.showErrorToast('NFC non disponibile');
      return;
    }

    try {
      const loading = await this.loadingController.create({
        message: 'Avvicina la CIE al dispositivo...',
        duration: 30000
      });
      await loading.present();

      this.cieData = await this.cieNfcService.readCie(this.can, {
        readPhoto: this.readPhoto,
        readAddress: this.readAddress
      });

      await loading.dismiss();
      await this.showSuccessToast('Lettura CIE completata con successo');

    } catch (error) {
      await this.loadingController.dismiss();
      console.error('Errore lettura CIE:', error);
      await this.showErrorAlert('Errore Lettura CIE', error.message);
    }
  }

  private isValidCan(): boolean {
    return this.can && this.can.length === 8 && /^\d{8}$/.test(this.can);
  }

  private async showNfcNotAvailableAlert() {
    const alert = await this.alertController.create({
      header: 'NFC Non Disponibile',
      message: 'NFC non è disponibile o è disabilitato. Abilita NFC nelle impostazioni.',
      buttons: [
        {
          text: 'Annulla',
          role: 'cancel'
        },
        {
          text: 'Abilita NFC',
          handler: () => this.enableNfc()
        }
      ]
    });
    await alert.present();
  }

  private async showErrorAlert(header: string, message: string) {
    const alert = await this.alertController.create({
      header,
      message,
      buttons: ['OK']
    });
    await alert.present();
  }

  private async showErrorToast(message: string) {
    const toast = await this.toastController.create({
      message,
      duration: 3000,
      color: 'danger',
      position: 'bottom'
    });
    await toast.present();
  }

  private async showSuccessToast(message: string) {
    const toast = await this.toastController.create({
      message,
      duration: 3000,
      color: 'success',
      position: 'bottom'
    });
    await toast.present();
  }

  clearData() {
    this.cieData = null;
    this.can = '';
  }
}
```

### Template HTML

```html
<!-- src/app/pages/cie-reader/cie-reader.page.html -->
<ion-header [translucent]="true">
  <ion-toolbar>
    <ion-title>Lettore CIE</ion-title>
  </ion-toolbar>
</ion-header>

<ion-content [fullscreen]="true">
  <div class="container">
    
    <!-- Status NFC -->
    <ion-card>
      <ion-card-header>
        <ion-card-title>
          <ion-icon [name]="nfcAvailable ? 'checkmark-circle' : 'close-circle'" 
                    [color]="nfcAvailable ? 'success' : 'danger'"></ion-icon>
          Status NFC
        </ion-card-title>
      </ion-card-header>
      <ion-card-content>
        <p>{{ nfcAvailable ? 'NFC attivo e disponibile' : 'NFC non disponibile' }}</p>
        <ion-button *ngIf="!nfcAvailable" 
                    (click)="enableNfc()" 
                    fill="outline" 
                    color="primary">
          Abilita NFC
        </ion-button>
      </ion-card-content>
    </ion-card>

    <!-- Form di lettura -->
    <ion-card *ngIf="nfcAvailable">
      <ion-card-header>
        <ion-card-title>Lettura CIE</ion-card-title>
      </ion-card-header>
      <ion-card-content>
        
        <!-- Input CAN -->
        <ion-item>
          <ion-label position="stacked">CAN (8 cifre)</ion-label>
          <ion-input 
            [(ngModel)]="can" 
            type="number" 
            maxlength="8"
            placeholder="12345678">
          </ion-input>
        </ion-item>

        <!-- Opzioni lettura -->
        <ion-item>
          <ion-checkbox [(ngModel)]="readPhoto"></ion-checkbox>
          <ion-label class="ion-margin-start">Leggi fotografia</ion-label>
        </ion-item>

        <ion-item>
          <ion-checkbox [(ngModel)]="readAddress"></ion-checkbox>
          <ion-label class="ion-margin-start">Leggi indirizzo</ion-label>
        </ion-item>

        <!-- Pulsante lettura -->
        <ion-button 
          (click)="readCie()" 
          expand="block" 
          [disabled]="!isValidCan() || readState.isReading"
          class="ion-margin-top">
          <ion-icon name="card-outline" slot="start"></ion-icon>
          {{ readState.isReading ? 'Lettura in corso...' : 'Leggi CIE' }}
        </ion-button>

        <!-- Progress bar -->
        <div *ngIf="readState.isReading" class="progress-container">
          <ion-progress-bar [value]="readState.progress / 100"></ion-progress-bar>
          <p class="progress-text">{{ readState.step }} ({{ readState.progress }}%)</p>
        </div>

      </ion-card-content>
    </ion-card>

    <!-- Risultati lettura -->
    <ion-card *ngIf="cieData">
      <ion-card-header>
        <ion-card-title>
          <ion-icon name="person-circle" color="success"></ion-icon>
          Dati CIE
        </ion-card-title>
      </ion-card-header>
      <ion-card-content>
        
        <!-- Dati anagrafici -->
        <ion-list>
          <ion-item>
            <ion-label>
              <h3>Nome Completo</h3>
              <p>{{ cieData.nome }} {{ cieData.cognome }}</p>
            </ion-label>
          </ion-item>

          <ion-item>
            <ion-label>
              <h3>Codice Fiscale</h3>
              <p>{{ cieData.codiceFiscale }}</p>
            </ion-label>
          </ion-item>

          <ion-item>
            <ion-label>
              <h3>Data di Nascita</h3>
              <p>{{ cieData.dataNascita }}</p>
            </ion-label>
          </ion-item>

          <ion-item>
            <ion-label>
              <h3>Luogo di Nascita</h3>
              <p>{{ cieData.luogoNascita }}</p>
            </ion-label>
          </ion-item>

          <ion-item>
            <ion-label>
              <h3>Numero Documento</h3>
              <p>{{ cieData.numeroDocumento }}</p>
            </ion-label>
          </ion-item>

          <ion-item>
            <ion-label>
              <h3>Scadenza</h3>
              <p>{{ cieData.dataScadenza }}</p>
            </ion-label>
          </ion-item>

          <!-- Fotografia se disponibile -->
          <ion-item *ngIf="cieData.fotografia">
            <ion-label>
              <h3>Fotografia</h3>
              <img [src]="'data:image/jpeg;base64,' + cieData.fotografia" 
                   alt="Foto CIE" 
                   class="cie-photo">
            </ion-label>
          </ion-item>

          <!-- Indirizzo se disponibile -->
          <ion-item *ngIf="cieData.indirizzoResidenza">
            <ion-label>
              <h3>Indirizzo di Residenza</h3>
              <p>{{ cieData.indirizzoResidenza.via }} {{ cieData.indirizzoResidenza.civico }}</p>
              <p>{{ cieData.indirizzoResidenza.cap }} {{ cieData.indirizzoResidenza.comune }} ({{ cieData.indirizzoResidenza.provincia }})</p>
            </ion-label>
          </ion-item>
        </ion-list>

        <ion-button (click)="clearData()" 
                    fill="outline" 
                    color="medium" 
                    expand="block"
                    class="ion-margin-top">
          <ion-icon name="refresh" slot="start"></ion-icon>
          Nuova Lettura
        </ion-button>

      </ion-card-content>
    </ion-card>

  </div>
</ion-content>
```

### Stili CSS

```scss
// src/app/pages/cie-reader/cie-reader.page.scss
.container {
  padding: 16px;
  max-width: 600px;
  margin: 0 auto;
}

.progress-container {
  margin-top: 16px;
  
  .progress-text {
    text-align: center;
    margin-top: 8px;
    font-size: 0.9em;
    color: var(--ion-color-medium);
  }
}

.cie-photo {
  max-width: 120px;
  max-height: 160px;
  border-radius: 8px;
  margin-top: 8px;
}

ion-card {
  margin-bottom: 16px;
}

ion-item {
  --padding-start: 0;
  --inner-padding-end: 0;
}

ion-button {
  --border-radius: 8px;
}
```

## Note Importanti

1. **Permessi**: Assicurati che i permessi NFC siano configurati correttamente
2. **Testing**: Testa sempre su dispositivo fisico con CIE reale
3. **Sicurezza**: Non memorizzare mai il CAN o i dati sensibili
4. **UX**: Fornisci feedback chiaro durante il processo di lettura
5. **Errori**: Gestisci tutti i possibili errori NFC e di autenticazione

## Troubleshooting

- **NFC non funziona**: Verifica permessi e che NFC sia attivo
- **Autenticazione fallita**: Controlla che il CAN sia corretto
- **Timeout**: Aumenta il timeout o migliora il posizionamento della CIE
- **Dati mancanti**: Alcuni dati richiedono autenticazione CAN avanzata

