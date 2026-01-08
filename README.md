# Secure Document Exchange 

![Java](https://img.shields.io/badge/Java-17-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white)
![Spring Boot](https://img.shields.io/badge/Spring_Boot-3.2-6DB33F?style=for-the-badge&logo=spring&logoColor=white)
![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-4169E1?style=for-the-badge&logo=postgresql&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Security](https://img.shields.io/badge/OWASP-Top_10-red?style=for-the-badge&logo=security&logoColor=white)

**Progetto per il corso di Sicurezza delle Architetture Orientate ai Servizi**

*Università degli Studi di Bari Aldo Moro - C.so di Laurea in Sicurezza Informatica*

---

## Abstract

Il presente progetto implementa una piattaforma web per lo scambio sicuro di documenti basata sul paradigma architetturale **Zero Trust**. L'architettura proposta integra crittografia AES-256 con gestione effimera delle chiavi, scansione anti-malware in tempo reale mediante ClamAV, autenticazione centralizzata tramite Keycloak (OIDC/OAuth2), e controllo degli accessi basato su attributi dipartimentali. La soluzione affronta le principali vulnerabilità delle applicazioni web moderne (OWASP Top 10) implementando meccanismi di protezione contro attacchi BOLA/IDOR, XSS, Path Traversal e DoS.

---

## Indice

1. [Scenario e Obiettivi](#1-scenario-e-obiettivi)
2. [Architettura di Sicurezza](#2-architettura-di-sicurezza)
3. [Componente Backend](#3-componente-backend-spring-boot)
4. [Componente Frontend](#4-componente-frontend-react)
5. [Flussi di Comunicazione](#5-flussi-di-comunicazione)
6. [Componenti Infrastrutturali](#6-componenti-infrastrutturali)
7. [Meccanismi di Sicurezza](#7-meccanismi-di-sicurezza)
8. [Stack Tecnologico](#8-stack-tecnologico)
9. [Installazione e Configurazione](#9-installazione-e-configurazione)
10. [Utenti di Test](#10-utenti-di-test)
11. [Scenari di Verifica](#11-scenari-di-verifica)
12. [Troubleshooting](#12-troubleshooting)
13. [Note Tecniche](#13-note-tecniche)

---

## 1. Scenario e Obiettivi

**Secure Document Exchange** è un'applicazione web progettata per dimostrare l'applicazione pratica dei principi di sicurezza in ambienti potenzialmente ostili. A differenza dei tradizionali sistemi di archiviazione file, questa piattaforma opera secondo il modello **Zero Trust**: il server stesso è considerato non affidabile per la custodia dei dati in chiaro.

### Principi Architetturali

| Principio | Descrizione |
|-----------|-------------|
| **Zero Trust** | Il server gestisce esclusivamente dati crittografati senza mai memorizzare le chiavi di decifratura |
| **Verifica Continua** | Ogni richiesta è sottoposta ad autenticazione, autorizzazione e scansione per minacce |
| **Privilegio Minimo** | Gli utenti accedono unicamente ai dati del proprio dipartimento (protezione BOLA/IDOR) |

### Struttura del Progetto

```
secure-doc-exchange/
├── backend/                     # Applicazione Spring Boot
│   ├── src/main/java/com/secure/exchange/
│   │   ├── config/              # Configurazione sicurezza (JWT, CSP, Rate Limiting)
│   │   ├── controller/          # Endpoint REST (Documenti, Chat, Audit)
│   │   ├── model/               # Entità JPA (DocumentEntity, AuditLog)
│   │   ├── repository/          # Repository Spring Data
│   │   ├── service/             # Logica di business (Crittografia, Anti-Malware)
│   │   └── util/                # Utility crittografiche AES-GCM
│   ├── Dockerfile
│   └── pom.xml
├── frontend/                    # Applicazione React
│   ├── src/
│   │   ├── App.jsx              # Dashboard principale
│   │   ├── SecretChat.jsx       # Componente chat WebSocket
│   │   ├── api.js               # Configurazione Axios
│   │   └── index.css            # Stili globali
│   ├── Dockerfile
│   └── vite.config.js
├── keycloak-themes/             # Tema login personalizzato
│   └── darknet/
├── docker-compose.yml           # Orchestrazione infrastruttura
└── README.md
```

---

## 2. Architettura di Sicurezza

La seguente tabella illustra come ciascun requisito di sicurezza è stato implementato e verificato:

| Requisito | Implementazione | Metodo di Verifica |
|-----------|-----------------|-------------------|
| **Zero Trust Architecture** | Envelope Encryption AES-256: il server memorizza blob crittografati senza persistere le chiavi di decifratura, che sono effimere e consegnate esclusivamente al client | Dump del database rivela dati illeggibili |
| **Protezione Malware** | Scansione a due stadi: Apache Tika (verifica Magic Bytes) + ClamAV (scansione profonda) eseguita in memoria prima della crittografia | Upload del file EICAR genera rifiuto immediato |
| **Segregazione Dipartimentale** | Protezione BOLA: Spring Security impone `User.Group == Document.Group` | Utente HR riceve `403 Forbidden` accedendo a file IT |
| **Secret Chat** | WebSocket in memoria: messaggi instradati via broker STOMP senza persistenza su disco | Messaggi eliminati al riavvio del server |
| **Protezione DoS** | Rate Limiting con algoritmo Token Bucket (Bucket4j): 50 req/min per IP | Superamento soglia genera `429 Too Many Requests` |
| **Audit Trail** | Logging anti-manomissione: operazioni critiche registrate in tabella audit separata | Dashboard Admin mostra timestamp e principal |
| **Protezione XSS** | Content Security Policy (CSP): header HTTP rigidi (`script-src 'self'`) | Console browser conferma blocco script esterni |
| **Fail-Secure** | Scansione bloccante: se ClamAV non è disponibile, l'upload fallisce | Container ClamAV spento → upload rifiutato |
| **Integrità Log** | Logging lato server: tutte le operazioni registrate indipendentemente dal client | Richiesta cURL diretta genera audit log |
| **Sanitizzazione Input** | Path Traversal Protection: pulizia nomi file (`Paths.get().getFileName()`) | Upload di `../../shell.php` salva solo `shell.php` |
| **Sicurezza Protocollo** | HSTS e Strict CORS: forza HTTPS per 1 anno, rifiuta origini HTTP | Tentativi downgrade HTTP bloccati |
| **Test Automatizzati** | Unit Test JUnit 5: verifica correttezza crittografica AES-GCM | Esecuzione via `mvn test` |

---

## 3. Componente Backend (Spring Boot)

Il backend rappresenta il nucleo applicativo, espone API REST sicure sulla porta `8443` e gestisce l'intera logica di business.

### Architettura a Livelli

1. **Security Filter Chain**: intercetta ogni richiesta HTTP, validando la firma del token JWT tramite la chiave pubblica (JWK) esposta da Keycloak. Token mancanti o scaduti generano `401 Unauthorized` prima dell'elaborazione.

2. **Controller Layer**: i controller `ReviewController` e `DocumentController` verificano le autorizzazioni granulari mediante annotazioni `@PreAuthorize` (es. `hasRole('ADMIN')`, segregazione dipartimentale).

3. **Service Layer**: implementa la logica crittografica e di sicurezza:
   - **Elaborazione In-Memory**: i file vengono processati in stream di memoria, senza scrittura su disco
   - **Anti-Malware**: lo stream viene analizzato da ClamAV via TCP; in caso di errore di connessione, il sistema opera in modalità fail-secure
   - **Envelope Encryption**: generazione di chiave AES-256 casuale tramite `AesUtil`, cifratura del contenuto, restituzione della chiave all'utente con immediata eliminazione lato server

4. **Logging Asincrono**: ogni operazione emette un evento di audit scritto su database in thread separato (`@Async`), garantendo non-ripudiabilità senza impatto sulle performance.

---

## 4. Componente Frontend (React)

L'interfaccia utente è implementata come Single Page Application (SPA), architetturalmente separata dal backend.

### Caratteristiche di Sicurezza

1. **Gestione Stateless**: l'applicazione non mantiene stato permanente. Al caricamento, verifica tramite OIDC l'esistenza di una sessione SSO valida.

2. **Gestione Token**:
   - JWT mantenuto in memoria RAM (variabile JavaScript), non in LocalStorage/SessionStorage, per mitigare attacchi XSS persistenti
   - Refresh silenzioso tramite iframe invisibile che comunica con Keycloak utilizzando cookie `HttpOnly`

3. **Visualizzazione Dinamica**: analisi del payload JWT per determinare i contenuti visualizzabili:
   - `groups: ['/IT']` → visualizzazione esclusiva file IT
   - `roles: ['admin']` → accesso alla sezione Audit Log

4. **Decifratura Client-Initiated**: per il download, l'utente fornisce la chiave che viene trasmessa al server via HTTPS esclusivamente per l'operazione di decifratura.

---

## 5. Flussi di Comunicazione

### Flusso di Autenticazione (OIDC)

1. **Utente → Frontend**: click su "Access Gateway"
2. **Frontend → Keycloak**: reindirizzamento alla pagina di login (porta 8444)
3. **Keycloak → Utente**: verifica credenziali
4. **Keycloak → Frontend**: rilascio Authorization Code
5. **Frontend → Backend**: utilizzo del JWT per ogni richiesta API (`Authorization: Bearer <token>`)

### Flusso Dati Interni

| Comunicazione | Protocollo | Sicurezza |
|---------------|------------|-----------|
| Frontend ↔ Backend | HTTPS/TLS 1.3 | Porta 8443 |
| Backend → ClamAV | TCP | Porta 3310, stream di byte |
| Backend → PostgreSQL | JDBC + SSL | `sslmode=verify-ca` |
| Backend → Vault | HTTPS | Porta 8200, secrets injection |

---

## 6. Componenti Infrastrutturali

### PostgreSQL (Persistenza)

#### Tabella `documents`
| Attributo | Descrizione |
|-------|-------------|
| `id` | Identificativo univoco |
| `filename` | Nome file originale |
| `content_type` | Tipo MIME verificato da Tika |
| `owner_id` | ID utente Keycloak proprietario |
| `department_group` | Etichetta di sicurezza (`/IT`, `/HR`) |
| `encrypted_content` | Testo cifrato AES-256 (memorizzato come Large Object/OID) |

#### Tabella `audit_logs`
| Attributo | Descrizione |
|-------|-------------|
| `action` | Tipo operazione (`UPLOAD_FILE`, `DECRYPT_FILE`, `DETECT_MALWARE`) |
| `principal` | Username esecutore |
| `resource` | Risorsa coinvolta |
| `status` | Esito (`SUCCESS`, `FAILURE`) |
| `ip_address` | Indirizzo IP sorgente |
| `timestamp` | Timestamp operazione |

### Keycloak (Identity Provider)

- **Standard OIDC**: gestione centralizzata utenti con revoca accessi immediata alla scadenza del token
- **RBAC e Gruppi**: mappatura ruoli aziendali in JWT Claims standard

### HashiCorp Vault (Secrets Management)

- **Funzione**: creazione, rotazione e revoca delle credenziali database e certificati TLS
- **Zero Knowledge**: solo il "Secret Zero" iniziale richiede gestione manuale

---

## 7. Meccanismi di Sicurezza

### A. Zero Trust ed Envelope Encryption

- **Algoritmo**: AES-256 in modalità GCM (Galois/Counter Mode) per crittografia autenticata
- **Gestione Chiavi**: chiavi one-time generate dal backend e restituite esclusivamente all'utente; il server non persiste alcuna chiave
- **Dati a Riposo**: file crittografati prima della persistenza su disco

### B. Pipeline Anti-Malware

1. **Stadio 1 - Analisi Magic Bytes**: Apache Tika identifica il tipo MIME reale, prevenendo spoofing dell'estensione
2. **Stadio 2 - Scansione Profonda**: ClamAV analizza il flusso file in memoria prima della crittografia

### C. Sicurezza di Rete e Identità

| Meccanismo | Implementazione |
|------------|-----------------|
| Autenticazione | OIDC/OAuth2 via Keycloak, verifica stateless JWT |
| Rate Limiting | Token Bucket basato su IP (Bucket4j), 50 req/min |
| CSP | `frame-ancestors 'none'`, `script-src 'self' 'unsafe-inline'` |
| WebSocket Security | Validazione JWT in `ChannelInterceptor` al frame STOMP `CONNECT` |
| TLS/SSL | HTTPS completo su tutti i componenti |

### D. Secret Chat

Canale di comunicazione tattico progettato per la massima segretezza operativa.

- **Controllo Accessi (RBAC)**:
  - **Inizializzazione**: Privilegio esclusivo del gruppo `/IT` ("Hacker Mode"). L'utente genera una stanza protetta e ottiene un *Invite Token* univoco.
  - **Join**: Qualsiasi utente autenticato può accedere alla stanza se in possesso del token valido.
- **Ephemerality by Design**:
  - **Architettura Volatile**: I messaggi risiedono esclusivamente nella RAM Heap del server. Nessuna operazione di I/O su disco (no database, no file log).
  - **Kill-Switch**: Il riavvio del servizio backend provoca l'immediata distruzione crittografica di tutte le stanze e cronologie.
- **Sicurezza del Canale**:
  - **WebSocket Secure (WSS)**: Tunnel TLS 1.3 per la protezione in transito.
  - **Trust Authorities**: Il server appone timestamp autoritativi per prevenire attacchi di replay o manipolazione temporale.
- **Interfaccia**: UI stile "Terminale" ad alto contrasto per operazioni in ambienti a bassa visibilità.

### E. Refresh Silenzioso

Implementazione di refresh basato su cookie `HttpOnly/Secure` tramite iframe nascosto, evitando l'esposizione di Refresh Token persistenti.

### F. Hardening Avanzato

- **Path Traversal Sanitization**: conversione aggressiva dei nomi file (es. `../../etc/passwd` → `passwd`)
- **HSTS**: header `Strict-Transport-Security: max-age=31536000; includeSubDomains`

---

## 8. Stack Tecnologico

| Componente | Tecnologia | Funzione |
|------------|------------|----------|
| Backend | Java 17, Spring Boot 3.2 | Logica applicativa, API REST, WebSocket |
| Frontend | React 18, Vite | UX/UI |
| Sicurezza | Spring Security, OAuth2 | Autenticazione e autorizzazione |
| Identity Provider | Keycloak 23 | Gestione identità centralizzata |
| Database | PostgreSQL 15 | Persistenza dati e audit log |
| Antivirus | ClamAV | Rilevamento malware |
| Secrets | HashiCorp Vault | Gestione credenziali |
| Orchestrazione | Docker Compose | Containerizzazione |

---

## 9. Installazione e Configurazione

### Prerequisiti

- Docker Desktop (in esecuzione)
- Java JDK 17+
- Node.js 18+

### Passo 1: Avvio Infrastruttura

```bash
cd secure-doc-exchange
docker-compose up -d
```

Attendere circa 2 minuti per l'inizializzazione completa di Keycloak e ClamAV.

### Passo 1.1: Configurazione Keycloak

1. Accedere a **https://localhost:8444**
2. Selezionare **"Administration Console"**
3. Autenticarsi con: `admin` / `admin`
4. Nel menu, selezionare **"Master"** → **"Create Realm"**
5. Importare il file `keycloak-realm.json` dalla directory principale del progetto
6. Confermare con **"Create"**

### Passo 2: Avvio Backend

```bash
cd backend
mvn spring-boot:run
```

Il server sarà disponibile sulla porta **8443** (HTTPS).

### Passo 3: Avvio Frontend

```bash
cd frontend
npm install    # Solo alla prima esecuzione
npm run dev
```

L'applicazione sarà accessibile all'indirizzo **https://localhost:5173**.

---

## 10. Utenti di Test

| Utente | Username | Password | Ruolo | Dipartimento | Permessi |
|--------|----------|----------|-------|--------------|----------|
| Alice | `alice` | `password` | ADMIN | IT | Upload, Decrypt file IT, Audit Log, Delete |
| Bob | `bob` | `password` | USER | HR | Upload, Decrypt file HR |

---

## 11. Scenari di Verifica

### Test A: Upload e Decifratura (Zero Trust)

1. Login come **Alice**
2. Caricare un file (es. `notes.txt`)
3. Copiare la **Chiave di Decifratura** dal messaggio di conferma (disponibile per 20 secondi)
4. Selezionare il file e cliccare `DECRYPT`
5. **Risultato atteso**:
   - Chiave corretta → file scaricato
   - Chiave errata → errore `AEAD Bad Tag`

### Test B: Blocco Malware

1. Creare un file di test EICAR:
   ```bash
   echo "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" > eicar.com
   ```
2. Tentare l'upload
3. **Risultato atteso**: rifiuto con messaggio `Security Alert: Malware detected`

### Test C: Segregazione Dipartimentale (BOLA/IDOR)

1. Login come **Alice** (IT), caricare `alice_secret.pdf`
2. Login come **Bob** (HR)
3. **Risultato atteso**: `alice_secret.pdf` non visibile nella lista di Bob
4. **Verifica avanzata**: richiesta diretta `GET /api/documents/{id}` da Bob genera `403 Forbidden`

### Test D: Rate Limiting (DoS Protection)

1. Effettuare più di 50 richieste in un minuto
2. **Risultato atteso**: risposta `429 Too Many Requests`

### Test E: Audit Logging

1. Login come **Alice** (Admin)
2. Accedere alla sezione `ADMIN LOGS`
3. **Risultato atteso**: visualizzazione completa delle operazioni con timestamp, principal e dettagli

### Test F: Secret Chat

1. **Finestra 1**: login come Alice, creare stanza in `SECRET_CHAT`, copiare token invito
2. **Finestra 2**: login come Bob, inserire token invito
3. **Risultato atteso**: messaggi in tempo reale via WebSocket
4. **Verifica persistenza**: riavviare backend → cronologia chat eliminata

### Test G: Protezione BFLA (Admin Delete)

1. Login come **Bob** (HR): pulsante Delete non disponibile
2. **Verifica avanzata**: richiesta `DELETE /api/documents/{id}` genera `403 Forbidden`
3. Login come **Alice** (Admin): pulsante Delete disponibile e funzionante

### Test H: Verifica Crittografia Database

**Crittografia a Riposo:**
```bash
docker exec secure_postgres psql -U admin -d secure_docs_db \
  -c "SELECT id, filename, content_type, encrypted_content FROM documents;"
```
Risultato: colonna `encrypted_content` mostra OID o byte grezzi, non testo in chiaro.

**Crittografia in Transito (TLS):**
```bash
docker exec secure_postgres psql -U admin -d secure_docs_db \
  -c "SELECT pid, ssl, version, cipher FROM pg_stat_ssl;"
```
Risultato: `ssl = t`, `version = TLSv1.3`, `cipher = TLS_AES_256_GCM_SHA384`.

### Test I: Refresh Automatico Token

1. Aprire Developer Tools (F12) → Network
2. Osservare il traffico durante la sessione
3. **Risultato atteso**: richieste periodiche verso Keycloak per rinnovo token silenzioso

### Test J: Integrità Log (Bypass UI)

1. Ottenere un token JWT valido
2. Eseguire richiesta esterna:
   ```bash
   curl -k -H "Authorization: Bearer $TOKEN" https://localhost:8443/api/documents
   ```
3. Verificare dashboard Admin
4. **Risultato atteso**: evento `LIST_DOCUMENTS` registrato

### Test K: Path Traversal Protection

1. Tentare upload con nome file malevolo:
   ```bash
   curl -k -F "file=@./clean.txt;filename=../../malicious.exe" ...
   ```
2. **Risultato atteso**: file salvato come `malicious.exe`, caratteri `../` rimossi

### Test L: Protezione XSS

1. In Secret Chat, inviare: `<script>alert(1)</script>`
2. **Risultato atteso**: messaggio renderizzato come testo, non eseguito
3. Verificare console browser per errori CSP

### Test M: Unit Test Crittografia

```bash
cd backend
mvn test
```
**Verifiche automatiche**:
- Round-trip cifratura/decifratura
- Unicità IV (due cifrature dello stesso testo producono output diversi)
- Tamper detection (`AEADBadTagException` su modifica ciphertext)

---

## 12. Troubleshooting

| Sintomo | Causa | Soluzione |
|---------|-------|-----------|
| "Malware Scanner unavailable" | ClamAV non ha completato il caricamento delle firme | Attendere 60s, verificare con `docker logs secure_clamav` |
| Login Keycloak fallisce | Browser rifiuta certificati | Accettare eccezione SSL su porta 8443 e 8444 |
| Backend crash all'avvio | Vault non raggiungibile | Verificare stato Vault, riavviare container |
| Swagger UI "Network Error" | Certificati non accettati | Visitare `https://localhost:8443` e accettare certificato |

---

## 13. Note Tecniche

### Certificati Auto-Firmati

Il progetto utilizza certificati auto-firmati per l'ambiente localhost. I browser visualizzeranno un avviso di sicurezza.

**Azione**: selezionare "Avanzate" → "Procedi su localhost (non sicuro)"

La crittografia rimane valida (AES-256/TLS 1.3); l'avviso è dovuto all'assenza di una CA riconosciuta per localhost.

### Keycloak HTTPS

Il provider di identità opera su HTTPS (porta 8444) con:
- Certificato auto-firmato (`server.crt`)
- Truststore backend (`truststore.p12`) contenente la chiave pubblica Keycloak

### Documentazione API

- **Swagger UI**: https://localhost:8443/swagger-ui/index.html
- **OpenAPI JSON**: https://localhost:8443/v3/api-docs

Per i test da Swagger, inserire il Bearer Token ottenuto dal frontend tramite il pulsante "Authorize".

