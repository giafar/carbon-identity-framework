# Login condivisa

Pagina login condivisa, Comune di Napoli

## Installation

Effettuare l'installazione delle dipendenze lanciando da terminale:

```bash
npm install
```

## Instruction

Nella cartella public sono presenti due pagine statiche html:
- login
- error page

Nel file style.css sono presenti tutti le classi css compilate dai componenti di sass.

le classi css da utilizzare per i form di errore sono .error-feedback & error-feedback-text

## changed class

nella login.html sono stati modificati tutti i pulsanti all'interno dei singoli tab.
ogni pulstante ha un suo commento di inizio e fine, es:
<!-- AGID - SPID IDP BUTTON LARGE "ENTRA CON SPID" * begin * -->

è stato aggiornato direttamente il file style.css
sono statti aggiunti due files javascript:

jquery.js
spid-sp-access-button.js

è stata aggiunta una nuova classe css:
spid-sp-access-button.css

nella cartella img sono state aggiornate le immagini


per i pulsanti spid, rif al repository:
https://github.com/italia/spid-sp-access-button


NB: per il primo tab, per la visualizzazione mobile, è la classe p-4 di bootstrap che applica l'estensione di visualizzazione.
