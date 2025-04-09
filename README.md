<h2>Dette må gjøres aller først: </h2>
<ol>
 <li> Installer <a href="https://nodejs.org/en">Node.js</a> om du ikkje har det frå før</li>
<li>Last ned eksempelkoden, pakk den ut, og lagre den </li>
  <li>Opne CMD og naviger til mappa </li>
<li> Kjør kommandoen <code>npm init -y </code> i mappa</li>
<li> Kjør kommandoen <code>npm install sqlite3 express ejs bcrypt sqlite express-session</code></li>
 <li>Opprett ei databasefil (database.db) (td. i SQLiteStudio). Denne må ligge i prosjektmappa di. </li>
 <li>Last ned eksempelkoden og prøv deg fram.</li>
</ol>

<h2>Starte applikasjonen: </h2>
<ul>
 <li>Bruk CMD (command prompt) og naviger til mappa.</li>
 <li>Kommando: node index.js</li>
</ul>

<h2>Mappa views</h2>
<p>I denne mappa finner du .ejs filer. Det er html-filer med ejs (Embedded JavaScript)</p>
<p>Det er her me endrer på utsjånaden på filene, slik som me er vant med.</p>

<h2>index.js</h2>
<p>Denne fila inneheld all koden for å hente inn og vise informasjon frå databasen. </p>
<p>Den lagar også routing, navigering, mellom dei ulike sidene. </p>

<h3><b>GET</b> vs <b>POST</b> i index.js i Express.js</h3>
<b>GET (Henter data)</b>
<ul>
 <li> Denne bruker me når me skal hente informasjon frå serveren.</li>
 <li>Ingen sensitiv informasjon sendes i body – berre via URL.</li>
 <li>Eksempel: Hente ein brukarprofil, eller ei nettside. </li>
</li>
</ul>
<b>POST (sender/skriver data )</b>
<ul>
 <li>Denne bruker me når me skal sende data til serveren (f.eks. lagre eller oppdatere noko i databasen).</li>
 <li>Data vert sendt i request body, ikkje i URL-en – sikrare for sensitiv info (f.eks. passord).</li>
 <li>Eksempel: Når ein brukar logger inn.</li>
</ul>


<h2>Styling:</h2> 

 Lenke til css : ... href="/style.css" <br>
 Denne må inn i .ejs filene der du ønsker å ha css (akkurat slik som i vanlige HTML-filer, bortsett fra at du ikkje trenger /public med)

<h2>Bilder:</h2> 
Bildefiler må inn i public-mappa. Gjerne i ei mappe som heiter images. (public/images)

<h2>Database:</h2> 
<p>Databasefila eg bruker heiter database.db</p>
<p>Åpne denne med SQLite Studio for å sjå tabellane som vert brukt.</p>
