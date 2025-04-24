import express from "express";
import session from "express-session";
import { open } from "sqlite";
import sqlite3 from "sqlite3";
import bcrypt from "bcrypt";

// BRUKERNAVN OG PASSORD TIL ADMIN-BRUKER:
// admin@test.no
// 123456

// Opnar databasen database.db
const dbPromise = open({
  filename: "MinDatabase.db",
  driver: sqlite3.Database,
});

const app = express();
const port = 3000;

app.use(
  session({
    secret: "secret",
    resave: true,
    saveUninitialized: true,
  })
);

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));

// Startar ein express applikasjon, og gjer den port 3000
app.listen(port, () => {
  console.log(`Server er startet her: http://localhost:${port}`);
});

// Henter fila index.ejs
app.get("/", (req, res) => {
  res.render("index");
});

// Henter fila login.ejs
app.get("/login", async (req, res) => {
  res.render("login");
});

//Vert kjørt når brukaren klikker "Registrer deg"
//Denne ligg i action på <form>

app.post("/register", async (req, res) => {
  const db = await dbPromise;
  const { fname, lname, email, password, confirmPassword } = req.body;

  if (password != confirmPassword) {
    res.render("login", { error: "Password must match." });
    return;
  }
  const passwordHash = await bcrypt.hash(confirmPassword, 10);

  // Tabellen eg bruker heiter "users" og har kolonnene "firstname", "lastname", "email" og "password"
  await db.run(
    "INSERT INTO users (firstname, lastname, email, password) VALUES (?, ?, ?, ?)",
    fname,
    lname,
    email,
    passwordHash
  );
  res.redirect("/login");
});

// Denne vert kjørt når brukaren trykker "Logg inn", i fila login.ejs
// Ref: <form action="/auth" method="post">
// Denne sjekker om brukaren finnes i databasen, og om passord dei skriv inn er rett.

app.get("/aml", async (req, res) => {
  // Check if user is logged in
  if (!req.session.loggedin) {
    return res.redirect("/login");
  }

  const db = await dbPromise;
  const admin = req.session.admin;
  const userId = req.session.userid;

  // Get category from query parameter, default to 'anime' if not specified
  let category = req.query.category || "anime";

  // Validate category to prevent SQL injection
  const validCategories = ["anime", "manga", "novel"];
  if (!validCategories.includes(category)) {
    category = "anime"; // Default to anime if invalid category
  }

  // Fetch user info to display name
  const user = await db.get("SELECT * FROM users WHERE id = ?", userId);

  // Fetch items based on category AND user_id
  const movies = await db.all(
    `SELECT * FROM AML 
   WHERE category = ? AND (user_id = ?)
   ORDER BY 
     CASE 
       WHEN status = 'In Progress' THEN 1
       WHEN status = 'Plan to Watch' THEN 2
       WHEN status = 'Completed' THEN 3
       WHEN status = 'Dropped' THEN 4
       WHEN status = 'On-Hold' THEN 5
       ELSE 6
     END`,
    [category, userId]
  );

  // Render the template with the data
  res.render("aml", {
    admin,
    movies,
    category,
    user, // Pass user info to template
  });
});

// Keep legacy routes for backward compatibility
app.get("/anime", (req, res) => {
  res.redirect("/aml?category=anime");
});

app.get("/manga", (req, res) => {
  res.redirect("/aml?category=manga");
});

app.get("/novel", (req, res) => {
  res.redirect("/aml?category=novel");
});

app.post("/add-item", async (req, res) => {
  // Check if user is logged in
  if (!req.session.loggedin) {
    return res.redirect("/login");
  }

  const db = await dbPromise;
  const userId = req.session.userid;
  const { name, category, link, status, image_url } = req.body;

  // Default values for fields not in the form
  const mal_id = null;
  const watchlistType = "user"; // To distinguish user-added content

  try {
    await db.run(
      "INSERT INTO AML (name, category, link, mal_id, status, watchlistType, image_url, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      [name, category, link, mal_id, status, watchlistType, image_url, userId]
    );

    res.redirect(`/aml?category=${category}`);
  } catch (error) {
    console.error("Error adding item:", error);
    res.status(500).send("Server error");
  }
});

// Update auth redirect to use the new route
app.post("/auth", async function (req, res) {
  const db = await dbPromise;
  const { email, password } = req.body;
  let getUserDetails = `SELECT * FROM users WHERE email = '${email}'`;
  let checkInDb = await db.get(getUserDetails);

  if (checkInDb === undefined) {
    res.status(400);
    res.send("Invalid user");
  } else {
    const isPasswordMatched = await bcrypt.compare(
      password,
      checkInDb.password
    );

    if (isPasswordMatched) {
      res.status(200);
      if (checkInDb.role == 1) {
        // Sjekker om brukaren er admin. Admin = 1
        req.session.admin = true;
      }
      // Dersom brukaren finnes, logg inn
      req.session.loggedin = true;
      req.session.email = email;
      req.session.userid = checkInDb.id;
      // Redirect til heimesida (now using the merged route)
      res.redirect("/aml?category=anime");
    } else {
      res.status(400);
      res.send("Invalid password");
      res.redirect("/");
    }
  }
});

app.get("/logout", async (req, res) => {
  req.session.loggedin = false;
  req.session.username = "";
  req.session.admin = false; // ADMIN SYSTEM
  res.redirect("/");
});

// ADMIN SYSTEM
app.get("/profile", async function (req, res) {
  if (req.session.loggedin) {
    const userid = req.session.userid;
    const admin = req.session.admin;
    const db = await dbPromise;
    let getUserDetails = `SELECT * FROM users WHERE id = '${userid}'`;
    let user = await db.get(getUserDetails);

    if (user === undefined) {
      res.status(400);
      res.send("Invalid user");
    } else {
      res.status(200);
      // Hent filmer som er favoritter for denne brukeren
      res.render("profile", { userid, user, admin });
    }
  } else {
    return res.render(403);
  }
});

// Rute for å håndtere POST-forespørsler til '/admin/delete/:id'.
app.post("/profile/delete/:id", async (req, res) => {
  const id = req.params.id; // Henter ID fra URL-parameteren.
  const db = await dbPromise; // Venter på at databasetilkoblingen skal være klar.
  const query = "DELETE FROM users WHERE id = ?";

  try {
    await db.run(query, id); // Utfører sletting av brukeren fra databasen.
    console.log("Deleted user with ID:", id); // Logger ID-en til brukeren som ble slettet.
    res.redirect("/"); // Omdirigerer tilbake til admin-siden etter sletting.
  } catch (error) {
    console.error("Error when deleting:", error); // Logger eventuelle feil under sletting.
    res.status(500).send("Unable to delete user."); // Sender feilmelding hvis sletting feiler.
  }
});

// Bruker kan redigere sin egen profil
app.get("/profile/edit", async function (req, res) {
  const admin = req.session.admin;
  const db = await dbPromise;
  const loggedInUserId = req.session.userid; // Henter ID-en til den innloggede brukeren

  // Sørger for at en vanlig bruker kun kan redigere sin egen profil
  if (!loggedInUserId) {
    return res
      .status(403)
      .send("Du har ikke tilgang til å redigere denne profilen.");
  }

  const query = "SELECT * FROM users WHERE id = ?";
  const user = await db.get(query, loggedInUserId);

  if (!user) {
    return res.status(404).send("Bruker ikke funnet.");
  }

  res.render("edit", { user, admin });
});

app.post("/profile/edit/:id", async function (req, res) {
  const id = req.params.id; // Henter ID fra URL-parameteren.

  // Sjekker om brukaren er logga inn, hvis ikkje - vart den sendt til fila 403.ejs i mappa errors
  if (!req.session.loggedin) {
    return res.render(403);
  }

  const db = await dbPromise;
  const loggedInUserId = req.session.userid; // finner userid til innlogga brukar
  const admin = req.session.admin; // finner ut om brukaren som er logga inn er admin

  // Sjekker om brukaren som prøver å redigere profilen, er den same som er logga inn, eller om admin
  if (parseInt(id) !== loggedInUserId) {
    return res.render(403);
  }

  // henter ut firstname og lastname frå <form> i edit.ejs
  // desse er "name" i <input> feltet, og må skrives på same måte
  const { firstname, lastname } = req.body;

  const query = "UPDATE users SET firstname = ?, lastname = ? WHERE id = ?";

  try {
    await db.run(query, [firstname, lastname, loggedInUserId]); // kjører SQL spørringen
    //console.log(`Profil oppdatert for bruker-ID: ${loggedInUserId}`);
    res.redirect("/profile"); // Tilbake til profilsiden
  } catch (error) {
    //console.error('Feil ved oppdatering:', error);
    res.status(500).send("Kunne ikke oppdatere profilen.");
  }
});

// ADMIN SYSTEM - opner admin.ejs
app.get("/admin", async function (req, res) {
  if (req.session.loggedin) {
    const user = req.session.email;
    const db = await dbPromise;
    let getUserDetails = `SELECT * FROM users WHERE email = '${user}' AND role = 1`;
    let checkInDb = await db.get(getUserDetails);
    const query = "SELECT * FROM users";
    const users = await db.all(query); // kjører SQL spørringen

    if (checkInDb === undefined) {
      res.status(400);
      res.send("Invalid user");
    } else {
      let admin = true;
      res.status(200);
      res.render("admin", { user, admin, users });
    }
  }
});

// Rute for å håndtere POST-forespørsler til '/admin/delete/:id'.
app.post("/admin/delete/:id", async (req, res) => {
  const id = req.params.id; // Henter ID fra URL-parameteren.
  const db = await dbPromise; // Venter på at databasetilkoblingen skal være klar.
  const query = "DELETE FROM users WHERE id = ?";
  console.log("ID to delete:", id); // Logger ID-en til brukeren som skal slettes.

  try {
    await db.run(query, id); // Utfører sletting av brukeren fra databasen.
    //console.log('Deleted user with ID:', id); // Logger ID-en til brukeren som ble slettet.
    res.redirect("/admin"); // Omdirigerer tilbake til admin-siden etter sletting.
  } catch (error) {
    console.log("Error when deleting:", error); // Logger eventuelle feil under sletting.
    res.status(500).send("Unable to delete user."); // Sender feilmelding hvis sletting feiler.
  }
});

app.get("/admin/edit/:id", async (req, res) => {
  const admin = req.session.admin;
  if (!req.session.admin) {
    return res.redirect("/anime"); // Sikrer at kun admin har tilgang
  }

  const db = await dbPromise;
  const userId = req.params.id; // Henter brukerens ID fra URL
  const user = await db.get("SELECT * FROM users WHERE id = ?", [userId]);

  if (!user) {
    return res.status(404).send("Bruker ikke funnet");
  }

  res.render("admin_edit", { user, admin });
});

app.post("/admin/edit/:id", async (req, res) => {
  const admin = req.session.admin;
  if (!req.session.admin) {
    return res.status(403).send("Access Denied");
  }

  const db = await dbPromise;
  const { firstname, lastname, role } = req.body;
  const userId = req.params.id;

  try {
    await db.run(
      "UPDATE users SET firstname = ?, lastname = ?, role = ? WHERE id = ?",
      [firstname, lastname, role, userId]
    );

    res.redirect("/admin"); // Gå tilbake til admin-panelet etter oppdatering
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).send("Error updating user.");
  }
});

// AML Admin routes
app.get("/aml-admin", async function (req, res) {
  // Check if user is logged in and is admin
  if (!req.session.loggedin || !req.session.admin) {
    return res.status(403).send("Access Denied");
  }

  const db = await dbPromise;
  const admin = req.session.admin;

  // Get category from query parameter, default to 'all' if not specified
  let category = req.query.category || "all";

  // Validate category to prevent SQL injection
  const validCategories = ["all", "anime", "manga", "novel"];
  if (!validCategories.includes(category)) {
    category = "all"; // Default to all if invalid category
  }

  // Fetch items based on category
  let items;
  if (category === "all") {
    items = await db.all("SELECT * FROM AML ORDER BY category, name");
  } else {
    items = await db.all(
      "SELECT * FROM AML WHERE category = ? ORDER BY name",
      category
    );
  }

  // Render the template with the data
  res.render("aml_admin", {
    admin,
    items,
    category,
  });
});

// Edit AML content
app.get("/aml-admin/edit/:id", async function (req, res) {
  // Check if user is logged in and is admin
  if (!req.session.loggedin || !req.session.admin) {
    return res.status(403).send("Access Denied");
  }

  const db = await dbPromise;
  const admin = req.session.admin;
  const id = req.params.id;

  // Get item details
  const item = await db.get("SELECT * FROM AML WHERE id = ?", id);

  if (!item) {
    return res.status(404).send("Content not found");
  }

  // Render edit form
  res.render("edit-item", {
    admin,
    item,
    isNew: false,
  });
});

// Process edit form submission
app.get("/aml-admin/edit/:id", async function (req, res) {
  // Check if user is logged in and is admin
  if (!req.session.loggedin || !req.session.admin) {
    return res.status(403).send("Access Denied");
  }

  const db = await dbPromise;
  const admin = req.session.admin;
  const id = req.params.id;

  // Get item details
  const item = await db.get("SELECT * FROM AML WHERE id = ?", id);

  if (!item) {
    return res.status(404).send("Content not found");
  }

  // Get all users for the dropdown
  const users = await db.all(
    "SELECT id, firstname, lastname, email FROM users"
  );

  // Render edit form
  res.render("edit-item", {
    admin,
    item,
    users,
    isNew: false,
  });
});

// Process add form submission
app.post("/aml-admin/add", async function (req, res) {
  // Check if user is logged in and is admin
  if (!req.session.loggedin || !req.session.admin) {
    return res.status(403).send("Access Denied");
  }

  const db = await dbPromise;
  // Get user selection from form, or null for all users (global content)
  const {
    name,
    category,
    link,
    mal_id,
    status,
    watchlistType,
    image_url,
    user_id,
  } = req.body;

  try {
    await db.run(
      "INSERT INTO AML (name, category, link, mal_id, status, watchlistType, image_url, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      [
        name,
        category,
        link,
        mal_id,
        status,
        watchlistType,
        image_url,
        user_id || null,
      ]
    );

    res.redirect("/aml-admin");
  } catch (error) {
    console.error("Error adding AML content:", error);
    res.status(500).send("Error adding content");
  }
});

// Delete AML content
app.post("/admin/delete/:id", async (req, res) => {
  const id = req.params.id; // Henter ID fra URL-parameteren.
  const db = await dbPromise; // Venter på at databasetilkoblingen skal være klar.
  const query = "DELETE FROM users WHERE id = ?";

  try {
    await db.run(query, id); // Utfører sletting av brukeren fra databasen.
    //console.log('Deleted user with ID:', id); // Logger ID-en til brukeren som ble slettet.
    res.redirect("/admin"); // Omdirigerer tilbake til admin-siden etter sletting.
  } catch (error) {
    //console.error('Error when deleting:', error); // Logger eventuelle feil under sletting.
    res.status(500).send("Unable to delete user."); // Sender feilmelding hvis sletting feiler.
  }
});

// Add these routes to your Express application

// Route to handle status updates
app.post("/update-status/:id", async (req, res) => {
  if (!req.session.loggedin) {
    return res.redirect("/login");
  }

  const db = await dbPromise;
  const userId = req.session.userid;
  const itemId = req.params.id;
  const { status } = req.body;

  try {
    // First check if the item belongs to this user (security check)
    const item = await db.get("SELECT * FROM AML WHERE id = ?", itemId);

    if (
      !item ||
      (item.user_id && item.user_id !== userId && !req.session.admin)
    ) {
      return res
        .status(403)
        .send("You don't have permission to update this item");
    }

    // Update the status
    await db.run("UPDATE AML SET status = ? WHERE id = ?", [status, itemId]);

    // Redirect back to the page they were on
    res.redirect(`/aml?category=${item.category}`);
  } catch (error) {
    console.error("Error updating status:", error);
    res.status(500).send("Error updating status");
  }
});

// Route to handle delete functionality
app.get("/delete-item/:id", async (req, res) => {
  if (!req.session.loggedin) {
    return res.redirect("/login");
  }

  const db = await dbPromise;
  const userId = req.session.userid;
  const itemId = req.params.id;

  try {
    // First check if the item belongs to this user (security check)
    const item = await db.get(
      "SELECT * FROM AML WHERE id = ? AND user_id = ?",
      [itemId, userId]
    );

    if (!item && !req.session.admin) {
      return res
        .status(403)
        .send("You don't have permission to delete this item");
    }

    // Get the category before deleting the item
    const category = item ? item.category : "anime";

    // Delete the item
    await db.run("DELETE FROM AML WHERE id = ?", itemId);

    // Redirect back to the same category page
    res.redirect(`/aml?category=${category}`);
  } catch (error) {
    console.error("Error deleting item:", error);
    res.status(500).send("Error deleting item");
  }
});

// Route to show edit form
app.get("/edit-item/:id", async (req, res) => {
  if (!req.session.loggedin) {
    return res.redirect("/login");
  }

  const db = await dbPromise;
  const userId = req.session.userid;
  const itemId = req.params.id;
  const admin = req.session.admin;

  try {
    // Get the item to edit
    const item = await db.get("SELECT * FROM AML WHERE id = ?", itemId);

    if (!item) {
      return res.status(404).send("Item not found");
    }

    // Check if user has permission to edit this item
    if (item.user_id !== userId && !admin) {
      return res
        .status(403)
        .send("You don't have permission to edit this item");
    }

    // Fetch user info
    const user = await db.get("SELECT * FROM users WHERE id = ?", userId);

    // Render the edit form
    res.render("edit-item", {
      item,
      user,
      admin,
      category: item.category,
    });
  } catch (error) {
    console.error("Error displaying edit form:", error);
    res.status(500).send("Server error");
  }
});

// Route to process the edit form
app.post("/edit-item/:id", async (req, res) => {
  if (!req.session.loggedin) {
    return res.redirect("/login");
  }

  const db = await dbPromise;
  const userId = req.session.userid;
  const itemId = req.params.id;
  const { name, link, image_url, status, category } = req.body;

  try {
    // Check if user has permission to edit this item
    const item = await db.get("SELECT * FROM AML WHERE id = ?", itemId);

    if (!item) {
      return res.status(404).send("Item not found");
    }

    if (item.user_id !== userId && !req.session.admin) {
      return res
        .status(403)
        .send("You don't have permission to edit this item");
    }

    // Update the item
    await db.run(
      "UPDATE AML SET name = ?, link = ?, image_url = ?, status = ? WHERE id = ?",
      [name, link, image_url, status, itemId]
    );

    // Redirect back to the category page
    res.redirect(`/aml?category=${category}`);
  } catch (error) {
    console.error("Error updating item:", error);
    res.status(500).send("Error updating item");
  }
});

// Search route
app.get("/search", async (req, res) => {
  // Check if user is logged in
  if (!req.session.loggedin) {
    return res.redirect("/login");
  }

  const db = await dbPromise;
  const admin = req.session.admin;
  const userId = req.session.userid;

  // Get search parameters
  const query = req.query.query;
  let category = req.query.category || "anime"; // Store current category for navigation context

  // Validate category to prevent SQL injection
  const validCategories = ["anime", "manga", "novel"];
  if (!validCategories.includes(category)) {
    category = "anime"; // Default to anime if invalid category
  }

  // Fetch user info to display name
  const user = await db.get("SELECT * FROM users WHERE id = ?", userId);

  try {
    // Always search across all categories
    const movies = await db.all(
      "SELECT * FROM AML WHERE user_id = ? AND name LIKE ? ORDER BY category, name",
      [userId, `%${query}%`]
    );

    // Render the template with search results
    res.render("aml", {
      admin,
      movies,
      category, // Keep the original category for navigation context
      user,
      searchQuery: query,
      isSearchResult: true,
    });
  } catch (error) {
    console.error("Search error:", error);
    res.status(500).send("Error performing search");
  }
});
