// index.js

const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const { MongoClient } = require("mongodb");
require('dotenv').config(); // charge le pepper

const app = express();

// Connexion MongoDB
const uri = "mongodb+srv://jeremy:BtsmCwF94oPaediq@cluster0.6zy2pjk.mongodb.net/";
const client = new MongoClient(uri);

// Connexion à la base
async function connecterMongo() {
    await client.connect();
    console.log("MongoDB connecté");
    
}

const db = client.db("USER");
const usersCol = db.collection("user");


connecterMongo();

app.use(express.json());
app.use(cors());

// Fonction : ajoute le pepper au hash du client
function hashWithPepper(clientHash) {
    return crypto
        .createHash("sha256")
        .update(clientHash + process.env.PEPPER)
        .digest("hex");
}

// Obtenir le sel d’un utilisateur
app.post('/getSalt', async (req, res) => {
    const { mail } = req.body;

    if (!mail) {
        return res.status(400).json({ error: "Mail manquant" });
    }

    const user = await usersCol.findOne({ mail: mail });

    if (user) {
        return res.status(200).json({ salt: user.salt });
    } else {
        return res.status(404).json({ error: "Utilisateur non trouvé" });
    }
});

// Connexion
app.post('/login', async (req, res) => {
    const { mail, password } = req.body;

    if (!mail || !password) {
        return res.status(400).json({ error: "Données manquantes" });
    }

    const user = await usersCol.findOne({ mail: mail });

    // Valeur par défaut si l’utilisateur n’existe pas
    const storedPass = user ? user.pass : crypto.randomBytes(32).toString('hex');

    // Ajout du pepper au hash envoyé par le client
    const providedPass = hashWithPepper(password);

    // Comparaison sécurisée
    const bufStored = Buffer.from(storedPass);
    const bufProvided = Buffer.from(providedPass);

    let isValid = false;

    if (bufStored.length === bufProvided.length) {
        try {
            isValid = crypto.timingSafeEqual(bufStored, bufProvided);
        } catch {
            isValid = false;
        }
    }

    if (!isValid) {
        return res.status(401).json({ error: "Identifiants invalides" });
    }

    return res.status(200).json({ mail: user.mail });
});

// Fonction : génère un salt unique
function genererSalt() {
    return crypto.randomBytes(16).toString('hex');
}

// Début inscription : création du sel
app.post('/register', async (req, res) => {
    const { mail } = req.body;

    if (!mail) {
        return res.status(400).json({ error: "Mail manquant" });
    }

    const existing = await usersCol.findOne({ mail: mail });

    if (existing) {
        return res.status(409).json({ error: "Utilisateur déjà existant" });
    }

    const salt = genererSalt();

    const newUser = {
        mail: mail,
        pass: "",
        salt: salt
    };

    const resultat = await usersCol.insertOne(newUser);

    return res.status(201).json({ _id: resultat.insertedId, salt: salt });
});

// Fin inscription : enregistrement du mot de passe hashé
app.post('/completeRegister', async (req, res) => {
    const { mail, password } = req.body;

    if (!mail || !password) {
        return res.status(400).json({ error: "Données manquantes" });
    }

    const user = await usersCol.findOne({ mail: mail });

    if (!user) {
        return res.status(404).json({ error: "Utilisateur non trouvé" });
    }

    // Ajout du pepper au hash envoyé par le client
    const finalHash = hashWithPepper(password);

    await usersCol.updateOne(
        { mail: mail },
        { $set: { pass: finalHash } }
    );

    return res.status(201).json({ mail: mail });
});

// Lancer le serveur
app.listen(3000, () => {
    console.log("Serveur démarré sur http://localhost:3000");
});