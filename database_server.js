const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const { faker } = require('@faker-js/faker');

const app = express();
const JWT_SECRET = 'secretkey';
app.use(bodyParser.json());

// Connexion à la base de données
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'woodog'
});

db.connect((err) => {
    if (err) {
        console.error('Erreur de connexion à la base de données :', err);
    } else {
        console.log('Connecté à la base de données MySQL');
    }
});

// Créations des tables
db.query(`
  CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    fullName VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL
  )
`);

db.query(`
  CREATE TABLE IF NOT EXISTS walkers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    fullName VARCHAR(255) NOT NULL,
    age INT NOT NULL,
    month_of_experience INT NOT NULL,
    description TEXT NOT NULL,
    distance_location TEXT NOT NULL,
    photo_url VARCHAR(255) NOT NULL,
    isRecruited BOOLEAN DEFAULT false
  )
`);

db.query(`
  CREATE TABLE IF NOT EXISTS suggested_walkers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    fullName VARCHAR(255) NOT NULL,
    age INT NOT NULL,
    month_of_experience INT NOT NULL,
    description TEXT NOT NULL,
    distance_location TEXT NOT NULL,
    photo_url VARCHAR(255) NOT NULL,
    isRecruited BOOLEAN DEFAULT false
  )
`);

// Route pour gérer l'inscription
app.post('/register', (req, res) => {
    const { fullName, email, password } = req.body;

    // Vérification si l'utilisateur n'est pas déjà inscrit
    db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
        if (results.length > 0) {
            return res.status(400).json({ message: 'Un utilisateur avec un email pareil existe déJà' });
        }

        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) throw err;

            db.query('INSERT INTO users (fullName, email, password) VALUES (?, ?, ?)', [fullName, email, hashedPassword], (err) => {
                if (err) throw err;
                res.status(201).json({ message: 'Inscription réussie' });
            });
        });
    });
});

// Route pour gérer la connexion
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (err || results.length === 0) {
            res.status(401).json({ error: 'Email ou mot de passe incorrect' });
        } else {
            const user = results[0];
            const match = await bcrypt.compare(password, user.password);
            if (match) {
                const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
                res.json({
                    message: 'Connexion réussie',
                    token: token
                });
            } else {
                res.status(401).json({ error: 'Email ou mot de passe incorrect' });
            }
        }
    });
});

function verifyToken(req, res, next) {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(403).json({ message: 'Token non fourni' });
    }

    const actualToken = token.startsWith('Bearer ') ? token.slice(7, token.length) : token;

    jwt.verify(actualToken, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Token invalide' });
        }
        req.userId = decoded.userId;
        next();
    });
}

// route pour obtenir tous les promeneurs
app.get('/walkers', verifyToken, (req, res) => {
    db.query('SELECT id, fullName, age, month_of_experience, description, distance_location, isRecruited, photo_url FROM walkers', (err, results) => {
        if (err) {
            res.status(500).json({ error: 'Erreur lors de la récupération des promeneurs' });
        } else {
            res.json(results);
        }
    });
});

// route pour obtenir tous les promeneurs suggérés
app.get('/suggested_walkers', verifyToken, (req, res) => {
    db.query('SELECT id, fullName, age, month_of_experience, description, distance_location, isRecruited, photo_url FROM suggested_walkers', (err, results) => {
        if (err) {
            res.status(500).json({ error: 'Erreur lors de la récupération des promeneurs' });
        } else {
            res.json(results);
        }
    });
});

// route pour obtenir les détails d'un promeneur
app.get('/walkers/:id', verifyToken, (req, res) => {
    const { id } = req.params;
    db.query('SELECT * FROM walkers WHERE id = ?', [id], (err, results) => {
        if (err || results.length === 0) {
            res.status(404).json({ error: 'Promeneur non trouvé' });
        } else {
            res.json(results[0]);
        }
    });
});

// route pour obtenir les détails d'un promeneur suggéré
app.get('/suggested_walkers/:id', verifyToken, (req, res) => {
    const { id } = req.params;
    db.query('SELECT * FROM suggested_walkers WHERE id = ?', [id], (err, results) => {
        if (err || results.length === 0) {
            res.status(404).json({ error: 'Promeneur non trouvé' });
        } else {
            res.json(results[0]);
        }
    });
});

// Recruter un promeneur
app.post('/walkers/:id/recrute', (req, res) => {
    const { id } = req.params;
    db.query('UPDATE walkers SET isRecruited = true WHERE id = ?', [id], (err, result) => {
        if (err) {
            res.status(500).json({ error: 'Erreur lors du recrutement du promeneur' });
        } else if (result.affectedRows === 0) {
            res.status(404).json({ error: 'Promeneur non trouvé' });
        } else {
            res.json({ message: 'Promeneur recruté avec succès' });
        }
    });
});

// Recruter un promeneur suggéré
app.post('/suggested_walkers/:id/recrute', (req, res) => {
    const { id } = req.params;
    db.query('UPDATE suggested_walkers SET isRecruited = true WHERE id = ?', [id], (err, result) => {
        if (err) {
            res.status(500).json({ error: 'Erreur lors du recrutement du promeneur' });
        } else if (result.affectedRows === 0) {
            res.status(404).json({ error: 'Promeneur non trouvé' });
        } else {
            res.json({ message: 'Promeneur recruté avec succès' });
        }
    });
});

// Route pour obtenir les informations de l'utilisateur connecté
app.get('/profile', verifyToken, (req, res) => {
    const userId = req.userId;

    db.query('SELECT id, fullName, email FROM users WHERE id = ?', [userId], (err, results) => {
        if (err || results.length === 0) {
            return res.status(404).json({ error: 'Utilisateur non trouvé' });
        }
        res.json(results[0]);
    });
});


// création d'une liste de promeneur
const walkers = [
    { fullName: 'Alice Dupont', age: 25, month_of_experience: 12, description: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.', distance_location: '7km from you'},
    { fullName: 'Bob Martin', age: 30, month_of_experience: 24, description: 'Sed do eiusmod tempor incididunt ut labore et dolore magna.', distance_location: '7km from you' },
    { fullName: 'Claire Rousseau', age: 28, month_of_experience: 18, description: 'Ut enim ad minim veniam, quis nostrud exercitation ullamco.', distance_location: '14km from you' },
    { fullName: 'David Lefebvre', age: 35, month_of_experience: 36, description: 'Duis aute irure dolor in reprehenderit in voluptate velit.', distance_location: '2km from you' },
    { fullName: 'Emilie Dubois', age: 22, month_of_experience: 6, description: 'Excepteur sint occaecat cupidatat non proident, sunt in culpa.', distance_location: '12km from you' },
];

const suggested_walkers = [
    { fullName: 'François Moreau', age: 40, month_of_experience: 48, description: 'Nemo enim ipsam voluptatem quia voluptas sit aspernatur aut.', distance_location: '14km from you' },
    { fullName: 'Gabrielle Petit', age: 33, month_of_experience: 30, description: 'Neque porro quisquam est, qui dolorem ipsum quia dolor sit.', distance_location: '12km from you' },
    { fullName: 'Hugo Bernard', age: 27, month_of_experience: 15, description: 'Quis autem vel eum iure reprehenderit qui in ea voluptate.', distance_location: '7km from you' },
    { fullName: 'Isabelle Girard', age: 31, month_of_experience: 27, description: 'At vero eos et accusamus et iusto odio dignissimos ducimus.', distance_location: '7km from you' },
    { fullName: 'Jules Lambert', age: 29, month_of_experience: 21, description: 'Et harum quidem rerum facilis est et expedita distinctio.', distance_location: '2km from you' }
];

walkers.forEach(walker => {
    const photoUrl = `https://loremflickr.com/320/240/people?random=${Math.floor(Math.random() * 1000)}`;
    db.query('INSERT INTO walkers (fullName, age, month_of_experience, description, distance_location, photo_url) VALUES (?, ?, ?, ?, ?, ?)',
        [walker.fullName, walker.age, walker.month_of_experience, walker.description, walker.distance_location, photoUrl]
    );
});

suggested_walkers.forEach(suggested_walkers => {
    const photoUrl = `https://loremflickr.com/320/240/people?random=${Math.floor(Math.random() * 1000)}`;
    db.query('INSERT INTO suggested_walkers (fullName, age, month_of_experience, description, distance_location, photo_url) VALUES (?, ?, ?, ?, ?, ?)',
        [suggested_walkers.fullName, suggested_walkers.age, suggested_walkers.month_of_experience, suggested_walkers.description, suggested_walkers.distance_location, photoUrl]
    );
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Serveur en cours d'exécution sur le port ${PORT}`);
});