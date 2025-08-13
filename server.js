const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/globalna-banka';
mongoose.connect(MONGODB_URI)
  .then(() => console.log('✅ Connecté à MongoDB'))
  .catch(err => console.error('❌ Erreur MongoDB:', err));

// Schémas MongoDB
const UserSchema = new mongoose.Schema({
  civilite: { type: String, required: true },
  ime: { type: String, required: true },
  priimek: { type: String, required: true },
  dateNaissance: { type: Date, required: true },
  numeroId: { type: String, required: true, unique: true },
  pays: { type: String, required: true },
  ville: { type: String, required: true },
  adresse: { type: String, required: true },
  telephone: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  motDePasse: { type: String, required: true },
  accountNumber: { type: String, default: '' },
  balance: { type: String, default: '0,00' },
  status: { type: String, enum: ['pending', 'approved', 'blocked'], default: 'pending' },
  isAdmin: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);

// Routes

// Page d'accueil
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Inscription
app.post('/api/register', async (req, res) => {
  try {
    const {
      civilite, ime, priimek, dateNaissance, numeroId,
      pays, ville, adresse, telephone, email, motDePasse
    } = req.body;

    // Vérifier si l'utilisateur existe déjà
    const existingUser = await User.findOne({
      $or: [{ email }, { numeroId }]
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'Uporabnik s to e-pošto ali ID že obstaja'
      });
    }

    // Hasher le mot de passe
    const hashedPassword = await bcrypt.hash(motDePasse, 10);

    // Créer nouvel utilisateur
    const newUser = new User({
      civilite, ime, priimek, dateNaissance, numeroId,
      pays, ville, adresse, telephone, email,
      motDePasse: hashedPassword
    });

    await newUser.save();

    res.status(201).json({
      success: true,
      message: 'Registracija uspešna! Vaš račun je v obravnavi.'
    });

  } catch (error) {
    console.error('Napaka pri registraciji:', error);
    res.status(500).json({
      success: false,
      message: 'Napaka strežnika'
    });
  }
});

// Connexion
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Compte admin par défaut
    if (username === 'admin' && password === 'admin') {
      const token = jwt.sign(
        { userId: 'admin', isAdmin: true },
        process.env.JWT_SECRET || 'secret-key',
        { expiresIn: '24h' }
      );

      return res.json({
        success: true,
        token,
        user: {
          id: 'admin',
          isAdmin: true,
          ime: 'Administrator'
        }
      });
    }

    // Chercher l'utilisateur
    const user = await User.findOne({
      $or: [{ email: username }, { numeroId: username }]
    });

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Napačni podatki'
      });
    }

    // Vérifier le mot de passe
    const isValidPassword = await bcrypt.compare(password, user.motDePasse);
    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        message: 'Napačni podatki'
      });
    }

    // Vérifier le statut du compte
    if (user.status === 'blocked') {
      return res.status(403).json({
        success: false,
        message: 'Vaš račun je blokiran'
      });
    }

    if (user.status === 'pending') {
      return res.status(403).json({
        success: false,
        message: 'Vaš račun je še vedno v obravnavi'
      });
    }

    // Générer token
    const token = jwt.sign(
      { userId: user._id, isAdmin: false },
      process.env.JWT_SECRET || 'secret-key',
      { expiresIn: '24h' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        ime: user.ime,
        priimek: user.priimek,
        accountNumber: user.accountNumber,
        balance: user.balance,
        isAdmin: false
      }
    });

  } catch (error) {
    console.error('Napaka pri prijavi:', error);
    res.status(500).json({
      success: false,
      message: 'Napaka strežnika'
    });
  }
});

// Middleware d'authentification
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'Token manjka' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'secret-key', (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Neveljaven token' });
    }
    req.user = user;
    next();
  });
};

// Routes Admin
app.get('/api/admin/users', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({ success: false, message: 'Dostop zavrnjen' });
    }

    const users = await User.find({ isAdmin: { $ne: true } })
      .select('-motDePasse')
      .sort({ createdAt: -1 });

    res.json({ success: true, users });
  } catch (error) {
    console.error('Napaka pri pridobivanju uporabnikov:', error);
    res.status(500).json({ success: false, message: 'Napaka strežnika' });
  }
});

app.post('/api/admin/approve-user/:userId', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({ success: false, message: 'Dostop zavrnjen' });
    }

    const { userId } = req.params;
    
    // Générer numéro de compte
    const generateAccountNumber = () => {
      const formats = ['SI56 3300 0001 3772', 'ES71 1491 0001 2130'];
      const randomFormat = formats[Math.floor(Math.random() * formats.length)];
      const randomNumber = Math.floor(Math.random() * 10000).toString().padStart(4, '0');
      return `${randomFormat} ${randomNumber}`;
    };

    const accountNumber = generateAccountNumber();

    const user = await User.findByIdAndUpdate(
      userId,
      { 
        status: 'approved',
        accountNumber: accountNumber
      },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ success: false, message: 'Uporabnik ni najden' });
    }

    res.json({ success: true, message: 'Uporabnik odobren', user });
  } catch (error) {
    console.error('Napaka pri odobritvi:', error);
    res.status(500).json({ success: false, message: 'Napaka strežnika' });
  }
});

app.post('/api/admin/block-user/:userId', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({ success: false, message: 'Dostop zavrnjen' });
    }

    const { userId } = req.params;

    const user = await User.findByIdAndUpdate(
      userId,
      { status: 'blocked' },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ success: false, message: 'Uporabnik ni najden' });
    }

    res.json({ success: true, message: 'Uporabnik blokiran', user });
  } catch (error) {
    console.error('Napaka pri blokiranju:', error);
    res.status(500).json({ success: false, message: 'Napaka strežnika' });
  }
});

app.post('/api/admin/update-balance/:userId', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({ success: false, message: 'Dostop zavrnjen' });
    }

    const { userId } = req.params;
    const { balance } = req.body;

    const user = await User.findByIdAndUpdate(
      userId,
      { balance: balance },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ success: false, message: 'Uporabnik ni najden' });
    }

    res.json({ success: true, message: 'Stanje posodobljeno', user });
  } catch (error) {
    console.error('Napaka pri posodabljanju stanja:', error);
    res.status(500).json({ success: false, message: 'Napaka strežnika' });
  }
});

// Route pour obtenir les données utilisateur
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    if (req.user.isAdmin) {
      return res.json({
        success: true,
        user: {
          id: 'admin',
          ime: 'Administrator',
          isAdmin: true
        }
      });
    }

    const user = await User.findById(req.user.userId).select('-motDePasse');
    if (!user) {
      return res.status(404).json({ success: false, message: 'Uporabnik ni najden' });
    }

    res.json({ success: true, user });
  } catch (error) {
    console.error('Napaka pri pridobivanju profila:', error);
    res.status(500).json({ success: false, message: 'Napaka strežnika' });
  }
});

// Contact
app.post('/api/contact', async (req, res) => {
  try {
    const { ime, email, sporocilo } = req.body;
    
    console.log('Novo sporočilo:', { ime, email, sporocilo });
    
    res.json({
      success: true,
      message: 'Sporočilo uspešno poslano!'
    });
  } catch (error) {
    console.error('Napaka pri pošiljanju sporočila:', error);
    res.status(500).json({
      success: false,
      message: 'Napaka strežnika'
    });
  }
});

// Démarrer le serveur
app.listen(PORT, () => {
  console.log(`🚀 Strežnik se izvaja na portu ${PORT}`);
  console.log(`🌐 Aplikacija dostopna na: http://localhost:${PORT}`);
});
