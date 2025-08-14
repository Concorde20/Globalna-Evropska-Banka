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
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI;
console.log('🔗 Connecting to MongoDB...');

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log('✅ Successfully connected to MongoDB');
})
.catch(err => {
  console.error('❌ MongoDB connection error:', err);
  process.exit(1);
});

// Schéma utilisateur
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

// Test de santé
app.get('/health', (req, res) => {
  res.json({
    success: true,
    message: 'Server is running',
    timestamp: new Date().toISOString(),
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// Inscription
app.post('/api/register', async (req, res) => {
  try {
    console.log('📝 Registration attempt:', req.body);
    
    const {
      civilite, ime, priimek, dateNaissance, numeroId,
      pays, ville, adresse, telephone, email, motDePasse
    } = req.body;

    // Validation des champs requis
    if (!civilite || !ime || !priimek || !dateNaissance || !numeroId || 
        !pays || !ville || !adresse || !telephone || !email || !motDePasse) {
      return res.status(400).json({
        success: false,
        message: 'Vsa polja so obvezna'
      });
    }

    // Vérifier si l'utilisateur existe déjà
    const existingUser = await User.findOne({
      $or: [{ email }, { numeroId }]
    });

    if (existingUser) {
      console.log('❌ User already exists:', { email, numeroId });
      return res.status(400).json({
        success: false,
        message: 'Uporabnik s to e-pošto ali ID že obstaja'
      });
    }

    // Hasher le mot de passe
    const hashedPassword = await bcrypt.hash(motDePasse, 12);

    // Créer nouvel utilisateur
    const newUser = new User({
      civilite, ime, priimek, dateNaissance, numeroId,
      pays, ville, adresse, telephone, email,
      motDePasse: hashedPassword
    });

    await newUser.save();
    console.log('✅ User registered successfully:', newUser.email);

    res.status(201).json({
      success: true,
      message: 'Registracija uspešna! Vaš račun je v obravnavi.'
    });

  } catch (error) {
    console.error('❌ Registration error:', error);
    
    if (error.code === 11000) {
      return res.status(400).json({
        success: false,
        message: 'E-pošta ali ID že obstaja'
      });
    }
    
    res.status(500).json({
      success: false,
      message: 'Napaka strežnika pri registraciji'
    });
  }
});

// Connexion
app.post('/api/login', async (req, res) => {
  try {
    console.log('🔐 Login attempt:', req.body);
    const { username, password } = req.body;

    // Compte admin par défaut
    if (username === 'admin' && password === 'admin') {
      const token = jwt.sign(
        { userId: 'admin', isAdmin: true },
        process.env.JWT_SECRET || 'default-secret',
        { expiresIn: '24h' }
      );

      console.log('✅ Admin login successful');
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
      console.log('❌ User not found:', username);
      return res.status(401).json({
        success: false,
        message: 'Napačni podatki'
      });
    }

    // Vérifier le mot de passe
    const isValidPassword = await bcrypt.compare(password, user.motDePasse);
    if (!isValidPassword) {
      console.log('❌ Invalid password for user:', username);
      return res.status(401).json({
        success: false,
        message: 'Napačni podatki'
      });
    }

    // Vérifier le statut du compte
    if (user.status === 'blocked') {
      console.log('❌ Blocked user attempted login:', username);
      return res.status(403).json({
        success: false,
        message: 'Vaš račun je blokiran'
      });
    }

    if (user.status === 'pending') {
      console.log('❌ Pending user attempted login:', username);
      return res.status(403).json({
        success: false,
        message: 'Vaš račun je še vedno v obravnavi'
      });
    }

    // Générer token
    const token = jwt.sign(
      { userId: user._id, isAdmin: false },
      process.env.JWT_SECRET || 'default-secret',
      { expiresIn: '24h' }
    );

    console.log('✅ User login successful:', user.email);
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
    console.error('❌ Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Napaka strežnika pri prijavi'
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

  jwt.verify(token, process.env.JWT_SECRET || 'default-secret', (err, user) => {
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

    console.log('📊 Admin fetched users:', users.length);
    res.json({ success: true, users });
  } catch (error) {
    console.error('❌ Error fetching users:', error);
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

    console.log('✅ User approved:', user.email, 'Account:', accountNumber);
    res.json({ success: true, message: 'Uporabnik odobren', user });
  } catch (error) {
    console.error('❌ Error approving user:', error);
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

    console.log('🚫 User blocked:', user.email);
    res.json({ success: true, message: 'Uporabnik blokiran', user });
  } catch (error) {
    console.error('❌ Error blocking user:', error);
    res.status(500).json({ success: false, message: 'Napaka strežnika' });
  }
});

app.post('/api/admin/unblock-user/:userId', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({ success: false, message: 'Dostop zavrnjen' });
    }

    const { userId } = req.params;

    const user = await User.findByIdAndUpdate(
      userId,
      { status: 'approved' },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ success: false, message: 'Uporabnik ni najden' });
    }

    console.log('✅ User unblocked:', user.email);
    res.json({ success: true, message: 'Uporabnik odblokiran', user });
  } catch (error) {
    console.error('❌ Error unblocking user:', error);
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

    console.log('💰 Balance updated for user:', user.email, 'New balance:', balance);
    res.json({ success: true, message: 'Stanje posodobljeno', user });
  } catch (error) {
    console.error('❌ Error updating balance:', error);
    res.status(500).json({ success: false, message: 'Napaka strežnika' });
  }
});

app.post('/api/admin/update-account/:userId', authenticateToken, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({ success: false, message: 'Dostop zavrnjen' });
    }

    const { userId } = req.params;
    const { accountNumber } = req.body;

    const user = await User.findByIdAndUpdate(
      userId,
      { accountNumber: accountNumber },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ success: false, message: 'Uporabnik ni najden' });
    }

    console.log('🔢 Account number updated for user:', user.email, 'New account:', accountNumber);
    res.json({ success: true, message: 'Številka računa posodobljena', user });
  } catch (error) {
    console.error('❌ Error updating account number:', error);
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
    console.error('❌ Error fetching user profile:', error);
    res.status(500).json({ success: false, message: 'Napaka strežnika' });
  }
});

// Contact
app.post('/api/contact', async (req, res) => {
  try {
    const { ime, email, sporocilo } = req.body;
    
    console.log('📧 New contact message:', { ime, email, sporocilo });
    
    res.json({
      success: true,
      message: 'Sporočilo uspešno poslano!'
    });
  } catch (error) {
    console.error('❌ Error sending contact message:', error);
    res.status(500).json({
      success: false,
      message: 'Napaka strežnika'
    });
  }
});

// Gestionnaire d'erreurs global
app.use((err, req, res, next) => {
  console.error('💥 Unhandled error:', err);
  res.status(500).json({
    success: false,
    message: 'Napaka strežnika'
  });
});

// Route 404
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found'
  });
});

// Démarrer le serveur
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌐 Application available at: http://localhost:${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
});
