const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const cors = require('cors');
const path = require('path');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5001;

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/your_database_name')
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  googleId: String,
  displayName: String,
  email: String,
  photo: String,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Debug environment variables
console.log('Environment check:');
console.log('Client ID available:', !!process.env.GOOGLE_CLIENT_ID);
console.log('Client Secret available:', !!process.env.GOOGLE_CLIENT_SECRET);

// Middleware
app.use(express.json());
app.use(cors({
  origin: process.env.NODE_ENV === 'production'
    ? ['https://truck-xddp.onrender.com', 'http://localhost:5173']
    : 'http://localhost:5173',
  credentials: true
}));

app.use(session({
  secret: process.env.SESSION_SECRET || 'your_secret_key',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI || 'mongodb://localhost:27017/your_database_name',
    ttl: 24 * 60 * 60 // 1 day
  }),
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
  }
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Serialize and deserialize user
passport.serializeUser((user, done) => {
  console.log('Serializing user:', user._id);
  done(null, user._id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    if (!user) {
      console.log('User not found during deserialization');
      return done(null, false);
    }
    console.log('User found:', user.displayName || user.email);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Add JWT secret key to environment variables
const JWT_SECRET = process.env.JWT_SECRET || 'your-jwt-secret-key';

// Modify the Google OAuth Strategy to use JWT
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: 'https://truck-xddp.onrender.com/auth/google/callback'
},
  async (accessToken, refreshToken, profile, done) => {
    try {
      console.log('Google authentication successful');
      console.log('Profile:', profile.displayName);

      let user = await User.findOne({ googleId: profile.id });

      if (!user) {
        user = await User.create({
          googleId: profile.id,
          displayName: profile.displayName,
          email: profile.emails && profile.emails[0] ? profile.emails[0].value : '',
          photo: profile.photos && profile.photos[0] ? profile.photos[0].value : ''
        });
        console.log('New user created:', user.displayName);
      } else {
        console.log('Existing user found:', user.displayName);
      }

      // Generate JWT token
      const token = jwt.sign(
        {
          id: user._id,
          email: user.email,
          displayName: user.displayName
        },
        JWT_SECRET,
        { expiresIn: '24h' }
      );

      // Attach token to user object
      user.token = token;
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));

// Routes
app.get('/auth/google',
  (req, res, next) => {
    console.log('Starting Google authentication flow');
    next();
  },
  passport.authenticate('google', {
    scope: ['profile', 'email'],
    prompt: 'select_account'
  })
);

// Modify the Google callback route to return token
app.get('/auth/google/callback',
  passport.authenticate('google', {
    failureRedirect: 'http://localhost:5173/login',
    failWithError: true
  }),
  (req, res) => {
    console.log('Authentication successful, user:', req.user);

    // Redirect with token as query parameter
    const token = req.user.token;
    res.redirect(`http://localhost:5173/dashboard?token=${token}`);
  },
  (err, req, res, next) => {
    console.error('Google authentication error:', err);
    res.redirect('http://localhost:5173/login?error=' + encodeURIComponent(err.message));
  }
);

// Add middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token' });
  }
};

// Modify the user route to use token verification
app.get('/auth/user', verifyToken, (req, res) => {
  res.json(req.user);
});

// Modify the login route to use JWT
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email and password are required' });
  }

  // Mock authentication - in a real app, you'd check against a database
  if (email === 'test@example.com' && password === 'password') {
    const user = {
      id: 999,
      email: 'test@example.com',
      displayName: 'Test User'
    };

    // Generate JWT token
    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        displayName: user.displayName
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    return res.json({
      success: true,
      user,
      token
    });
  } else {
    return res.status(401).json({ success: false, message: 'Invalid credentials' });
  }
});

// Modify logout to be token-based
app.post('/auth/logout', verifyToken, (req, res) => {
  // Since we're using JWT, we don't need to do anything server-side
  // The client should remove the token from localStorage
  res.json({ success: true });
});

// Add a test route to check authentication
app.get('/auth/test', (req, res) => {
  console.log('Session:', req.session);
  console.log('User:', req.user);
  console.log('Is authenticated:', req.isAuthenticated());
  res.json({
    authenticated: req.isAuthenticated(),
    session: req.session,
    user: req.user
  });
});

// Create a static route for serving uploaded files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Google callback URL: http://localhost:${PORT}/auth/google/callback`);
}); 