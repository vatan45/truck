const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const cors = require('cors');
const path = require('path');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs-extra');
const Razorpay = require('razorpay');
const crypto = require('crypto');
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
  createdAt: { type: Date, default: Date.now },
  fullName: String,
  phoneNumber: String,
  drivingLicenseNumber: String,
  aadharNumber: String,
  dateOfBirth: Date,
  address: String,
  city: String,
  state: String,
  pincode: String,
  profilePhoto: {
    data: Buffer,
    contentType: String
  },
  drivingLicensePhoto: {
    data: Buffer,
    contentType: String
  }
});

const User = mongoose.model('User', userSchema);

// First, let's create a Policy Schema
const policySchema = new mongoose.Schema({
  policyName: {
    type: String,
    required: true
  },
  policyType: {
    type: String,
    required: true,
    enum: ['Comprehensive', 'Third Party', 'Liability', 'Personal Accident']
  },
  description: {
    type: String,
    required: true
  },
  coverage: {
    type: String,
    required: true
  },
  premium: {
    type: Number,
    required: true
  },
  duration: {
    type: Number,
    required: true,
    comment: 'Duration in months'
  },
  features: [{
    type: String
  }],
  termsAndConditions: [{
    type: String
  }],
  isActive: {
    type: Boolean,
    default: true
  }
});

const Policy = mongoose.model('Policy', policySchema);

// Create a Purchase Schema to track policy purchases
const purchaseSchema = new mongoose.Schema({
  userId: {
    type: String,
    required: true
  },
  policyId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Policy',
    required: true
  },
  purchaseDate: {
    type: Date,
    default: Date.now
  },
  startDate: {
    type: Date,
    required: true
  },
  endDate: {
    type: Date,
    required: true
  },
  status: {
    type: String,
    enum: ['Active', 'Expired', 'Cancelled'],
    default: 'Active'
  },
  paymentStatus: {
    type: String,
    enum: ['Pending', 'Completed', 'Failed'],
    default: 'Pending'
  },
  paymentDetails: {
    amount: Number,
    transactionId: String,
    paymentDate: Date
  }
});

const Purchase = mongoose.model('Purchase', purchaseSchema);

// Initialize Razorpay
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// Payment Schema
const paymentSchema = new mongoose.Schema({
  userId: {
    type: String,
    required: true
  },
  policyId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Policy'
  },
  loanId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Loan'
  },
  amount: {
    type: Number,
    required: true
  },
  currency: {
    type: String,
    default: 'INR'
  },
  razorpayOrderId: String,
  razorpayPaymentId: String,
  razorpaySignature: String,
  status: {
    type: String,
    enum: ['Pending', 'Completed', 'Failed', 'Refunded'],
    default: 'Pending'
  },
  paymentType: {
    type: String,
    enum: ['Policy', 'Loan', 'Renewal'],
    required: true
  },
  paymentDate: {
    type: Date,
    default: Date.now
  },
  dueDate: Date,
  reminderSent: {
    type: Boolean,
    default: false
  }
});

const Payment = mongoose.model('Payment', paymentSchema);

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
    failureRedirect: process.env.NODE_ENV === 'production'
      ? 'https://truck-xddp.onrender.com/login'
      : 'http://localhost:5173/login',
    failWithError: true
  }),
  (req, res) => {
    console.log('Authentication successful, user:', req.user);
    const token = req.user.token;
    const redirectUrl = process.env.NODE_ENV === 'production'
      ? `https://truck-xddp.onrender.com/dashboard?token=${token}`
      : `http://localhost:5173/dashboard?token=${token}`;
    res.redirect(redirectUrl);
  },
  (err, req, res, next) => {
    console.error('Google authentication error:', err);
    const errorRedirect = process.env.NODE_ENV === 'production'
      ? 'https://truck-xddp.onrender.com/login'
      : 'http://localhost:5173/login';
    res.redirect(`${errorRedirect}?error=${encodeURIComponent(err.message)}`);
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

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'uploads');
fs.ensureDirSync(uploadsDir);

// Configure multer storage
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  }
});

// Add route to update user details (public version)
app.post('/api/user/details', upload.fields([
  { name: 'profilePhoto', maxCount: 1 },
  { name: 'drivingLicensePhoto', maxCount: 1 }
]), async (req, res) => {
  try {
    // Get userId from request body instead of req.user
    const { userId, fullName, phoneNumber, drivingLicenseNumber, aadharNumber,
      dateOfBirth, address, city, state, pincode } = req.body;

    // Validate userId is provided
    if (!userId) {
      return res.status(400).json({
        success: false,
        message: 'User ID is required'
      });
    }

    // Validate required fields
    if (!fullName || !phoneNumber || !drivingLicenseNumber || !aadharNumber ||
      !dateOfBirth || !address || !city || !state || !pincode) {
      return res.status(400).json({
        success: false,
        message: 'All fields are required'
      });
    }

    // Validate Aadhar number (12 digits)
    if (!/^\d{12}$/.test(aadharNumber)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid Aadhar number'
      });
    }

    // Validate phone number (10 digits)
    if (!/^\d{10}$/.test(phoneNumber)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid phone number'
      });
    }

    // Validate pincode (6 digits)
    if (!/^\d{6}$/.test(pincode)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid pincode'
      });
    }

    // Prepare update object
    const updateData = {
      fullName,
      phoneNumber,
      drivingLicenseNumber,
      aadharNumber,
      dateOfBirth: new Date(dateOfBirth),
      address,
      city,
      state,
      pincode
    };

    // Handle file uploads if present
    if (req.files) {
      if (req.files.profilePhoto) {
        updateData.profilePhoto = {
          data: req.files.profilePhoto[0].buffer,
          contentType: req.files.profilePhoto[0].mimetype
        };
      }
      if (req.files.drivingLicensePhoto) {
        updateData.drivingLicensePhoto = {
          data: req.files.drivingLicensePhoto[0].buffer,
          contentType: req.files.drivingLicensePhoto[0].mimetype
        };
      }
    }

    // Update user in database
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      updateData,
      { new: true, runValidators: true }
    );

    if (!updatedUser) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      message: 'User details updated successfully',
      user: updatedUser
    });

  } catch (error) {
    console.error('Error updating user details:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating user details',
      error: error.message
    });
  }
});

// Add route to get user details
app.get('/api/user/details', async (req, res) => {
  try {
    const userId = req.query.userId; // Get userId from query parameter

    if (!userId) {
      return res.status(400).json({
        success: false,
        message: 'User ID is required'
      });
    }

    // Find user by ID and select only the necessary fields
    const user = await User.findById(userId).select({
      fullName: 1,
      email: 1,
      phoneNumber: 1,
      drivingLicenseNumber: 1,
      aadharNumber: 1,
      dateOfBirth: 1,
      address: 1,
      city: 1,
      state: 1,
      pincode: 1,
      profilePhoto: 1,
      drivingLicensePhoto: 1,
      photo: 1, // Google profile photo if available
      displayName: 1 // Google display name if available
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Format the response
    const userDetails = {
      success: true,
      data: {
        fullName: user.fullName,
        email: user.email,
        phoneNumber: user.phoneNumber,
        drivingLicenseNumber: user.drivingLicenseNumber,
        aadharNumber: user.aadharNumber,
        dateOfBirth: user.dateOfBirth,
        address: user.address,
        city: user.city,
        state: user.state,
        pincode: user.pincode,
        profilePhoto: user.profilePhoto || user.photo, // Use uploaded photo or Google photo
        drivingLicensePhoto: user.drivingLicensePhoto,
        displayName: user.displayName
      }
    };

    res.json(userDetails);

  } catch (error) {
    console.error('Error fetching user details:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching user details',
      error: error.message
    });
  }
});

// Add a route to serve images from MongoDB
app.get('/api/user/image/:userId/:imageType', async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const imageData = req.params.imageType === 'profile'
      ? user.profilePhoto
      : user.drivingLicensePhoto;

    if (!imageData || !imageData.data) {
      return res.status(404).json({ message: 'Image not found' });
    }

    res.set('Content-Type', imageData.contentType);
    res.send(imageData.data);
  } catch (error) {
    res.status(500).json({ message: 'Error serving image' });
  }
});

// Add this route alongside your existing /api/user/details route
app.post('/api/users/details', verifyToken, upload.fields([
  { name: 'profilePhoto', maxCount: 1 },
  { name: 'drivingLicensePhoto', maxCount: 1 }
]), async (req, res) => {
  try {
    const userId = req.user.id;
    const {
      fullName,
      phoneNumber,
      drivingLicenseNumber,
      aadharNumber,
      dateOfBirth,
      address,
      city,
      state,
      pincode
    } = req.body;

    // Validate required fields
    if (!fullName || !phoneNumber || !drivingLicenseNumber || !aadharNumber ||
      !dateOfBirth || !address || !city || !state || !pincode) {
      return res.status(400).json({
        success: false,
        message: 'All fields are required'
      });
    }

    // Validate Aadhar number (12 digits)
    if (!/^\d{12}$/.test(aadharNumber)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid Aadhar number'
      });
    }

    // Validate phone number (10 digits)
    if (!/^\d{10}$/.test(phoneNumber)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid phone number'
      });
    }

    // Validate pincode (6 digits)
    if (!/^\d{6}$/.test(pincode)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid pincode'
      });
    }

    // Prepare update object
    const updateData = {
      fullName,
      phoneNumber,
      drivingLicenseNumber,
      aadharNumber,
      dateOfBirth: new Date(dateOfBirth),
      address,
      city,
      state,
      pincode
    };

    // Handle file uploads if present
    if (req.files) {
      if (req.files.profilePhoto) {
        updateData.profilePhoto = {
          data: req.files.profilePhoto[0].buffer,
          contentType: req.files.profilePhoto[0].mimetype
        };
      }
      if (req.files.drivingLicensePhoto) {
        updateData.drivingLicensePhoto = {
          data: req.files.drivingLicensePhoto[0].buffer,
          contentType: req.files.drivingLicensePhoto[0].mimetype
        };
      }
    }

    // Update user in database
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      updateData,
      { new: true, runValidators: true }
    );

    if (!updatedUser) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      message: 'User details updated successfully',
      user: updatedUser
    });

  } catch (error) {
    console.error('Error updating user details:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating user details',
      error: error.message
    });
  }
});

// API Routes for Policies

// 1. Get all available policies
app.get('/api/policies', async (req, res) => {
  try {
    const policies = await Policy.find({ isActive: true })
      .select('policyName policyType description premium duration features');

    res.json({
      success: true,
      data: policies
    });
  } catch (error) {
    console.error('Error fetching policies:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching policies',
      error: error.message
    });
  }
});

// 2. Get detailed information about a specific policy
app.get('/api/policies/:policyId', async (req, res) => {
  try {
    const policy = await Policy.findById(req.params.policyId);

    if (!policy) {
      return res.status(404).json({
        success: false,
        message: 'Policy not found'
      });
    }

    res.json({
      success: true,
      data: policy
    });
  } catch (error) {
    console.error('Error fetching policy details:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching policy details',
      error: error.message
    });
  }
});

// 3. Purchase a policy
app.post('/api/policies/purchase', async (req, res) => {
  try {
    const { policyId, startDate, userId } = req.body;

    // Validate required fields
    if (!policyId || !startDate || !userId) {
      return res.status(400).json({
        success: false,
        message: 'Policy ID, start date, and user ID are required'
      });
    }

    // Validate policy exists
    const policy = await Policy.findById(policyId);
    if (!policy) {
      return res.status(404).json({
        success: false,
        message: 'Policy not found'
      });
    }

    // Calculate end date based on policy duration
    const endDate = new Date(startDate);
    endDate.setMonth(endDate.getMonth() + policy.duration);

    // Create purchase record
    const purchase = new Purchase({
      userId,
      policyId,
      startDate,
      endDate,
      paymentDetails: {
        amount: policy.premium
      }
    });

    await purchase.save();

    res.json({
      success: true,
      message: 'Policy purchase initiated successfully',
      data: {
        purchaseId: purchase._id,
        policyDetails: {
          name: policy.policyName,
          type: policy.policyType,
          premium: policy.premium,
          duration: policy.duration
        },
        startDate: purchase.startDate,
        endDate: purchase.endDate
      }
    });
  } catch (error) {
    console.error('Error purchasing policy:', error);
    res.status(500).json({
      success: false,
      message: 'Error purchasing policy',
      error: error.message
    });
  }
});

// 4. Get user's purchased policies
app.get('/api/policies/user/purchases', async (req, res) => {
  try {
    const { userId } = req.query;

    if (!userId) {
      return res.status(400).json({
        success: false,
        message: 'User ID is required'
      });
    }

    const purchases = await Purchase.find({ userId })
      .populate('policyId', 'policyName policyType premium duration')
      .sort({ purchaseDate: -1 });

    res.json({
      success: true,
      data: purchases
    });
  } catch (error) {
    console.error('Error fetching user purchases:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching user purchases',
      error: error.message
    });
  }
});

// 5. Update payment status for a purchase
app.patch('/api/policies/purchase/:purchaseId/payment', async (req, res) => {
  try {
    const { purchaseId } = req.params;
    const { paymentStatus, transactionId, userId } = req.body;

    if (!userId) {
      return res.status(400).json({
        success: false,
        message: 'User ID is required'
      });
    }

    const purchase = await Purchase.findById(purchaseId);

    if (!purchase) {
      return res.status(404).json({
        success: false,
        message: 'Purchase not found'
      });
    }

    // Verify the purchase belongs to the user
    if (purchase.userId !== userId) {
      return res.status(403).json({
        success: false,
        message: 'Unauthorized access'
      });
    }

    purchase.paymentStatus = paymentStatus;
    if (transactionId) {
      purchase.paymentDetails.transactionId = transactionId;
      purchase.paymentDetails.paymentDate = new Date();
    }

    await purchase.save();

    res.json({
      success: true,
      message: 'Payment status updated successfully',
      data: purchase
    });
  } catch (error) {
    console.error('Error updating payment status:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating payment status',
      error: error.message
    });
  }
});

// 1. My Account APIs
app.get('/api/account/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    // Get user details
    const user = await User.findById(userId).select('-profilePhoto.data -drivingLicensePhoto.data');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Get active policies count
    const activePolicies = await Purchase.countDocuments({
      userId,
      status: 'Active',
      paymentStatus: 'Completed'
    });

    // Get total premium amount
    const totalPremium = await Purchase.aggregate([
      { $match: { userId, paymentStatus: 'Completed' } },
      {
        $lookup: {
          from: 'policies',
          localField: 'policyId',
          foreignField: '_id',
          as: 'policy'
        }
      },
      { $unwind: '$policy' },
      {
        $group: {
          _id: null,
          total: { $sum: '$policy.premium' }
        }
      }
    ]);

    res.json({
      success: true,
      data: {
        userDetails: user,
        accountSummary: {
          activePolicies,
          totalPremium: totalPremium[0]?.total || 0
        }
      }
    });
  } catch (error) {
    console.error('Error fetching account details:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching account details',
      error: error.message
    });
  }
});

// 2. My Policies APIs
app.get('/api/account/:userId/policies', async (req, res) => {
  try {
    const { userId } = req.params;
    const { status } = req.query; // Optional filter by status

    const query = { userId };
    if (status) {
      query.status = status;
    }

    const policies = await Purchase.find(query)
      .populate('policyId')
      .sort({ purchaseDate: -1 });

    res.json({
      success: true,
      data: policies
    });
  } catch (error) {
    console.error('Error fetching user policies:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching user policies',
      error: error.message
    });
  }
});

// 3. Help/Support Section APIs
// First, create a Support Ticket Schema
const supportTicketSchema = new mongoose.Schema({
  userId: {
    type: String,
    required: true
  },
  subject: {
    type: String,
    required: true
  },
  description: {
    type: String,
    required: true
  },
  category: {
    type: String,
    enum: ['Policy', 'Payment', 'Technical', 'Other'],
    required: true
  },
  status: {
    type: String,
    enum: ['Open', 'In Progress', 'Resolved', 'Closed'],
    default: 'Open'
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  responses: [{
    message: String,
    responder: String,
    timestamp: {
      type: Date,
      default: Date.now
    }
  }]
});

const SupportTicket = mongoose.model('SupportTicket', supportTicketSchema);

// Create support ticket
app.post('/api/support/tickets', async (req, res) => {
  try {
    const { userId, subject, description, category } = req.body;

    const ticket = new SupportTicket({
      userId,
      subject,
      description,
      category
    });

    await ticket.save();

    res.json({
      success: true,
      message: 'Support ticket created successfully',
      data: ticket
    });
  } catch (error) {
    console.error('Error creating support ticket:', error);
    res.status(500).json({
      success: false,
      message: 'Error creating support ticket',
      error: error.message
    });
  }
});

// Get user's support tickets
app.get('/api/support/tickets/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const tickets = await SupportTicket.find({ userId })
      .sort({ createdAt: -1 });

    res.json({
      success: true,
      data: tickets
    });
  } catch (error) {
    console.error('Error fetching support tickets:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching support tickets',
      error: error.message
    });
  }
});

// 4. Loan Detail APIs
// First, create a Loan Schema
const loanSchema = new mongoose.Schema({
  userId: {
    type: String,
    required: true
  },
  policyId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Policy',
    required: true
  },
  amount: {
    type: Number,
    required: true
  },
  interestRate: {
    type: Number,
    required: true
  },
  term: {
    type: Number,
    required: true,
    comment: 'Term in months'
  },
  status: {
    type: String,
    enum: ['Pending', 'Approved', 'Rejected', 'Active', 'Paid'],
    default: 'Pending'
  },
  startDate: Date,
  endDate: Date,
  monthlyPayment: Number,
  remainingAmount: Number,
  paymentHistory: [{
    amount: Number,
    date: Date,
    status: String
  }]
});

const Loan = mongoose.model('Loan', loanSchema);

// Get loan details
app.get('/api/loans/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const loans = await Loan.find({ userId })
      .populate('policyId')
      .sort({ startDate: -1 });

    res.json({
      success: true,
      data: loans
    });
  } catch (error) {
    console.error('Error fetching loan details:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching loan details',
      error: error.message
    });
  }
});

// Apply for a loan
app.post('/api/loans/apply', async (req, res) => {
  try {
    const { userId, policyId, amount, term } = req.body;

    // Calculate interest rate (example: 8% per annum)
    const interestRate = 8;
    const monthlyRate = interestRate / 12 / 100;
    const monthlyPayment = (amount * monthlyRate * Math.pow(1 + monthlyRate, term)) /
      (Math.pow(1 + monthlyRate, term) - 1);

    const loan = new Loan({
      userId,
      policyId,
      amount,
      interestRate,
      term,
      monthlyPayment,
      remainingAmount: amount,
      startDate: new Date()
    });

    await loan.save();

    res.json({
      success: true,
      message: 'Loan application submitted successfully',
      data: loan
    });
  } catch (error) {
    console.error('Error applying for loan:', error);
    res.status(500).json({
      success: false,
      message: 'Error applying for loan',
      error: error.message
    });
  }
});

// 5. Profile Details APIs
app.get('/api/profile/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await User.findById(userId)
      .select('-profilePhoto.data -drivingLicensePhoto.data');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Get user's active policies count
    const activePolicies = await Purchase.countDocuments({
      userId,
      status: 'Active',
      paymentStatus: 'Completed'
    });

    // Get user's active loans
    const activeLoans = await Loan.countDocuments({
      userId,
      status: 'Active'
    });

    res.json({
      success: true,
      data: {
        userDetails: user,
        statistics: {
          activePolicies,
          activeLoans
        }
      }
    });
  } catch (error) {
    console.error('Error fetching profile details:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching profile details',
      error: error.message
    });
  }
});

// 1. First Payment Setup API
app.post('/api/payments/setup', async (req, res) => {
  try {
    const { userId, policyId, amount, paymentType } = req.body;

    // Create Razorpay Order
    const options = {
      amount: amount * 100, // Razorpay expects amount in paise
      currency: 'INR',
      receipt: `receipt_${Date.now()}`,
      notes: {
        userId,
        policyId,
        paymentType
      }
    };

    const order = await razorpay.orders.create(options);

    // Create payment record
    const payment = new Payment({
      userId,
      policyId,
      amount,
      razorpayOrderId: order.id,
      paymentType,
      dueDate: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours from now
    });

    await payment.save();

    res.json({
      success: true,
      message: 'Payment setup successful',
      data: {
        orderId: order.id,
        amount: order.amount,
        currency: order.currency,
        paymentId: payment._id
      }
    });
  } catch (error) {
    console.error('Error setting up payment:', error);
    res.status(500).json({
      success: false,
      message: 'Error setting up payment',
      error: error.message
    });
  }
});

// 2. Verify and Complete Payment
app.post('/api/payments/verify', async (req, res) => {
  try {
    const {
      razorpayOrderId,
      razorpayPaymentId,
      razorpaySignature,
      paymentId
    } = req.body;

    // Verify signature
    const generatedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(`${razorpayOrderId}|${razorpayPaymentId}`)
      .digest('hex');

    if (generatedSignature !== razorpaySignature) {
      return res.status(400).json({
        success: false,
        message: 'Invalid payment signature'
      });
    }

    // Update payment record
    const payment = await Payment.findById(paymentId);
    if (!payment) {
      return res.status(404).json({
        success: false,
        message: 'Payment record not found'
      });
    }

    payment.razorpayPaymentId = razorpayPaymentId;
    payment.razorpaySignature = razorpaySignature;
    payment.status = 'Completed';
    await payment.save();

    // Update related records based on payment type
    if (payment.paymentType === 'Policy') {
      await Purchase.findByIdAndUpdate(payment.policyId, {
        paymentStatus: 'Completed',
        'paymentDetails.transactionId': razorpayPaymentId,
        'paymentDetails.paymentDate': new Date()
      });
    } else if (payment.paymentType === 'Loan') {
      await Loan.findByIdAndUpdate(payment.loanId, {
        $push: {
          paymentHistory: {
            amount: payment.amount,
            date: new Date(),
            status: 'Completed'
          }
        },
        $inc: { remainingAmount: -payment.amount }
      });
    }

    res.json({
      success: true,
      message: 'Payment verified and completed successfully',
      data: payment
    });
  } catch (error) {
    console.error('Error verifying payment:', error);
    res.status(500).json({
      success: false,
      message: 'Error verifying payment',
      error: error.message
    });
  }
});

// 3. Monthly Payment System
app.post('/api/payments/monthly', async (req, res) => {
  try {
    const { userId, policyId, amount } = req.body;

    // Create Razorpay Order for monthly payment
    const options = {
      amount: amount * 100,
      currency: 'INR',
      receipt: `monthly_${Date.now()}`,
      notes: {
        userId,
        policyId,
        paymentType: 'Monthly'
      }
    };

    const order = await razorpay.orders.create(options);

    // Create payment record
    const payment = new Payment({
      userId,
      policyId,
      amount,
      razorpayOrderId: order.id,
      paymentType: 'Policy',
      dueDate: new Date(Date.now() + 24 * 60 * 60 * 1000)
    });

    await payment.save();

    res.json({
      success: true,
      message: 'Monthly payment setup successful',
      data: {
        orderId: order.id,
        amount: order.amount,
        currency: order.currency,
        paymentId: payment._id
      }
    });
  } catch (error) {
    console.error('Error setting up monthly payment:', error);
    res.status(500).json({
      success: false,
      message: 'Error setting up monthly payment',
      error: error.message
    });
  }
});

// 4. Payment Reminders
app.get('/api/payments/reminders', async (req, res) => {
  try {
    const { userId } = req.query;

    // Find pending payments that are due
    const duePayments = await Payment.find({
      userId,
      status: 'Pending',
      dueDate: { $lte: new Date() },
      reminderSent: false
    }).populate('policyId', 'policyName');

    // Update reminder status
    await Payment.updateMany(
      { _id: { $in: duePayments.map(p => p._id) } },
      { $set: { reminderSent: true } }
    );

    res.json({
      success: true,
      data: duePayments
    });
  } catch (error) {
    console.error('Error fetching payment reminders:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching payment reminders',
      error: error.message
    });
  }
});

// 5. Full Payment History
app.get('/api/payments/history', async (req, res) => {
  try {
    const { userId } = req.query;
    const { startDate, endDate, status, paymentType } = req.query;

    // Build query
    const query = { userId };
    if (startDate && endDate) {
      query.paymentDate = {
        $gte: new Date(startDate),
        $lte: new Date(endDate)
      };
    }
    if (status) query.status = status;
    if (paymentType) query.paymentType = paymentType;

    const payments = await Payment.find(query)
      .populate('policyId', 'policyName')
      .populate('loanId')
      .sort({ paymentDate: -1 });

    // Calculate summary
    const summary = await Payment.aggregate([
      { $match: { userId } },
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 },
          totalAmount: { $sum: '$amount' }
        }
      }
    ]);

    res.json({
      success: true,
      data: {
        payments,
        summary: summary.reduce((acc, curr) => {
          acc[curr._id] = {
            count: curr.count,
            totalAmount: curr.totalAmount
          };
          return acc;
        }, {})
      }
    });
  } catch (error) {
    console.error('Error fetching payment history:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching payment history',
      error: error.message
    });
  }
});

// 6. Get Payment Details
app.get('/api/payments/:paymentId', async (req, res) => {
  try {
    const { paymentId } = req.params;

    const payment = await Payment.findById(paymentId)
      .populate('policyId', 'policyName')
      .populate('loanId');

    if (!payment) {
      return res.status(404).json({
        success: false,
        message: 'Payment not found'
      });
    }

    res.json({
      success: true,
      data: payment
    });
  } catch (error) {
    console.error('Error fetching payment details:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching payment details',
      error: error.message
    });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Google callback URL: http://localhost:${PORT}/auth/google/callback`);
}); 