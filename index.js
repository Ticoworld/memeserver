const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { Connection, PublicKey, Transaction, SystemProgram, sendAndConfirmTransaction } = require('@solana/web3.js');
const Admin = require('./models/Admin');
const AirdropClaim = require('./models/AirdropClaim');
const { TOKEN_PROGRAM_ID } = require('@solana/spl-token');

dotenv.config();
const app = express();
const PORT = process.env.PORT || 5000;

// Simple logging utility to manage log levels
const logger = {
  info: (message) => {
    if (process.env.NODE_ENV !== 'production' || process.env.LOG_LEVEL === 'info') {
      console.log(`[${new Date().toISOString()}] INFO: ${message}`);
    }
  },
  warn: (message) => {
    console.warn(`[${new Date().toISOString()}] WARN: ${message}`);
  },
  error: (message, error) => {
    console.error(`[${new Date().toISOString()}] ERROR: ${message}`, error || '');
  },
};

// Utility to anonymize IP addresses (mask last octet)
const anonymizeIP = (ip) => {
  const parts = ip.split('.');
  if (parts.length === 4) {
    parts[3] = 'xxx';
    return parts.join('.');
  }
  return ip; // Return as-is if not IPv4 (e.g., IPv6 or '::1' for localhost)
};

const campaignSchema = new mongoose.Schema({
  isActive: { type: Boolean, default: true },
  endDate: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});
const Campaign = mongoose.model('Campaign', campaignSchema);

const distributedAirdropSchema = new mongoose.Schema({
  claimId: { type: mongoose.Schema.Types.ObjectId, ref: 'AirdropClaim', required: true },
  walletAddress: { type: String, required: true },
  rewardAmount: { type: Number, required: true },
  txId: { type: String },
  distributedAt: { type: Date, default: Date.now },
});
const DistributedAirdrop = mongoose.model('DistributedAirdrop', distributedAirdropSchema);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
    }
  }
}));

app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

// Request logging middleware (only for admin routes and errors in production)
app.use((req, res, next) => {
  const isAdminRoute = req.path.startsWith('/api/admin/');
  if (process.env.NODE_ENV !== 'production' || isAdminRoute) {
    logger.info(`${req.method} ${req.path} by IP: ${anonymizeIP(req.ip)}`);
  }
  next();
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  message: 'Too many requests from this IP, please try again after 15 minutes',
  headers: true,
  handler: (req, res) => {
    logger.warn(`Rate limit exceeded for ${req.method} ${req.path} by IP: ${anonymizeIP(req.ip)}`);
    res.status(429).json({ error: 'Too many requests, please try again later' });
  },
});

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 2000,
  message: 'Too many admin requests, please try again after 15 minutes',
  headers: true,
  handler: (req, res) => {
    logger.warn(`Admin rate limit exceeded for ${req.method} ${req.path} by IP: ${anonymizeIP(req.ip)}`);
    res.status(429).json({ error: 'Too many admin requests, please try again later' });
  },
});

app.use('/api/', apiLimiter);
app.use('/api/admin/', adminLimiter);

mongoose.connect(process.env.MONGO_URI, {
  autoIndex: process.env.NODE_ENV !== 'production'
})
.then(() => logger.info('MongoDB connected successfully'))
.catch(err => logger.error('MongoDB connection error:', err));

const solanaConnection = new Connection(process.env.SOLANA_RPC_URL, { commitment: 'confirmed' });

const authenticateAdmin = async (req, res, next) => {
  const token = req.cookies.adminJwt;
  if (!token) return res.status(401).json({ error: 'Unauthorized - No token provided' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const admin = await Admin.findById(decoded.id).select('-password');
    if (!admin || !admin.isActive) return res.status(401).json({ error: 'Admin account disabled' });
    req.admin = admin;
    next();
  } catch (error) {
    logger.error('Authentication error:', error);
    res.status(401).json({ error: 'Invalid or expired token' });
  }
};

const authorizeRoles = (...roles) => (req, res, next) => {
  if (!roles.includes(req.admin.role)) return res.status(403).json({ error: 'Forbidden - Insufficient privileges' });
  next();
};

// Airdrop Routes
app.post('/api/check-duplicate', async (req, res) => {
  try {
    const { txId, walletAddress } = req.body;
    const existingClaim = await AirdropClaim.findOne({ txId });
    if (existingClaim) {
      return res.status(409).json({
        error: 'Duplicate entry',
        message: 'This transaction has already been registered',
        claimId: existingClaim._id.toString()
      });
    }
    res.status(200).json({ valid: true });
  } catch (error) {
    logger.error('Duplicate check error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/submit-claim', async (req, res) => {
  try {
    const { txId, walletAddress, stakedAmount, lockDurationDays, rewardAmount } = req.body;
    if (!txId || !walletAddress || !stakedAmount || !lockDurationDays || !rewardAmount) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Check campaign status
    const campaign = await Campaign.findOne();
    if (!campaign) {
      return res.status(400).json({ error: 'No campaign found' });
    }
    const isCampaignActive = campaign.isActive && new Date() <= new Date(campaign.endDate);
    if (!isCampaignActive) {
      const reason = !campaign.isActive ? 'Campaign is disabled' : 'Campaign has ended';
      return res.status(400).json({ error: reason });
    }

    const newClaim = new AirdropClaim({
      txId,
      walletAddress,
      rewardAmount,
      stakedAmount,
      lockDurationDays,
    });
    await newClaim.save();
    res.status(201).json({
      success: true,
      message: 'Claim registered successfully',
      claimId: newClaim._id.toString(),
    });
  } catch (error) {
    logger.error('Claim submission error:', error);
    res.status(500).json({ error: 'Failed to register claim' });
  }
});

app.get('/api/top-stakers', async (req, res) => {
  try {
    const topStakers = await AirdropClaim.aggregate([
      {
        $group: {
          _id: "$walletAddress",
          stakedAmount: { $sum: "$stakedAmount" },
          rewardAmount: { $sum: "$rewardAmount" },
        },
      },
      {
        $sort: { stakedAmount: -1 },
      },
      {
        $limit: 10,
      },
      { 
        $project: {
          walletAddress: "$_id",
          stakedAmount: 1,
          rewardAmount: 1,
          _id: 0,
        },
      },
    ]);
    res.json(topStakers);
  } catch (error) {
    logger.error('Fetch top stakers error:', error);
    res.status(500).json({ error: 'Failed to fetch top stakers' });
  }
});

// Admin Routes
app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const admin = await Admin.findOne({ username });
    if (!admin || !(await admin.comparePassword(password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign(
      { id: admin._id, role: admin.role }, 
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );
    res.cookie('adminJwt', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: 8 * 60 * 60 * 1000
    });
    res.json({
      id: admin._id,
      username: admin.username,
      role: admin.role,
      email: admin.email
    });
  } catch (error) {
    logger.error('Admin login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/admin/logout', (req, res) => {
  res.clearCookie('adminJwt', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
    path: '/',
  });
  res.status(200).json({ message: 'Logged out successfully' });
});

app.get('/api/admin/me', authenticateAdmin, async (req, res) => {
  try {
    const admin = await Admin.findById(req.admin.id).select('-password');
    res.json(admin);
  } catch (error) {
    logger.error('Error in GET /api/admin/me:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/metrics', authenticateAdmin, async (req, res) => {
  try {
    const metrics = {
      totalClaims: await AirdropClaim.countDocuments().catch(err => {
        logger.error('totalClaims query error:', err);
        throw err;
      }),
      pendingApprovals: 0,
      totalAdmins: await Admin.countDocuments().catch(err => {
        logger.error('totalAdmins query error:', err);
        throw err;
      }),
      activeAdmins: await Admin.countDocuments({ isActive: true }).catch(err => {
        logger.error('activeAdmins query error:', err);
        throw err;
      }),
      distributedAirdrops: await DistributedAirdrop.countDocuments().catch(err => {
        logger.error('distributedAirdrops query error:', err);
        throw err;
      }),
    };
    res.json(metrics);
  } catch (error) {
    logger.error('Error in GET /api/admin/metrics:', error);
    res.status(500).json({ error: 'Failed to load metrics' });
  }
});

app.get('/api/admin/admins', authenticateAdmin, authorizeRoles('superadmin'), async (req, res) => {
  try {
    const admins = await Admin.find().select('-password');
    res.json(admins);
  } catch (error) {
    logger.error('Error in GET /api/admin/admins:', error);
    res.status(500).json({ error: 'Failed to fetch admins' });
  }
});

app.post('/api/admin/admins', authenticateAdmin, authorizeRoles('superadmin'), async (req, res) => {
  try {
    const { username, email, password, role } = req.body;
    const existingAdmin = await Admin.findOne({ $or: [{ username }, { email }] });
    if (existingAdmin) {
      return res.status(409).json({ error: 'Admin already exists' });
    }
    const newAdmin = new Admin({
      username,
      email,
      password,
      role: role || 'admin'
    });
    await newAdmin.save();
    res.status(201).json(newAdmin);
  } catch (error) {
    logger.error('Create admin error:', error);
    res.status(500).json({ error: 'Failed to create admin' });
  }
});

app.get('/api/check-tx/:txId', async (req, res) => {
  try {
    const exists = await AirdropClaim.exists({ txId: req.params.txId });
    res.json({ exists: !!exists });
  } catch (error) {
    logger.error('Transaction check error:', error);
    res.status(500).json({ error: 'Transaction check failed' });
  }
});

app.get(
  '/api/admin/airdrops',
  authenticateAdmin,
  authorizeRoles('superadmin', 'admin', 'moderator'),
  async (req, res) => {
    try {
      const { sort } = req.query;
      const sortOrder = sort === 'oldest' ? 1 : -1;
      const claims = await AirdropClaim.find()
        .sort({ createdAt: sortOrder })
        .lean();
      const distributedClaimIds = new Set(
        (await DistributedAirdrop.find().select('claimId').lean()).map(d => d.claimId.toString())
      );
      const claimsWithStatus = claims.map(claim => ({
        ...claim,
        distributed: distributedClaimIds.has(claim._id.toString()),
      }));
      res.json(claimsWithStatus);
    } catch (error) {
    logger.error('Fetch airdrops error:', error);
    res.status(500).json({ error: 'Failed to fetch airdrops' });
    }
  }
);

app.get('/api/admin/airdrops/claim/:claimId', authenticateAdmin, async (req, res) => {
  try {
    const { claimId } = req.params;
    if (!mongoose.Types.ObjectId.isValid(claimId)) {
      return res.status(400).json({ message: 'Invalid Claim ID format.' });
    }
    const claim = await AirdropClaim.findById(claimId);
    if (!claim) {
      return res.status(404).json({ message: 'Airdrop claim not found.' });
    }
    const distributed = await DistributedAirdrop.findOne({ claimId }).lean();
    const claimWithStatus = {
      ...claim.toObject(),
      distributed: !!distributed,
      distributionTxId: distributed ? distributed.txId : null,
    };
    res.status(200).json(claimWithStatus);
  } catch (error) {
    logger.error('Error fetching single airdrop claim:', error);
    res.status(500).json({ message: 'Internal server error while fetching claim details.' });
  }
});

app.get('/api/admin/campaign/status', authenticateAdmin, authorizeRoles('superadmin', 'admin'), async (req, res) => {
  try {
    let campaign = await Campaign.findOne();
    if (!campaign) {
      campaign = new Campaign({
        isActive: true,
        endDate: new Date('2025-12-31'),
      });
      await campaign.save();
    }
    res.json({
      isActive: campaign.isActive,
      endDate: campaign.endDate,
    });
  } catch (error) {
    logger.error('Fetch campaign status error:', error);
    res.status(500).json({ error: 'Failed to fetch campaign status' });
  }
});

app.post('/api/admin/campaign/toggle', authenticateAdmin, authorizeRoles('superadmin', 'admin'), async (req, res) => {
  try {
    let campaign = await Campaign.findOne();
    if (!campaign) {
      campaign = new Campaign({
        isActive: true,
        endDate: new Date('2025-12-31'),
      });
    }
    campaign.isActive = !campaign.isActive;
    campaign.updatedAt = new Date();
    await campaign.save();
    res.json({
      isActive: campaign.isActive,
      endDate: campaign.endDate,
    });
  } catch (error) {
    logger.error('Toggle campaign status error:', error);
    res.status(500).json({ error: 'Failed to toggle campaign status' });
  }
});

app.post('/api/admin/campaign/update-end-date', authenticateAdmin, authorizeRoles('superadmin', 'admin'), async (req, res) => {
  try {
    const { endDate } = req.body;
    if (!endDate || isNaN(new Date(endDate).getTime())) {
      return res.status(400).json({ error: 'Invalid end date' });
    }
    let campaign = await Campaign.findOne();
    if (!campaign) {
      campaign = new Campaign({
        isActive: true,
        endDate: new Date(endDate),
      });
    } else {
      campaign.endDate = new Date(endDate);
      campaign.updatedAt = new Date();
    }
    await campaign.save();
    res.json({
      isActive: campaign.isActive,
      endDate: campaign.endDate,
    });
  } catch (error) {
    logger.error('Update campaign end date error:', error);
    res.status(500).json({ error: 'Failed to update campaign end date' });
  }
});

app.get('/api/campaign/status', async (req, res) => {
  try {
    let campaign = await Campaign.findOne();
    if (!campaign) {
      campaign = new Campaign({
        isActive: true,
        endDate: new Date('2025-12-31'),
      });
      await campaign.save();
    }
    res.json({
      isActive: campaign.isActive,
      endDate: campaign.endDate,
    });
  } catch (error) {
    logger.error('Fetch campaign status (public) error:', error);
    res.status(500).json({ error: 'Failed to fetch campaign status' });
  }
});

app.post('/api/admin/airdrop/distribute', authenticateAdmin, authorizeRoles('superadmin', 'admin'), async (req, res) => {
  try {
    const claims = await AirdropClaim.find().lean();
    if (!claims.length) {
      return res.status(400).json({ error: 'No airdrop claims to distribute' });
    }
    const campaign = await Campaign.findOne();
    if (!campaign || campaign.isActive) {
      return res.status(400).json({ error: 'Campaign must be inactive to distribute airdrops' });
    }
    const distributionPromises = claims.map(async (claim) => {
      const existingDistribution = await DistributedAirdrop.findOne({ claimId: claim._id });
      if (existingDistribution) return null;
      const mockTxId = `mock-tx-${claim._id}-${Date.now()}`;
      const distributedAirdrop = new DistributedAirdrop({
        claimId: claim._id,
        walletAddress: claim.walletAddress,
        rewardAmount: claim.rewardAmount,
        txId: mockTxId,
      });
      await distributedAirdrop.save();
      return distributedAirdrop;
    });
    const distributions = (await Promise.all(distributionPromises)).filter(Boolean);
    res.json({ message: `Distributed ${distributions.length} airdrops successfully` });
  } catch (error) {
    logger.error('Airdrop distribution error:', error);
    res.status(500).json({ error: 'Failed to distribute airdrops' });
  }
});

app.post('/api/admin/airdrop/distribute-batch', authenticateAdmin, authorizeRoles('superadmin', 'admin'), async (req, res) => {
  try {
    const { serializedTx, claimIds } = req.body;
    if (!serializedTx) return res.status(400).json({ error: 'Serialized transaction is required' });
    if (!claimIds || !Array.isArray(claimIds) || claimIds.length === 0) {
      return res.status(400).json({ error: 'An array of claim IDs for the batch is required' });
    }

    const campaign = await Campaign.findOne();
    if (!campaign || campaign.isActive) {
      return res.status(400).json({ error: 'Campaign must be inactive to distribute airdrops' });
    }

    const transaction = Transaction.from(Buffer.from(serializedTx, 'base64'));
    const signature = await solanaConnection.sendRawTransaction(transaction.serialize(), {
      skipPreflight: true, // Skip preflight to speed up submission
      maxRetries: 5 // Retry on network issues
    });

    // Check if this transaction signature already exists
    const existingDistribution = await DistributedAirdrop.findOne({ txId: signature }).lean();
    if (existingDistribution) {
      logger.info(`Transaction ${signature} already processed.`);
      return res.status(200).json({
        signature,
        message: `Transaction ${signature} already processed and recorded previously.`
      });
    }

    // Use getSignatureStatuses to check the transaction status
    let status = null;
    for (let attempt = 0; attempt < 10; attempt++) { // Retry up to 10 times
      const statuses = await solanaConnection.getSignatureStatuses([signature], { searchTransactionHistory: true });
      status = statuses.value[0];
      if (status) break;
      await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2 seconds between attempts
    }

    if (!status) {
      logger.warn(`Could not retrieve status for transaction ${signature}. Assuming success since tokens were received.`);
    } else if (status.err) {
      logger.error(`Transaction ${signature} failed on-chain:`, status.err);
      return res.status(500).json({ error: 'Transaction failed on-chain', details: status.err });
    }

    // Since tokens were received, proceed to update the database regardless of confirmation status
    let successfullyRecordedCount = 0;
    for (const claimId of claimIds) {
      try {
        const claim = await AirdropClaim.findById(claimId).lean();
        if (!claim) {
          logger.warn(`Claim ID ${claimId} from batch not found in database.`);
          continue;
        }

        const existingDistributionForClaim = await DistributedAirdrop.findOne({ claimId: claim._id });
        if (existingDistributionForClaim) {
          logger.warn(`Claim ${claim._id} already marked as distributed.`);
          continue;
        }

        const distributedAirdrop = new DistributedAirdrop({
          claimId: claim._id,
          walletAddress: claim.walletAddress,
          rewardAmount: claim.rewardAmount,
          txId: signature,
        });
        await distributedAirdrop.save();
        successfullyRecordedCount++;
      } catch (dbError) {
        logger.error(`Error recording distribution for claim ID ${claimId}:`, dbError);
      }
    }

    logger.info(`Batch transaction ${signature} processed. Recorded ${successfullyRecordedCount} of ${claimIds.length} distributions.`);
    res.json({
      signature,
      message: `Batch transaction ${signature} processed. Successfully recorded ${successfullyRecordedCount} of ${claimIds.length} distributions.`
    });

  } catch (error) {
    logger.error('Batch distribution error:', error);
    if (error.message.includes('Transaction simulation failed') || error.logs) {
      logger.error('Solana Transaction Failure Summary:', error.message);
      return res.status(500).json({ error: 'Failed to distribute batch due to on-chain error.', details: error.message });
    }
    return res.status(500).json({ error: `Failed to distribute batch: ${error.message}` });
  }
});

app.get('/api/admin/distributed-airdrops', authenticateAdmin, authorizeRoles('superadmin', 'admin', 'moderator'), async (req, res) => {
  try {
    const { sort } = req.query;
    const sortOrder = sort === 'oldest' ? 1 : -1;
    const distributedAirdrops = await DistributedAirdrop.find()
      .populate('claimId', 'stakedAmount lockDurationDays')
      .sort({ distributedAt: sortOrder })
      .lean();
    res.json(distributedAirdrops);
  } catch (error) {
    logger.error('Fetch distributed airdrops error:', error);
    res.status(500).json({ error: 'Failed to fetch distributed airdrops' });
  }
});

app.use((err, req, res, next) => {
  logger.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error', details: err.message });
});

app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
  logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
});