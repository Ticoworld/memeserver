const mongoose = require('mongoose');

const AirdropClaimSchema = new mongoose.Schema({
  txId: {
    type: String,
    required: true,
    unique: true,
  },
  walletAddress: {
    type: String,
    required: true,
  },
  rewardAmount: {
    type: Number,
    required: true,
  },
  stakedAmount: {
    type: Number,
    required: true,
  },
  lockDurationDays: {
    type: Number,
    required: true,
  },
  distributed: {
    type: Boolean,
    default: false,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
}, {
  timestamps: true,
});

module.exports = mongoose.model('AirdropClaim', AirdropClaimSchema);