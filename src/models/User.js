import mongoose from 'mongoose';

const UserSchema = new mongoose.Schema(
  {
    // Phone-based users (OTP flow). Admins may not have a phone.
    phone: { type: String, unique: true, sparse: true, index: true },
    // Email/password for admins (and optionally users in future)
    email: { type: String, unique: true, sparse: true, index: true },
    passwordHash: { type: String },

    role: { type: String, enum: ['user', 'admin'], default: 'user', index: true },
    walletBalance: { type: Number, default: 1000 },

    // OTP fields (for phone-based login)
    otpHash: { type: String },
    otpExpiresAt: { type: Date },

    // Profile fields
    name: { type: String },

    // Audit fields
    lastLoginAt: { type: Date },
    loginCount: { type: Number, default: 0 },
    lastLoginIp: { type: String },
    lastOtpAt: { type: Date },
    lastOtpIp: { type: String },
  },
  { timestamps: true }
);

export default mongoose.model('User', UserSchema);
