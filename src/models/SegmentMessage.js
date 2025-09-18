import mongoose from 'mongoose';

export const SEGMENT_KEYS = Object.freeze(['NIFTY', 'BANKNIFTY', 'STOCKS', 'SENSEX', 'COMMODITY']);

export function normalizeSegmentKey(value) {
  if (value === undefined || value === null) return null;
  const key = String(value)
    .trim()
    .toUpperCase()
    .replace(/[\s_-]+/g, '');
  return SEGMENT_KEYS.find((segment) => segment === key) || null;
}

const SegmentMessageSchema = new mongoose.Schema(
  {
    segment: { type: String, enum: SEGMENT_KEYS, required: true, unique: true },
    message: { type: String, trim: true, default: '', maxlength: 1000 },
    updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  },
  { timestamps: true }
);

export default mongoose.model('SegmentMessage', SegmentMessageSchema);
