import express from 'express';
import SegmentMessage, { SEGMENT_KEYS, normalizeSegmentKey } from '../models/SegmentMessage.js';
import { auth, admin } from '../middleware/auth.js';

const router = express.Router();

const SEGMENT_METADATA = {
  NIFTY: { label: 'Nifty' },
  BANKNIFTY: { label: 'BankNifty' },
  STOCKS: { label: 'Stocks' },
  SENSEX: { label: 'Sensex' },
  COMMODITY: { label: 'Commodity' },
};

function serializeSegment(doc, fallbackKey) {
  if (!doc) {
    return {
      key: fallbackKey,
      label: SEGMENT_METADATA[fallbackKey]?.label || fallbackKey,
      message: '',
      updatedAt: null,
      updatedBy: null,
    };
  }

  return {
    key: doc.segment,
    label: SEGMENT_METADATA[doc.segment]?.label || doc.segment,
    message: doc.message || '',
    updatedAt: doc.updatedAt || null,
    updatedBy: doc.updatedBy ? String(doc.updatedBy) : null,
  };
}

router.get('/', async (req, res) => {
  try {
    const messages = await SegmentMessage.find({ segment: { $in: SEGMENT_KEYS } }).lean();
    const messageMap = new Map(messages.map((item) => [item.segment, item]));
    const segments = SEGMENT_KEYS.map((key) => serializeSegment(messageMap.get(key), key));
    return res.json({ segments });
  } catch (err) {
    console.error('Failed to fetch segment messages', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.get('/:segment', async (req, res) => {
  try {
    const key = normalizeSegmentKey(req.params.segment);
    if (!key) return res.status(404).json({ error: 'segment not found' });
    const message = await SegmentMessage.findOne({ segment: key }).lean();
    return res.json(serializeSegment(message, key));
  } catch (err) {
    console.error('Failed to fetch segment message', err);
    return res.status(500).json({ error: 'server error' });
  }
});

router.put('/:segment', auth, admin, async (req, res) => {
  try {
    const key = normalizeSegmentKey(req.params.segment);
    if (!key) return res.status(404).json({ error: 'segment not found' });

    const { message } = req.body || {};
    if (typeof message !== 'string' || !message.trim()) {
      return res.status(400).json({ error: 'message required' });
    }

    const trimmed = message.trim();
    if (trimmed.length > 1000) {
      return res.status(400).json({ error: 'message too long (max 1000 chars)' });
    }

    const updated = await SegmentMessage.findOneAndUpdate(
      { segment: key },
      { segment: key, message: trimmed, updatedBy: req.user?.id || null },
      { new: true, upsert: true, setDefaultsOnInsert: true }
    );

    const response = serializeSegment(updated);

    const io = req.app.get('io');
    if (io) {
      io.emit('segment:update', {
        segment: response.key,
        message: response.message,
        updatedAt: response.updatedAt,
      });
    }

    return res.json(response);
  } catch (err) {
    console.error('Failed to upsert segment message', err);
    return res.status(500).json({ error: 'server error' });
  }
});

export default router;
