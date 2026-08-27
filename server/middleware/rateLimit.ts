import rateLimit from 'express-rate-limit';

const windowMs = parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10); // 15 min default
const maxRequests = parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10);

export const apiLimiter = rateLimit({
  windowMs,
  max: maxRequests,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: {
      code: 'RATE_LIMIT_EXCEEDED',
      message: 'Too many requests from this IP, please try again later.',
    },
  },
});

export const analysisLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // 30 analyses per minute
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: {
      code: 'ANALYSIS_RATE_LIMIT_EXCEEDED',
      message: 'Email analysis rate limit exceeded. Please wait before submitting more emails.',
    },
  },
});

export const responseActionLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 20, // 20 mitigation actions per minute
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: {
      code: 'RESPONSE_ACTION_RATE_LIMIT_EXCEEDED',
      message: 'Response action rate limit exceeded. Please throttle remediation calls.',
    },
  },
});
