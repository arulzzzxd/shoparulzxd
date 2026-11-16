import express from 'express';
import fileUpload from 'express-fileupload';
import session from 'express-session';
import mongoose from 'mongoose';
import cron from 'node-cron';
import MongoStore from 'connect-mongo';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import bcrypt from 'bcrypt';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import path from 'path';
import fs from 'fs';
import axios from 'axios';
import mime from 'mime-types';
import multer from 'multer';
import moment from 'moment-timezone';
import nodemailer from 'nodemailer';
import https from 'https';
import http from 'http';
import crypto from 'crypto';
import compression from 'compression';
import os from 'os';
import { fileURLToPath } from 'url';
import { createCanvas, loadImage, GlobalFonts } from '@napi-rs/canvas';

// ============================================================
// 1. ENVIRONMENT CONFIG (semua data sensitif dari .env / Vercel Env)
// ============================================================

const PORT = process.env.PORT || 3000;
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');

// Database & keamanan
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const SESSION_SECRET = process.env.SESSION_SECRET;
const OWNER_EMAIL = (process.env.OWNER_EMAIL || '').toLowerCase().trim();

// Email (SMTP)
const SMTP_HOST = process.env.SMTP_HOST || 'smtp.gmail.com';
const SMTP_PORT = Number(process.env.SMTP_PORT) || 465;
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const MAIL_FROM = process.env.MAIL_FROM || SMTP_USER;

// Telegram
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_ADMIN_CHAT_ID = process.env.TELEGRAM_ADMIN_CHAT_ID;

// Paywuz
const PAYWUZ_API_KEY = process.env.PAYWUZ_API_KEY;
const PAYWUZ_BASE_URL = process.env.PAYWUZ_BASE_URL || "https://api.paywuz.id/v2";
const PAYWUZ_HEADERS = {
    "Authorization": `Bearer ${PAYWUZ_API_KEY}`,
    "Content-Type": "application/json"
};

// OAuth GitHub
const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const GITHUB_CALLBACK_URL = process.env.GITHUB_CALLBACK_URL || `${BASE_URL}/auth/github/callback`;

// OAuth Google
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL || `${BASE_URL}/auth/google/callback`;

// Peringatan jika ada variabel wajib yang belum diisi
const REQUIRED_ENV = [
    'MONGODB_URI', 'JWT_SECRET', 'SESSION_SECRET', 'OWNER_EMAIL',
    'SMTP_USER', 'SMTP_PASS', 'TELEGRAM_BOT_TOKEN', 'TELEGRAM_ADMIN_CHAT_ID',
    'PAYWUZ_API_KEY', 'GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET',
    'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET'
];
const MISSING_ENV = REQUIRED_ENV.filter((key) => !process.env[key]);
if (MISSING_ENV.length > 0) {
    console.warn('⚠️ Environment variable belum diisi:', MISSING_ENV.join(', '));
}


// ============================================================
// 2. APP SETUP
// ============================================================

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(compression());
app.set('etag', false);
app.use(express.static(path.join(__dirname)));
app.use(express.json({
    verify: (req, res, buf) => {
        req.rawBody = buf.toString('utf8');
    }
}));
app.use(cookieParser());
app.set('trust proxy', 1);

// ============================================================
// 3. DATABASE CONNECTION
// ============================================================

let cached = global.mongoose;
if (!cached) {
    cached = global.mongoose = { conn: null, promise: null };
}

async function connectDB() {
    if (cached.conn && mongoose.connection.readyState === 1) {
        return cached.conn;
    }

    if (!cached.promise) {
        cached.promise = mongoose.connect(MONGODB_URI, {
            bufferCommands: false,
            serverSelectionTimeoutMS: 10000,
            socketTimeoutMS: 45000,
            maxPoolSize: 10
        }).then((mongooseInstance) => {
            console.log('📦 Berhasil terhubung ke Database Utama!');
            return mongooseInstance;
        }).catch((err) => {
            cached.promise = null;
            console.error('❌ Gagal koneksi ke Database:', err);
            throw err;
        });
    }

    cached.conn = await cached.promise;
    return cached.conn;
}

// Jalankan inisialisasi koneksi
const dbPromise = connectDB();

// ============================================================
// 4. SCHEMAS & MODELS
// ============================================================

// USER SCHEMA V2
const userSchemaV2 = new mongoose.Schema({
    username: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, trim: true, lowercase: true },
    password: { type: String, default: null },
    provider: { type: String, default: 'local' },
    providerId: { type: String, default: null },
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    avatar: { type: String, default: 'https://cdn.larasxd.my.id/files/Z9zjj0RF7G7ena.png' }, 
    banner: { type: String, default: 'https://cdn.larasxd.my.id/files/Tk4GavOaHEEP2ykm.mp4' },
    saldo: { type: Number, default: 0 },
    referralCode: { type: String, unique: true },
    referredBy: { type: String, default: null },
    createdAt: { type: Date, default: Date.now }
});

const UserV2 = mongoose.models.UserV2 || mongoose.model('UserV2', userSchemaV2);

// SCHEMA VERIFIKASI OTP 6 DIGIT
const verificationCodeSchema = new mongoose.Schema({
    email: { type: String, required: true, lowercase: true, trim: true },
    code: { type: String, required: true },
    type: { type: String, enum: ['login', 'register', 'forgot'], required: true },
    expiresAt: { type: Date, required: true },
    createdAt: { type: Date, default: Date.now, expires: 600 } // Auto hapus 10 menit
});

const VerificationCode = mongoose.models.VerificationCode || mongoose.model('VerificationCode', verificationCodeSchema);

// SCHEMA PENCATATAN BATAS MAKSIMAL PENGIRIMAN EMAIL (MAKS 5x SEHARI)
const emailLimitSchema = new mongoose.Schema({
    email: { type: String, required: true, lowercase: true, trim: true },
    date: { type: String, required: true },
    count: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now, expires: 172800 }
});

const EmailLimit = mongoose.models.EmailLimit || mongoose.model('EmailLimit', emailLimitSchema);

// PRODUCT SCHEMA V2
const productSchemaV2 = new mongoose.Schema({
    Id: { type: String, required: true, unique: true, trim: true },
    nama: { type: String, required: true, trim: true },
    harga: { type: Number, required: true },
    harga_diskon: { type: Number, default: null },
    kategori: { type: String, required: true },
    badge: { type: String, default: "" },
    terjual: { type: Number, default: 0 },
    stok: { type: Number, default: 0 },
    gambar: { 
        type: [String], 
        default: ["https://cdn.larasxd.my.id/files/Z9zjj0RF7G7ena.png"] 
    },    
    deskripsi: { type: String, default: "" },
    link: { type: String, required: true },
    purchasedBy: [{ type: String }],
    createdAt: { type: Date, default: Date.now }
});

const ProductV2 = mongoose.models.ProductV2 || mongoose.model('ProductV2', productSchemaV2);

// REVIEW SCHEMA V2
const reviewSchemaV2 = new mongoose.Schema({
    productId: { type: String, required: true, index: true },
    userId: { type: String, default: null, index: true },
    username: { type: String, required: true },
    userAvatar: { type: String, default: 'https://cdn.larasxd.my.id/files/Z9zjj0RF7G7ena.png' },
    rating: { type: Number, required: true, min: 1, max: 5 },
    comment: { type: String, required: true, trim: true },
    media: [{
        type: { type: String, enum: ['image', 'video'] },
        url: String
    }],
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

reviewSchemaV2.index({ productId: 1, userId: 1 }, { unique: true, sparse: true });
const ReviewV2 = mongoose.models.ReviewV2 || mongoose.model('ReviewV2', reviewSchemaV2);

// CACHE SCHEMA V2
const cacheSchemaV2 = new mongoose.Schema({
    key: { type: String, required: true, unique: true },
    data: { type: mongoose.Schema.Types.Mixed, required: true },
    createdAt: { type: Date, default: Date.now, expires: 60 } 
});

const CacheV2 = mongoose.models.CacheV2 || mongoose.model('CacheV2', cacheSchemaV2);

// VOUCHER SCHEMA V2
const voucherSchemaV2 = new mongoose.Schema({
    code: { type: String, required: true, unique: true, uppercase: true },
    discount: { type: Number, required: true },
    type: { type: String, enum: ['percentage', 'fixed'], default: 'percentage' },
    expiredAt: { type: Date, required: true },
    usageLimit: { type: Number, default: 20 },
    usedCount: { type: Number, default: 0 },
    usedBy: [{ type: String }],
    createdAt: { type: Date, default: Date.now }
});

const VoucherV2 = mongoose.models.VoucherV2 || mongoose.model('VoucherV2', voucherSchemaV2);

// TRANSACTION SCHEMA V2
const transactionSchemaV2 = new mongoose.Schema({
    orderId: { type: String, required: true, unique: true },
    amount: { type: Number, required: true },
    paymentNumber: { type: String, default: null }, 
    paymentMethod: { type: String, default: "QRIS" },
    type: { type: String, enum: ['PURCHASE', 'DEPOSIT'], default: 'PURCHASE' },
    userEmail: { type: String, default: null, index: true },
    status: { type: String, default: "pending" }, 
    itemDetails: {
        nama: String,
        harga: Number,
        harga_diskon: Number,
        harga_setelah_voucher: Number,
        kategori: String,
        gambar: String,
        link: String,
        buyer: String,
        qty: Number
    },
    productLink: { type: String, default: null },
    downloadCount: { type: Number, default: 0 },
    downloadedAt: { type: Date, default: null },
    downloadLockedAt: { type: Date, default: null },
    createdAt: { type: Date, default: Date.now },
    expiredAt: { type: Date, required: true },
    updatedAt: { type: Date, default: Date.now }
});

const TransactionV2 = mongoose.models.TransactionV2 || mongoose.model('TransactionV2', transactionSchemaV2);

// ANALYTICS METRICS SCHEMA V2
const systemMetricsSchemaV2 = new mongoose.Schema({
    path: { type: String, required: true },
    method: { type: String, default: 'GET' },
    responseTimeMs: { type: Number, required: true },
    statusCode: { type: Number, required: true },
    timestamp: { type: Date, default: Date.now, index: true }
});

const SystemMetricsV2 = mongoose.models.SystemMetricsV2 || mongoose.model('SystemMetricsV2', systemMetricsSchemaV2);

// CHAT MESSAGE SCHEMA & MODEL
const chatMessageSchema = new mongoose.Schema({
    userEmail: { type: String, required: true, index: true },
    sender: { type: String, enum: ['user', 'owner', 'admin'], required: true },
    senderName: { type: String, default: 'Guest' },
    message: { type: String, required: true, trim: true },
    readByAdmin: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

const ChatMessage = mongoose.models.ChatMessage || mongoose.model('ChatMessage', chatMessageSchema);

// ============================================================
// 5. HELPERS & UTILS
// ============================================================

function generateReferralCode() {
    return 'REF' + Math.floor(100000 + Math.random() * 900000);
}

// HELPER PENGIRIMAN EMAIL OTP MAKSIMAL 5 KALI SEHARI
async function checkAndIncrementEmailLimit(email) {
    const today = moment().tz('Asia/Jakarta').format('YYYY-MM-DD');
    const cleanEmail = email.toLowerCase().trim();

    let limitRecord = await EmailLimit.findOne({ email: cleanEmail, date: today });
    if (!limitRecord) {
        limitRecord = new EmailLimit({ email: cleanEmail, date: today, count: 0 });
    }

    if (limitRecord.count >= 5) {
        return false;
    }

    limitRecord.count += 1;
    await limitRecord.save();
    return true;
}

// HELPER NODEMAILER OTP EMAIL
async function sendEmailOTP(email, code, typeTitle) {
    const transporter = nodemailer.createTransport({
        host: SMTP_HOST,
        port: SMTP_PORT,
        secure: true, 
        auth: {
            user: SMTP_USER,
            pass: SMTP_PASS
        },
        tls: { rejectUnauthorized: false }
    });

    const mailOptions = {
    from: MAIL_FROM,
    to: email,
    subject: `Kode Verifikasi ${typeTitle} - ArulzXD Store`,
    html: `
<!-- Preheader (teks pratinjau di inbox) -->
<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:#F5F2EB;font-size:1px;line-height:1px;">
    Kode verifikasi ${typeTitle} Anda: ${code}. Berlaku 10 menit.
</div>

<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#F5F2EB;">
<tr>
<td align="center" style="padding:40px 16px;">

    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
           style="max-width:500px;background-color:#FFFFFF;border:4px solid #000000;border-radius:16px;box-shadow:8px 8px 0px #000000;font-family:'Plus Jakarta Sans','Segoe UI',Helvetica,Arial,sans-serif;">

        <!-- Header -->
        <tr>
            <td style="background-color:#00E5FF;border-bottom:4px solid #000000;border-radius:12px 12px 0 0;padding:22px 28px;">
                <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                    <tr>
                        <td style="font-size:24px;font-weight:900;color:#000000;letter-spacing:-0.5px;">
                            ArulzXD Store
                        </td>
                        <td align="right">
                            <span style="display:inline-block;background-color:#FF90E8;color:#000000;border:3px solid #000000;border-radius:8px;padding:4px 10px;font-size:11px;font-weight:800;">
                                Verifikasi
                            </span>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>

        <!-- Body -->
        <tr>
            <td style="padding:28px;">
                <p style="margin:0 0 8px 0;color:#000000;font-size:20px;font-weight:800;line-height:1.3;">
                    Halo, ini kode ${typeTitle} Anda
                </p>
                <p style="margin:0 0 24px 0;color:#333333;font-size:14px;line-height:1.6;">
                    Masukkan kode 6 digit di bawah untuk melanjutkan. Kode hanya berlaku selama
                    <span style="background-color:#FFDE59;border:2px solid #000000;border-radius:6px;padding:1px 6px;font-weight:800;color:#000000;">10 menit</span>.
                </p>

                <!-- Kode -->
                <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                    <tr>
                        <td align="center"
                            style="background-color:#FFDE59;border:4px solid #000000;border-radius:12px;box-shadow:5px 5px 0px #000000;padding:22px 12px;">
                            <span style="font-family:'Courier New',Courier,monospace;font-size:40px;font-weight:900;letter-spacing:10px;color:#000000;">${code}</span>
                        </td>
                    </tr>
                </table>

                <div style="height:28px;line-height:28px;font-size:0;">&nbsp;</div>

                <!-- Peringatan -->
                <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                    <tr>
                        <td style="background-color:#FFD6D6;border:3px solid #000000;border-radius:10px;padding:14px 16px;">
                            <p style="margin:0 0 4px 0;color:#000000;font-size:13px;font-weight:800;">
                                Jangan bagikan kode ini
                            </p>
                            <p style="margin:0;color:#333333;font-size:12px;line-height:1.6;">
                                Jangan berikan kode ini kepada siapa pun, termasuk yang mengaku admin, demi keamanan akun Anda.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>

        <!-- Footer -->
        <tr>
            <td style="border-top:4px solid #000000;background-color:#F5F2EB;border-radius:0 0 12px 12px;padding:16px 28px;">
                <p style="margin:0;color:#555555;font-size:11px;line-height:1.6;">
                    Pengiriman kode dibatasi maksimal 5 kali sehari. Jika Anda tidak merasa meminta kode ini, abaikan email ini.
                </p>
            </td>
        </tr>
    </table>

</td>
</tr>
</table>
`
};

    await transporter.sendMail(mailOptions);
}

function getUserIdentifier(req) {
    if (req.user) {
        return (req.user.email || req.user.username || req.user._id || "").toString().toLowerCase().trim();
    }
    const bodyIdentifier = req.body?.username || req.body?.email || req.body?.userIdentifier;
    if (bodyIdentifier) {
        return bodyIdentifier.toString().toLowerCase().trim();
    }
    return req.ip; 
}

async function sendTelegramNotification(username, userEmail, messageText) {
    if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_ADMIN_CHAT_ID) return;

    const escapeHtml = (str) => String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');

    const text = `
📩 <b>PESAN LIVE CHAT BARU!</b>
━━━━━━━━━━━━━━━━━━━━
👤 <b>Username:</b> ${escapeHtml(username)}
📧 <b>Email:</b> <code>${escapeHtml(userEmail)}</code>
💬 <b>Percakapan:</b>
${escapeHtml(messageText)}
━━━━━━━━━━━━━━━━━━━━
🔗 <a href="${BASE_URL}/admin/livechat">Buka Panel Admin Live Chat</a>
    `.trim();

    try {
        await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
            chat_id: TELEGRAM_ADMIN_CHAT_ID,
            text: text,
            parse_mode: 'HTML',
            disable_web_page_preview: true
        }, { timeout: 8000 });
    } catch (error) {
        console.error('❌ Gagal mengirim notifikasi ke Telegram:', error.response?.data || error.message);
    }
}

async function axiosPaywuzWithRetry(config, maxRetries = 3, delayMs = 1500) {
    for (let i = 0; i < maxRetries; i++) {
        try {
            return await axios({
                timeout: 15000,
                ...config
            });
        } catch (error) {
            const status = error.response?.status;
            const isLastAttempt = i === maxRetries - 1;

            const isNetworkOrTimeout = !error.response || error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT';
            const isRetryableStatus = status === 429 || (status >= 500 && status < 600);
            const shouldRetry = isNetworkOrTimeout || isRetryableStatus;

            if (shouldRetry && !isLastAttempt) {
                const reason = status ? `HTTP ${status}` : (error.code || 'Network/Timeout Error');
                console.warn(`⚠️ Gateway gagal (${reason}). Retry ke-${i + 1} dalam ${delayMs}ms...`);
                await new Promise(resolve => setTimeout(resolve, delayMs));
                delayMs *= 2;
            } else {
                throw error;
            }
        }
    }
}

function isValidIndonesianPhone(phone) {
    if (!phone) return false;
    const cleaned = phone.toString().replace(/[\s\-()]/g, '');
    return /^(\+62|62|08)[0-9]{8,12}$/.test(cleaned);
}

async function recordProductBuyer(productQuery, userIdentifier) {
    if (!productQuery || !userIdentifier) return;
    try {
        const cleanIdentifier = userIdentifier.toString().toLowerCase().trim();
        await ProductV2.findOneAndUpdate(
            { 
                $or: [
                    { Id: productQuery },
                    { _id: mongoose.Types.ObjectId.isValid(productQuery) ? productQuery : null },
                    { nama: { $regex: new RegExp(`^${productQuery.toString().trim()}$`, 'i') } }
                ]
            },
            { $addToSet: { purchasedBy: cleanIdentifier } }
        );
    } catch (err) {
        console.error("❌ Gagal mencatat pembeli produk:", err.message);
    }
}

async function updateProductStockAndSold(productName, qtyChange = 1, isRollback = false) {
    try {
        if (!productName) return null;

        const product = await ProductV2.findOne({ 
            nama: { $regex: new RegExp(`^${productName.trim()}$`, 'i') } 
        });

        if (product) {
            if (isRollback) {
                product.stok = (product.stok || 0) + qtyChange;
                product.terjual = Math.max(0, (product.terjual || 0) - qtyChange);
            } else {
                product.stok = Math.max(0, (product.stok || 0) - qtyChange);
                product.terjual = (product.terjual || 0) + qtyChange;
            }

            await product.save();
            return product;
        }
    } catch (err) {
        console.error("❌ Gagal meng-update stok produk:", err.message);
    }
    return null;
}

async function setCache(key, data) {
    try {
        await CacheV2.findOneAndUpdate(
            { key },
            { data, createdAt: new Date() },
            { upsert: true, new: true }
        );
    } catch (e) {
        console.error("Gagal simpan cache Database:", e.message);
    }
}

async function getCache(key) {
    try {
        const cached = await CacheV2.findOne({ key });
        return cached ? cached.data : null;
    } catch (e) {
        return null;
    }
}

async function deleteCache(key) {
    try {
        await CacheV2.deleteOne({ key });
    } catch (e) {}
}

function verifyPaywuzSignature(rawBody, receivedSignature, apikey) {
    if (!receivedSignature || !rawBody) return false;

    const computedSignature = "sha256=" + crypto
        .createHmac("sha256", apikey)
        .update(typeof rawBody === 'string' ? rawBody : JSON.stringify(rawBody))
        .digest("hex");

    try {
        return crypto.timingSafeEqual(
            Buffer.from(receivedSignature),
            Buffer.from(computedSignature)
        );
    } catch (err) {
        return false;
    }
}

function classifyProductLink(rawLink) {
    const link = (rawLink || '').trim();
    const lower = link.toLowerCase();

    const normalizeHref = (url) => {
        if (/^(https?:\/\/|whatsapp:\/\/|tg:\/\/)/i.test(url)) return url;
        return `https://${url}`;
    };

    if (
        lower.includes('wa.me/') ||
        lower.includes('whatsapp.com') ||
        lower.startsWith('whatsapp://')
    ) {
        return {
            linkType: 'whatsapp',
            platformName: 'WhatsApp',
            chatUrl: normalizeHref(link),
            specialDescription: 'Lanjut chat admin mengenai produk'
        };
    }

    if (
        lower.includes('t.me/') ||
        lower.includes('telegram.me/') ||
        lower.includes('telegram.dog/') ||
        lower.startsWith('tg://')
    ) {
        return {
            linkType: 'telegram',
            platformName: 'Telegram',
            chatUrl: normalizeHref(link),
            specialDescription: 'Lanjut chat admin mengenai produk'
        };
    }

    return {
        linkType: 'download',
        platformName: 'Download',
        chatUrl: null,
        specialDescription: null
    };
}

// HELPER KONVERSI LINK CLOUD KE DIRECT DOWNLOAD STREAM
function normalizeDirectDownloadUrl(rawUrl) {
    let url = (rawUrl || '').trim();

    // Google Drive (file/d/ID, open?id=ID, uc?id=ID) -> direct download (bypass halaman konfirmasi virus scan)
    const gdriveMatch =
        url.match(/drive\.google\.com\/file\/d\/([^/?#]+)/i) ||
        url.match(/drive\.google\.com\/(?:open|uc)\?(?:[^#]*&)?id=([^&#]+)/i);
    if (gdriveMatch && gdriveMatch[1]) {
        return `https://drive.usercontent.google.com/download?id=${gdriveMatch[1]}&export=download&confirm=t`;
    }

    // Dropbox -> paksa dl=1 (baik dl=0 maupun tanpa parameter dl)
    if (/(^|\.)dropbox\.com/i.test(url.replace(/^https?:\/\//i, '').split('/')[0] || '')) {
        try {
            const u = new URL(url);
            u.searchParams.delete('raw');
            u.searchParams.set('dl', '1');
            return u.toString();
        } catch (e) {
            return url.replace('dl=0', 'dl=1');
        }
    }

    // Pixeldrain (pixeldrain.com/u/ID) -> API file langsung
    const pixel = url.match(/^https?:\/\/(?:www\.)?pixeldrain\.(?:com|net)\/u\/([A-Za-z0-9]+)/i);
    if (pixel) {
        return `https://pixeldrain.com/api/file/${pixel[1]}?download`;
    }

    // GitHub blob (halaman HTML) -> raw file langsung
    const ghBlob = url.match(/^https?:\/\/github\.com\/([^/]+)\/([^/]+)\/blob\/([^/]+)\/(.+?)(?:[?#].*)?$/i);
    if (ghBlob) {
        return `https://raw.githubusercontent.com/${ghBlob[1]}/${ghBlob[2]}/${ghBlob[3]}/${ghBlob[4]}`;
    }

    return url;
}

// Nama file aman untuk header Content-Disposition
function sanitizeDownloadFilename(name, fallback = 'produk-arulzxd') {
    let clean = String(name || '')
        .replace(/[\u0000-\u001f\u007f]/g, '')
        .replace(/[\\/:*?"<>|]+/g, '-')
        .replace(/^\.+/, '')
        .trim();
    if (!clean) clean = fallback;
    return clean.slice(0, 180);
}

function encodeRFC5987(str) {
    return encodeURIComponent(str).replace(/['()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

// Semua file produk SELALU dikirim sebagai attachment (langsung ter-download, tidak pernah dibuka sebagai halaman)
function setForcedDownloadHeaders(res, filename, contentLength) {
    const asciiName = filename.replace(/[^\x20-\x7E]/g, '_').replace(/["\\]/g, '');
    res.setHeader('Content-Disposition', `attachment; filename="${asciiName}"; filename*=UTF-8''${encodeRFC5987(filename)}`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Download-Filename', encodeURIComponent(filename));
    res.setHeader('Access-Control-Expose-Headers', 'Content-Disposition, X-Download-Filename');
    if (contentLength && Number(contentLength) > 0) {
        res.setHeader('Content-Length', String(contentLength));
    }
}

// File lokal (mis. "base-arulz.html" yang ada di folder project) yang tidak boleh ikut ter-download
const BLOCKED_LOCAL_FILES = new Set([
    'index.js', 'package.json', 'package-lock.json', 'vercel.json', '.env', '.env.local', '.gitignore'
]);

function resolveLocalProductFile(rawLink) {
    let link = (rawLink || '').trim();
    if (!link || /^[a-z][a-z0-9+.-]*:\/\//i.test(link)) return null;

    link = link.split('#')[0].split('?')[0];
    try { link = decodeURIComponent(link); } catch (e) {}
    link = link.replace(/\\/g, '/').replace(/^\/+/, '');
    if (!link) return null;

    const roots = [__dirname, path.join(__dirname, 'public')];
    for (const root of roots) {
        const candidate = path.resolve(root, link);
        if (!candidate.startsWith(root + path.sep)) continue; // cegah path traversal

        const relParts = path.relative(__dirname, candidate).split(path.sep);
        if (relParts.some((p) => p.startsWith('.') || p === 'node_modules')) continue;
        if (BLOCKED_LOCAL_FILES.has(path.basename(candidate).toLowerCase())) continue;

        try {
            if (fs.statSync(candidate).isFile()) return candidate;
        } catch (e) {}
    }
    return null;
}

// Tentukan sumber file produk: file lokal di server atau URL remote
function resolveProductSource(rawLink) {
    const link = (rawLink || '').trim();
    if (!link) return null;

    const localPath = resolveLocalProductFile(link);
    if (localPath) return { type: 'local', filePath: localPath };

    if (/^https?:\/\//i.test(link)) {
        return { type: 'remote', url: normalizeDirectDownloadUrl(link) };
    }

    // domain tanpa protokol, mis. "cdn.example.com/files/produk.zip"
    if (/^[a-z0-9-]+(\.[a-z0-9-]+)+\/.+/i.test(link)) {
        return { type: 'remote', url: normalizeDirectDownloadUrl(`https://${link}`) };
    }

    return null;
}

const BROWSER_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';

class ProductLinkError extends Error {}

function decodeHtmlEntities(str) {
    return String(str || '').replace(/&amp;/g, '&').replace(/&#x2F;/gi, '/').replace(/&#38;/g, '&');
}

// Ambil isi halaman HTML (maks 2MB) dari stream untuk dicari link file langsungnya
async function readStreamAsText(stream, maxBytes = 2 * 1024 * 1024) {
    return await new Promise((resolve, reject) => {
        const chunks = [];
        let size = 0;
        stream.on('data', (c) => {
            size += c.length;
            if (size <= maxBytes) chunks.push(c);
            else stream.destroy();
        });
        stream.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
        stream.on('close', () => resolve(Buffer.concat(chunks).toString('utf8')));
        stream.on('error', reject);
    });
}

// MediaFire: halaman file -> link direct (downloadXXXX.mediafire.com)
async function resolveMediafireDirectUrl(pageUrl) {
    if (/mediafire\.com\/folder\//i.test(pageUrl)) {
        throw new ProductLinkError('Link folder MediaFire tidak didukung. Gunakan link file langsung.');
    }

    const page = await axios.get(pageUrl, {
        responseType: 'text',
        timeout: 20000,
        maxRedirects: 8,
        headers: {
            'User-Agent': BROWSER_UA,
            'Accept': 'text/html,application/xhtml+xml',
            'Accept-Language': 'en-US,en;q=0.9'
        }
    });
    const html = String(page.data || '');

    // Versi baru: URL di-scramble dalam base64
    const scrambled = html.match(/data-scrambled-url="([^"]+)"/i);
    if (scrambled && scrambled[1]) {
        try {
            const decoded = Buffer.from(scrambled[1], 'base64').toString('utf8').trim();
            if (/^https?:\/\//i.test(decoded)) return decoded;
        } catch (e) {}
    }

    const direct =
        html.match(/id="downloadButton"[^>]*href="(https?:\/\/[^"]+)"/i) ||
        html.match(/href="(https?:\/\/[^"]+)"[^>]*id="downloadButton"/i) ||
        html.match(/href="(https?:\/\/download[0-9]*\.mediafire\.com\/[^"]+)"/i) ||
        html.match(/(https?:\/\/download[0-9]*\.mediafire\.com\/[^\s"'<>]+)/i);

    if (direct && direct[1]) return decodeHtmlEntities(direct[1]);

    throw new ProductLinkError('File MediaFire tidak ditemukan atau sudah dihapus.');
}

// Ubah link "halaman download" menjadi link file langsung bila memungkinkan
async function resolveRemoteDownloadUrl(url) {
    let host = '';
    try { host = new URL(url).hostname.toLowerCase(); } catch (e) { return url; }

    if (/(^|\.)mediafire\.com$/.test(host) && !/^download[0-9]*\.mediafire\.com$/.test(host)) {
        return await resolveMediafireDirectUrl(url);
    }
    return url;
}

// Cari link file langsung di dalam halaman HTML perantara (meta refresh / tombol download)
function scrapeDirectLinkFromHtml(html, baseUrl) {
    const toAbs = (u) => {
        try { return new URL(decodeHtmlEntities(u), baseUrl).toString(); } catch (e) { return null; }
    };

    const meta = html.match(/<meta[^>]+http-equiv=["']?refresh["']?[^>]+content=["'][^"']*url=([^"']+)["']/i);
    if (meta && meta[1]) {
        const abs = toAbs(meta[1]);
        if (abs) return abs;
    }

    const fileExt = '(?:zip|rar|7z|tar|gz|tgz|apk|exe|msi|pdf|mp3|mp4|mkv|jpg|jpeg|png|txt|json|js|py|html|sql|iso)';
    const hrefRe = new RegExp(`href=["']([^"']+\\.${fileExt}(?:\\?[^"']*)?)["']`, 'i');
    const link = html.match(hrefRe);
    if (link && link[1]) {
        const abs = toAbs(link[1]);
        if (abs) return abs;
    }
    return null;
}

function sendSweetAlert(res, icon, title, text, redirectUrl) {
    return res.send(`
        <!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Notification</title>
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --ink: #111111;
            --paper: #fffdf5;
            --bg: #f3efe3;
            --accent: #22d3ee;
            --accent-hover: #67e8f9;
            --success: #4ade80;
            --error: #ff6b6b;
            --warning: #facc15;
            --info: #22d3ee;
            --question: #c4b5fd;
        }

        body {
            background-color: var(--bg);
            background-image: radial-gradient(var(--ink) 1px, transparent 1px);
            background-size: 22px 22px;
            background-position: 0 0;
            font-family: 'Plus Jakarta Sans', sans-serif;
        }

        /* Popup */
        .swal2-popup {
            background: var(--paper) !important;
            border: 3px solid var(--ink) !important;
            border-radius: 12px !important;
            box-shadow: 8px 8px 0 var(--ink) !important;
            padding: 2em 1.5em 1.75em !important;
            font-family: 'Plus Jakarta Sans', sans-serif !important;
        }

        .swal2-title {
            color: var(--ink) !important;
            font-weight: 800 !important;
            letter-spacing: -0.02em;
        }

        .swal2-html-container {
            color: #374151 !important;
            font-weight: 500 !important;
        }

        /* Button */
        .swal2-confirm {
            background: var(--accent) !important;
            color: var(--ink) !important;
            font-weight: 800 !important;
            font-family: inherit !important;
            border: 3px solid var(--ink) !important;
            border-radius: 10px !important;
            padding: 10px 28px !important;
            box-shadow: 4px 4px 0 var(--ink) !important;
            transition: transform 0.1s ease, box-shadow 0.1s ease, background 0.1s ease;
        }
        .swal2-confirm:hover {
            background: var(--accent-hover) !important;
            transform: translate(-2px, -2px);
            box-shadow: 6px 6px 0 var(--ink) !important;
        }
        .swal2-confirm:active {
            transform: translate(4px, 4px);
            box-shadow: 0 0 0 var(--ink) !important;
        }
        .swal2-confirm:focus-visible {
            outline: 3px solid var(--ink) !important;
            outline-offset: 3px;
            box-shadow: 4px 4px 0 var(--ink) !important;
        }

        /* Icons: flat colored fill with thick black outline */
        .swal2-icon {
            border-width: 3px !important;
            border-color: var(--ink) !important;
            color: var(--ink) !important;
            box-shadow: 4px 4px 0 var(--ink);
        }
        .swal2-icon.swal2-success { background: var(--success); }
        .swal2-icon.swal2-error   { background: var(--error); }
        .swal2-icon.swal2-warning { background: var(--warning); }
        .swal2-icon.swal2-info    { background: var(--info); }
        .swal2-icon.swal2-question{ background: var(--question); }

        .swal2-icon.swal2-success [class^='swal2-success-line'] {
            background-color: var(--ink) !important;
        }
        .swal2-icon.swal2-success .swal2-success-ring {
            border: 0 !important;
        }
        .swal2-icon.swal2-success [class^='swal2-success-circular-line'],
        .swal2-icon.swal2-success .swal2-success-fix {
            background: transparent !important;
        }
        .swal2-icon.swal2-error [class^='swal2-x-mark-line'] {
            background-color: var(--ink) !important;
        }
        .swal2-icon .swal2-icon-content {
            color: var(--ink) !important;
            font-weight: 800;
        }

        @media (prefers-reduced-motion: reduce) {
            .swal2-confirm { transition: none; }
        }
    </style>
</head>
<body>
    <script>
        Swal.fire({
            icon: '${icon}',
            title: '${title}',
            text: '${text}',
            confirmButtonText: 'OKE',
            scrollbarPadding: false
        }).then(() => {
            window.location = '${redirectUrl}';
        });
    </script>
</body>
</html>
    `);
}

function drawNeoBox(ctx, x, y, w, h, radius, fillColor, shadowOffset = 6, borderWidth = 4) {
    ctx.save();
    // Hard Shadow Hitam
    if (shadowOffset > 0) {
        ctx.fillStyle = '#000000';
        ctx.beginPath();
        ctx.roundRect(x + shadowOffset, y + shadowOffset, w, h, radius);
        ctx.fill();
    }
    // Box Utama
    ctx.fillStyle = fillColor;
    ctx.beginPath();
    ctx.roundRect(x, y, w, h, radius);
    ctx.fill();

    // Border Hitam Tebal
    if (borderWidth > 0) {
        ctx.lineWidth = borderWidth;
        ctx.strokeStyle = '#000000';
        ctx.stroke();
    }
    ctx.restore();
}

let ogFontLoaded = false;
async function ensureOgFonts() {
    if (ogFontLoaded) return true;
    try {
        const [regRes, boldRes, blackRes] = await Promise.all([
            axios.get('https://github.com/google/fonts/raw/main/ofl/plusjakartasans/PlusJakartaSans%5Bwght%5D.ttf', {
                responseType: 'arraybuffer',
                timeout: 6000
            }),
            axios.get('https://github.com/google/fonts/raw/main/ofl/spacegrotesk/SpaceGrotesk%5Bwght%5D.ttf', {
                responseType: 'arraybuffer',
                timeout: 6000
            }),
            axios.get('https://github.com/google/fonts/raw/main/ofl/jetbrainsmono/JetBrainsMono%5Bwght%5D.ttf', {
                responseType: 'arraybuffer',
                timeout: 6000
            })
        ]);

        GlobalFonts.register(Buffer.from(regRes.data), 'JakartaSans');
        GlobalFonts.register(Buffer.from(boldRes.data), 'SpaceGrotesk');
        GlobalFonts.register(Buffer.from(blackRes.data), 'JetBrainsMono');
        ogFontLoaded = true;
        return true;
    } catch (err) {
        console.warn('⚠️ Gagal mengunduh font eksternal OG:', err.message);
        return false;
    }
}

// Helper memotong teks panjang agar rapi dan tidak keluar batas
function wrapText(ctx, text, x, y, maxWidth, lineHeight, maxLines = 3) {
    const cleanText = String(text || '').replace(/\s+/g, ' ').trim();
    const words = cleanText.split(' ');
    let line = '';
    let lineCount = 0;

    for (let n = 0; n < words.length; n++) {
        const testLine = line + words[n] + ' ';
        const metrics = ctx.measureText(testLine);
        if (metrics.width > maxWidth && n > 0) {
            lineCount++;
            if (lineCount >= maxLines) {
                ctx.fillText(line.trim() + '...', x, y);
                return y;
            }
            ctx.fillText(line.trim(), x, y);
            line = words[n] + ' ';
            y += lineHeight;
        } else {
            line = testLine;
        }
    }
    ctx.fillText(line.trim(), x, y);
    return y;
}

// ============================================================
// 6. UPLOAD CONFIG (MULTER)
// ============================================================

const uploadavatar = multer({ 
    limits: { fileSize: 4 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('File harus berupa gambar!'));
        }
    }
});

const uploadBannerMulter = multer({ 
    limits: { fileSize: 4 * 1024 * 1024 }, // Batas maksimal upload 4MB
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/') || file.mimetype.startsWith('video/')) {
            cb(null, true);
        } else {
            cb(new Error('File banner harus berupa gambar (JPG/PNG/GIF) atau video MP4!'));
        }
    }
});

const uploadReviewMedia = multer({
    limits: { fileSize: 5 * 1024 * 1024 }, // Maksimal 5MB
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/') || file.mimetype.startsWith('video/')) {
            cb(null, true);
        } else {
            cb(new Error('File harus berupa gambar atau video!'));
        }
    }
});

// ============================================================
// 7. MIDDLEWARES
// ============================================================

app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', async () => {
        try {
            const duration = Date.now() - start;
            if (req.originalUrl.startsWith('/api') || req.originalUrl.startsWith('/transactions') || req.originalUrl === '/') {
                await SystemMetricsV2.create({
                    path: req.path,
                    method: req.method,
                    responseTimeMs: duration,
                    statusCode: res.statusCode,
                    timestamp: new Date()
                });
            }
        } catch (e) {}
    });
    next();
});

app.use(async (req, res, next) => {
    try {
        await connectDB();
        next();
    } catch (err) {
        console.error('Database connection middleware error:', err.message);
        res.status(503).json({ status: false, message: 'Database sedang bersiap, silakan muat ulang halaman.' });
    }
});

app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        clientPromise: dbPromise.then(m => m.connection.getClient()),
        dbName: 'sessions',
        ttl: 24 * 60 * 60
    }),
    cookie: { maxAge: 24 * 60 * 60 * 1000 } 
}));

const checkAuthSession = (req, res, next) => {
    const token = req.cookies.auth_session;
    if (!token) {
        req.user = null;
        return next();
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; 
        next();
    } catch (err) {
        res.clearCookie('auth_session');
        req.user = null;
        next();
    }
};

app.use(checkAuthSession);

const checkAdminRole = (req, res, next) => {
    if (!req.user) return res.status(401).json({ status: false, message: 'Silakan login terlebih dahulu!' });
    const ownerEmail = OWNER_EMAIL;
    if (req.user.email?.toLowerCase().trim() === ownerEmail) {
        req.isAdmin = true;
        return next();
    }
    return res.status(403).json({ status: false, message: 'Akses ditolak! Khusus Admin/Owner.' });
};

// ============================================================
// 8. ROUTES: BANTUAN, USER, REVIEW, VOUCHER, DEPOSIT, STORE, TRANSAKSI
// ============================================================

// CHAT BANTUAN API
app.get('/api/bantuan/messages', checkAuthSession, async (req, res) => {
    try {
        const userIdentifier = getUserIdentifier(req);
        const messages = await ChatMessage.find({ userEmail: userIdentifier }).sort({ createdAt: 1 }).lean();
        return res.json({ status: true, messages });
    } catch (e) {
        return res.status(500).json({ status: false, message: 'Gagal memuat pesan live chat.' });
    }
});



app.post('/api/bantuan/send-user', checkAuthSession, async (req, res) => {
    try {
        const { message } = req.body;
        if (!message || !message.trim()) {
            return res.status(400).json({ status: false, message: 'Pesan tidak boleh kosong!' });
        }

        const userIdentifier = getUserIdentifier(req);
        let displayUsername = 'Pengguna Guest';
        let displayEmail = userIdentifier;
        
        if (req.user) {
            const activeUser = await UserV2.findById(req.user.id || req.user._id).select('username email').lean();
            displayUsername = activeUser?.username || req.user.username || req.user.name || 'User';
            displayEmail = (activeUser?.email || req.user.email || userIdentifier).toLowerCase().trim();
        }

        const cleanMessage = message.trim();

        const newMsg = new ChatMessage({
            userEmail: displayEmail,
            sender: 'user',
            senderName: displayUsername,
            message: cleanMessage,
            readByAdmin: false
        });

        await newMsg.save();

        await sendTelegramNotification(displayUsername, displayEmail, cleanMessage);

        return res.json({ status: true, message: 'Pesan berhasil dikirim!', data: newMsg });
    } catch (e) {
        return res.status(500).json({ status: false, message: 'Gagal mengirim pesan.' });
    }
});

app.get('/api/bantuan/admin/users', checkAuthSession, checkAdminRole, async (req, res) => {
    try {
        const rooms = await ChatMessage.aggregate([
            { $sort: { createdAt: -1 } },
            { 
                $group: {
                    _id: "$userEmail",
                    lastMessage: { $first: "$message" },
                    senderName: { $first: "$senderName" },
                    lastSender: { $first: "$sender" },
                    updatedAt: { $first: "$createdAt" },
                    unreadCount: {
                        $sum: {
                            $cond: [
                                { $and: [{ $eq: ["$sender", "user"] }, { $eq: ["$readByAdmin", false] }] },
                                1,
                                0
                            ]
                        }
                    }
                }
            },
            { $sort: { updatedAt: -1 } }
        ]);

        const emails = rooms.map(r => r._id).filter(e => e && e.includes('@'));
        const dbUsers = await UserV2.find({ email: { $in: emails } }).select('email username avatar').lean();
        const userMap = {};
        dbUsers.forEach(u => {
            userMap[u.email.toLowerCase().trim()] = u;
        });

        const formattedUsers = rooms.map(r => {
            const cleanEmail = (r._id || '').toLowerCase().trim();
            const matchedUser = userMap[cleanEmail];
            const isRegisteredEmail = cleanEmail.includes('@');

            let resolvedUsername = matchedUser?.username;
            if (!resolvedUsername) {
                resolvedUsername = (r.senderName && r.senderName !== 'Cs Owner')
                    ? r.senderName
                    : (isRegisteredEmail ? cleanEmail.split('@')[0] : 'Pengguna Guest');
            }

            return {
                userId: r._id,
                username: resolvedUsername,
                email: isRegisteredEmail ? cleanEmail : `Guest (${cleanEmail})`,
                avatar: matchedUser?.avatar || null,
                lastMessage: r.lastMessage,
                unreadCount: r.unreadCount,
                updatedAt: r.updatedAt
            };
        });

        return res.json({ status: true, users: formattedUsers });
    } catch (e) {
        return res.status(500).json({ status: false, message: 'Gagal memuat daftar pengguna chat.' });
    }
});

app.get('/api/bantuan/admin/messages/:userId', checkAuthSession, checkAdminRole, async (req, res) => {
    try {
        const { userId } = req.params;
        if (!userId) return res.status(400).json({ status: false, message: 'ID/Email pengguna wajib ada!' });

        const cleanId = userId.toLowerCase().trim();
        const messages = await ChatMessage.find({ userEmail: cleanId }).sort({ createdAt: 1 }).lean();

        await ChatMessage.updateMany(
            { userEmail: cleanId, sender: 'user', readByAdmin: false },
            { $set: { readByAdmin: true } }
        );

        return res.json({ status: true, messages });
    } catch (e) {
        return res.status(500).json({ status: false, message: 'Gagal memuat riwayat pesan pengguna.' });
    }
});

app.post('/api/bantuan/admin/reply', checkAuthSession, checkAdminRole, async (req, res) => {
    try {
        const { userId, message } = req.body;
        if (!userId || !message || !message.trim()) {
            return res.status(400).json({ status: false, message: 'ID Pengguna dan pesan balasan wajib diisi!' });
        }

        const replyMsg = new ChatMessage({
            userEmail: userId.toLowerCase().trim(),
            sender: 'owner',
            senderName: 'Cs Owner',
            message: message.trim(),
            readByAdmin: true
        });

        await replyMsg.save();
        return res.json({ status: true, message: 'Balasan admin berhasil terkirim!', data: replyMsg });
    } catch (e) {
        return res.status(500).json({ status: false, message: 'Gagal mengirim balasan admin.' });
    }
});

app.get('/admin/livechat', checkAuthSession, (req, res) => {
    const ownerEmail = OWNER_EMAIL;
    if (!req.user || req.user.email?.toLowerCase().trim() !== ownerEmail) {
        return res.redirect('/dashboard');
    }
    res.sendFile(path.join(__dirname, 'public', 'admin-chat.html'));
});

app.post('/api/user/update-username', checkAuthSession, async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({ status: false, message: 'Silakan login terlebih dahulu!' });
        }

        const newUsername = req.body.username;
        if (!newUsername || !newUsername.trim()) {
            return res.status(400).json({ status: false, message: 'Username baru tidak boleh kosong!' });
        }

        const cleanUsername = newUsername.trim();
        const userId = req.user.id || req.user._id;

        const updatedUser = await UserV2.findByIdAndUpdate(
            userId,
            { $set: { username: cleanUsername } },
            { new: true }
        );

        if (!updatedUser) {
            return res.status(404).json({ status: false, message: 'User tidak ditemukan.' });
        }

        const userPayload = {
            id: updatedUser._id,
            username: updatedUser.username,
            email: updatedUser.email,
            name: updatedUser.username,
            avatar: updatedUser.avatar,
            createdAt: updatedUser.createdAt
        };

        const token = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '7d' });
        res.cookie('auth_session', token, {
            maxAge: 7 * 24 * 60 * 60 * 1000,
            httpOnly: true,
            secure: true,
            sameSite: 'lax'
        });

        return res.json({
            status: true,
            message: 'Username berhasil diperbarui!',
            username: updatedUser.username
        });
    } catch(err) {
        return res.status(500).json({ status: false, message: 'Gagal memperbarui username.' });
    }
});


app.post('/api/user/update-avatar', checkAuthSession, (req, res) => {
    uploadavatar.single('avatar')(req, res, async (err) => {
        if (err) {
            return res.status(400).json({ status: false, message: err.message || 'Gagal mengunggah gambar.' });
        }

        try {
            if (!req.user) {
                return res.status(401).json({ status: false, message: 'Anda belum login!' });
            }

            if (!req.file) {
                return res.status(400).json({ status: false, message: 'Silakan pilih gambar terlebih dahulu!' });
            }

            const mimeType = req.file.mimetype || mime.lookup(req.file.originalname) || 'image/png';
            const base64 = req.file.buffer.toString("base64");
            const avatarDataUrl = `data:${mimeType};base64,${base64}`;

            const userIdToUpdate = req.user.id || req.user._id;
            const updatedUser = await UserV2.findByIdAndUpdate(
                userIdToUpdate,
                { $set: { avatar: avatarDataUrl } },
                { new: true, runValidators: true }
            );

            if (!updatedUser) {
                return res.status(404).json({ status: false, message: 'User tidak ditemukan.' });
            }

            const userPayload = {
                id: updatedUser._id,
                username: updatedUser.username,
                email: updatedUser.email,
                name: updatedUser.username,
                avatar: updatedUser.avatar,
                createdAt: updatedUser.createdAt
            };

            const token = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '7d' });
            res.cookie('auth_session', token, {
                maxAge: 7 * 24 * 60 * 60 * 1000,
                httpOnly: true,
                secure: true,
                sameSite: 'lax'
            });

            return res.json({
                status: true,
                message: 'Avatar berhasil diperbarui!',
                avatar: updatedUser.avatar
            });

        } catch (error) {
            console.error("Gagal update avatar:", error);
            return res.status(500).json({ status: false, message: 'Terjadi kesalahan pada server saat memperbarui avatar.' });
        }
    });
});

app.post('/api/user/update-banner', checkAuthSession, (req, res) => {
    uploadBannerMulter.single('bannerFile')(req, res, async (err) => {
        if (err) {
            if (err.code === 'LIMIT_FILE_SIZE') {
                return res.status(400).json({ status: false, message: 'Ukuran berkas melebihi batas maksimal 4MB!' });
            }
            return res.status(400).json({ status: false, message: err.message || 'Gagal mengunggah banner.' });
        }

        try {
            if (!req.user) {
                return res.status(401).json({ status: false, message: 'Anda belum login!' });
            }

            const userIdToUpdate = req.user.id || req.user._id;
            const bannerUrlInput = req.body.bannerUrl;

            let finalBanner = '';

            // JIKA UPLOAD DENGAN FILE
            if (req.file) {
                const fileSize = req.file.size;
                const maxSize = 4 * 1024 * 1024; // Maksimal 4 MB

                if (fileSize > maxSize) {
                    return res.status(400).json({ 
                        status: false, 
                        message: `Ukuran file berkas maksimal adalah 4MB! (Ukuran file Anda: ${(fileSize / (1024*1024)).toFixed(2)}MB)` 
                    });
                }

                // Konversi berkas ke Base64
                const mimeType = req.file.mimetype || mime.lookup(req.file.originalname) || 'image/png';
                const base64 = req.file.buffer.toString("base64");
                finalBanner = `data:${mimeType};base64,${base64}`;
            } 
            // JIKA MENGGUNAKAN LINK URL
            else if (bannerUrlInput && bannerUrlInput.trim() !== '') {
                finalBanner = bannerUrlInput.trim();
            } else {
                return res.status(400).json({ status: false, message: 'Silakan pilih berkas upload (Maks. 4MB) atau masukkan URL Link banner!' });
            }

            const updatedUser = await UserV2.findByIdAndUpdate(
                userIdToUpdate,
                { $set: { banner: finalBanner } },
                { new: true, runValidators: true }
            );

            if (!updatedUser) {
                return res.status(404).json({ status: false, message: 'User tidak ditemukan.' });
            }

            return res.json({
                status: true,
                message: 'Banner profil berhasil diperbarui!',
                banner: updatedUser.banner
            });

        } catch (error) {
            console.error("Gagal update banner:", error);
            return res.status(500).json({ status: false, message: 'Terjadi kesalahan pada server saat memperbarui banner.' });
        }
    });
});



app.post('/api/reviews', checkAuthSession, (req, res) => {
    uploadReviewMedia.array('mediaFiles', 5)(req, res, async (err) => {
        if (err) {
            if (err.code === 'LIMIT_FILE_SIZE') {
                return res.status(400).json({ status: false, message: 'Ukuran berkas maksimal 5MB!' });
            }
            return res.status(400).json({ status: false, message: err.message || 'Gagal mengunggah berkas.' });
        }

        try {
            if (!req.user) {
                return res.status(401).json({ 
                    status: false, 
                    message: 'Anda wajib login terlebih dahulu untuk memberikan ulasan!' 
                });
            }

            const { productId, rating, comment } = req.body;

            if (!productId) {
                return res.status(400).json({ status: false, message: 'Product ID wajib diisi!' });
            }

            if (!rating || Number(rating) < 1 || Number(rating) > 5) {
                return res.status(400).json({ status: false, message: 'Rating bintang wajib diisi (1-5)!' });
            }

            if (!comment || !comment.trim()) {
                return res.status(400).json({ status: false, message: 'Anda diwajibkan menuliskan ulasan/penilaian!' });
            }

            const username = req.user.username || req.user.name;
            const userAvatar = req.user.avatar || 'https://cdn.larasxd.my.id/files/Z9zjj0RF7G7ena.png';
            const userId = (req.user.id || req.user._id).toString();
            const userEmail = (req.user.email || "").toLowerCase().trim();

            const product = await ProductV2.findOne({
                $or: [{ Id: productId }, { _id: mongoose.Types.ObjectId.isValid(productId) ? productId : null }]
            });

            if (!product) {
                return res.status(404).json({ status: false, message: 'Produk tidak ditemukan.' });
            }

            let existingReview = await ReviewV2.findOne({ productId, userId });

            const purchasedList = (product.purchasedBy || []).map(p => p.toLowerCase().trim());
            const isBuyer = purchasedList.some(p => 
                p === userEmail || 
                p === username.toLowerCase() || 
                p === userId.toLowerCase()
            );

            if (!isBuyer && !existingReview) {
                return res.status(403).json({
                    status: false,
                    message: 'Anda belum pernah membeli produk ini, tidak dapat memberikan penilaian!'
                });
            }

            const mediaList = [];
            if (req.files && req.files.length > 0) {
                for (const file of req.files) {
                    const mimeType = file.mimetype || mime.lookup(file.originalname) || '';
                    const isVideo = mimeType.startsWith('video/');
                    const base64 = file.buffer.toString('base64');
                    const dataUrl = `data:${mimeType};base64,${base64}`;

                    mediaList.push({
                        type: isVideo ? 'video' : 'image',
                        url: dataUrl
                    });
                }
            }

            if (existingReview) {
                let preservedMedia = Array.isArray(existingReview.media) ? [...existingReview.media] : [];

                if (req.body.keptExistingIndices !== undefined) {
                    try {
                        const keptIndices = JSON.parse(req.body.keptExistingIndices);
                        if (Array.isArray(keptIndices)) {
                            preservedMedia = keptIndices
                                .map(idx => preservedMedia[Number(idx)])
                                .filter(Boolean);
                        }
                    } catch (e) {}
                } else if (req.body.keepExistingMedia === 'false') {
                    preservedMedia = [];
                } else if (req.body.removedMediaUrls) {
                    try {
                        const removedUrls = JSON.parse(req.body.removedMediaUrls);
                        if (Array.isArray(removedUrls) && removedUrls.length > 0) {
                            preservedMedia = preservedMedia.filter(m => !removedUrls.includes(m.url));
                        }
                    } catch (e) {}
                }

                existingReview.rating = Number(rating);
                existingReview.comment = comment.trim();
                existingReview.media = [...preservedMedia, ...mediaList].slice(0, 5);
                existingReview.updatedAt = new Date();
                await existingReview.save();

                return res.json({
                    status: true,
                    message: 'Penilaian produk Anda berhasil diperbarui!',
                    data: existingReview
                });
            } else {
                const newReview = new ReviewV2({
                    productId,
                    userId,
                    username,
                    userAvatar,
                    rating: Number(rating),
                    comment: comment.trim(),
                    media: mediaList.slice(0, 5)
                });

                await newReview.save();

                return res.json({
                    status: true,
                    message: 'Penilaian produk berhasil dikirim!',
                    data: newReview
                });
            }

        } catch (error) {
            console.error("Error submit review:", error);
            return res.status(500).json({ status: false, message: 'Terjadi kesalahan server saat menyimpan ulasan.' });
        }
    });
});

app.get('/api/reviews/:productId', async (req, res) => {
    try {
        const { productId } = req.params;
        const reviews = await ReviewV2.find({ productId }).sort({ createdAt: -1 }).lean();

        const userIds = reviews.map(r => r.userId).filter(Boolean);
        const users = await UserV2.find({ _id: { $in: userIds } }).select('_id avatar username').lean();
        
        const userMap = {};
        users.forEach(u => {
            userMap[u._id.toString()] = u;
        });

        const updatedReviews = reviews.map(rev => {
            if (rev.userId && userMap[rev.userId]) {
                return {
                    ...rev,
                    userAvatar: userMap[rev.userId].avatar || rev.userAvatar,
                    username: userMap[rev.userId].username || rev.username
                };
            }
            return rev;
        });

        let averageRating = 0;
        if (updatedReviews.length > 0) {
            const totalRating = updatedReviews.reduce((sum, item) => sum + item.rating, 0);
            averageRating = Number((totalRating / updatedReviews.length).toFixed(1));
        }

        return res.json({
            status: true,
            totalReviews: updatedReviews.length,
            averageRating: averageRating,
            reviews: updatedReviews
        });
    } catch (error) {
        console.error("Error fetch reviews:", error);
        return res.status(500).json({ status: false, message: 'Gagal mengambil ulasan produk.' });
    }
});

app.delete('/api/reviews/:reviewId', checkAuthSession, async (req, res) => {
    try {
        const { reviewId } = req.params;

        if (!mongoose.Types.ObjectId.isValid(reviewId)) {
            return res.status(400).json({ status: false, message: 'ID ulasan tidak valid!' });
        }

        const review = await ReviewV2.findById(reviewId);

        if (!review) {
            return res.status(404).json({ status: false, message: 'Ulasan tidak ditemukan!' });
        }

        let currentUserId = getUserIdentifier(req);
        if (req.user) {
            currentUserId = (req.user.id || req.user._id || req.user.email || req.user.username).toString();
        }

        const currentUsername = req.user ? req.user.username : null;

        const isOwner = (review.userId && review.userId.toString() === currentUserId.toString()) ||
                        (currentUsername && review.username.toLowerCase() === currentUsername.toLowerCase());

        if (!isOwner) {
            return res.status(403).json({ status: false, message: 'Anda tidak memiliki hak akses untuk menghapus ulasan ini!' });
        }

        await ReviewV2.findByIdAndDelete(reviewId);

        return res.json({ status: true, message: 'Ulasan berhasil dihapus!' });

    } catch (error) {
        console.error("Error delete review:", error);
        return res.status(500).json({ status: false, message: 'Terjadi kesalahan server saat menghapus ulasan.' });
    }
});




app.post('/api/vouchers/claim', async (req, res) => {
    try {
        const code = req.body.code;
        if (!code) {
            return res.status(400).json({ status: false, message: 'Kode voucher wajib diisi!' });
        }

        const cleanCode = code.trim().toUpperCase();
        const userIdentifier = getUserIdentifier(req);

        const voucher = await VoucherV2.findOne({ code: cleanCode });

        if (!voucher) {
            return res.status(404).json({ status: false, message: 'Kode voucher tidak ditemukan!' });
        }

        if (voucher.usageLimit <= 0) {
            return res.status(400).json({ 
                status: false, 
                reason: 'limit_reached',
                message: 'Kuota penggunaan voucher ini sudah habis!' 
            });
        }

        if (voucher.usedBy && voucher.usedBy.includes(userIdentifier)) {
            return res.status(400).json({
                status: false,
                reason: 'already_used',
                message: 'Anda sudah pernah menggunakan voucher ini sebelumnya!'
            });
        }

        if (new Date() > new Date(voucher.expiredAt)) {
            return res.status(400).json({ 
                status: false, 
                reason: 'expired',
                message: 'Voucher telah kedaluwarsa!' 
            });
        }

        voucher.usedCount += 1;
        voucher.usageLimit = Math.max(0, voucher.usageLimit - 1); 

        if (!voucher.usedBy) voucher.usedBy = [];
        voucher.usedBy.push(userIdentifier);

        await voucher.save();

        return res.json({
            status: true,
            message: 'Voucher berhasil diklaim!',
            voucher: {
                code: voucher.code,
                discount: voucher.discount,
                type: voucher.type
            },
            data: {
                code: voucher.code,
                discount: voucher.discount,
                type: voucher.type
            }
        });
    } catch (err) {
        console.error("Error Claim Voucher:", err);
        return res.status(500).json({ status: false, message: 'Terjadi kesalahan pada server.' });
    }
});

app.get('/api/vouchers/:code', async (req, res) => {
    try {
        const code = req.query.code || req.params.code;
        if (!code) {
            return res.status(400).json({ status: false, message: 'Kode voucher wajib diisi!' });
        }

        const userIdentifier = getUserIdentifier(req);
        const voucher = await VoucherV2.findOne({ code: code.trim().toUpperCase() });
        if (!voucher) {
            return res.status(404).json({ status: false, message: 'Kode voucher tidak ditemukan!' });
        }

        if (voucher.usageLimit <= 0) {
            return res.status(400).json({ 
                status: false, 
                reason: 'limit_reached',
                message: 'Kuota penggunaan voucher ini sudah habis!' 
            });
        }

        if (voucher.usedBy && voucher.usedBy.includes(userIdentifier)) {
            return res.status(400).json({
                status: false,
                reason: 'already_used',
                message: 'Anda sudah pernah menggunakan voucher ini sebelumnya!'
            });
        }

        if (new Date() > new Date(voucher.expiredAt)) {
            return res.status(400).json({ 
                status: false, 
                reason: 'expired',
                message: 'Voucher telah kedaluwarsa!' 
            });
        }

        return res.json({
            status: true,
            message: 'Voucher berhasil ditemukan!',
            data: {
                code: voucher.code,
                discount: voucher.discount,
                type: voucher.type
            }
        });
    } catch (err) {
        return res.status(500).json({ status: false, message: 'Terjadi kesalahan pada server.' });
    }
});


// DEPOSIT & SALDO
app.post('/api/deposit', checkAuthSession, async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({ status: false, message: 'Silakan login terlebih dahulu untuk deposit.' });
        }

        const amount = Number(req.body.amount);
        const customerPhone = (req.body.customerPhone || '').toString().replace(/[\s\-()]/g, '').trim();

        if (isNaN(amount) || amount < 1000) {
            return res.status(400).json({ status: false, message: 'Deposit minimal adalah Rp 1.000!' });
        }

        if (!isValidIndonesianPhone(customerPhone)) {
            return res.status(400).json({ 
                status: false, 
                message: 'Nomor HP Indonesia aktif wajib diisi dengan format 08xx, 62xx, atau +62!' 
            });
        }

        const activeUser = await UserV2.findById(req.user.id || req.user._id).lean();
        const customerName = (activeUser?.username || req.user.name || req.user.username || 'Pelanggan').trim();
        const customerEmail = (activeUser?.email || req.user.email).toLowerCase().trim();

        const orderId = `TRX-${Date.now()}-${Math.floor(1000 + Math.random() * 9000)}`;

        // Request ke Endpoint Paywuz v2 /transactions/qris
        const paywuzRes = await axiosPaywuzWithRetry({
            method: 'post',
            url: `${PAYWUZ_BASE_URL}/transactions/qris`,
            data: {
                orderId,
                amount: amount,
                feeByMerchant: false,
                customer: {
                    name: customerName,
                    phone: customerPhone,
                    email: customerEmail
                }
            },
            headers: PAYWUZ_HEADERS
        });

        const transactionData = paywuzRes.data?.data || paywuzRes.data;
        const qrisString = transactionData?.payment?.qrString || 
                           transactionData?.qrString || 
                           transactionData?.payment?.qrUrl ||
                           transactionData?.paymentNumber;

        if (!qrisString) {
            throw new Error("Gateway tidak mengembalikan payment.qrString yang valid.");
        }

        const safeNum = (val) => {
            const num = Number(val);
            return (!isNaN(num) && num > 0) ? num : null;
        };

        const feeFlatIdr = Number(transactionData.feeFlatIdr) || 290;
        const feePercentBps = Number(transactionData.feePercentBps) || 70;
        const calculatedFee = feeFlatIdr + Math.ceil((amount * feePercentBps) / 10000);

        let finalAmount = safeNum(transactionData.grossAmount) || 
                          safeNum(transactionData.totalAmount) || 
                          safeNum(transactionData.total);

        if (!finalAmount) {
            const feeVal = safeNum(transactionData.fee) || safeNum(transactionData.feeAdmin) || calculatedFee;
            finalAmount = amount + feeVal;
        }

        const expiredAt = transactionData.expiredAt 
            ? new Date(transactionData.expiredAt) 
            : new Date(Date.now() + 15 * 60 * 1000);

        const newTrx = new TransactionV2({
            orderId,
            amount: finalAmount,
            paymentNumber: qrisString,
            paymentMethod: "QRIS",
            type: "DEPOSIT",
            userEmail: customerEmail,
            status: (transactionData.status || "pending").toLowerCase(),
            itemDetails: {
                nama: `Deposit Saldo Rp ${amount.toLocaleString('id-ID')}`,
                harga: amount,
                buyer: customerEmail
            },
            expiredAt: expiredAt
        });

        await newTrx.save();

        return res.json({
            status: true,
            data: {
                ...newTrx.toObject(),
                payment: {
                    qrString: qrisString
                }
            }
        });

    } catch (error) {
        console.error("Error Create Deposit TRX v2:", error.response?.data || error.message);
        return res.status(500).json({
            status: false,
            message: error.response?.data?.message || error.message || "Gagal membuat invoice deposit QRIS v2"
        });
    }
});


app.post('/api/store/pay-with-balance', checkAuthSession, async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({ status: false, message: "Silakan login terlebih dahulu untuk bertransaksi." });
        }

        const { productId, qty, voucherCode, orderId: clientOrderId } = req.body;
        const buyQty = Number(qty) || 1;

        if (!productId) {
            return res.status(400).json({ status: false, message: "Product ID wajib diisi!" });
        }

        const dbProduct = await ProductV2.findOne({
            $or: [{ Id: productId }, { _id: mongoose.Types.ObjectId.isValid(productId) ? productId : null }]
        });

        if (!dbProduct) {
            return res.status(404).json({ status: false, message: "Produk tidak ditemukan di database." });
        }

        const user = await UserV2.findById(req.user.id || req.user._id);
        if (!user) {
            return res.status(404).json({ status: false, message: "Data akun tidak ditemukan." });
        }

        const unitPrice = dbProduct.harga_diskon || dbProduct.harga;
        let totalPrice = unitPrice * buyQty;

        let discountAmount = 0;
        if (voucherCode && voucherCode.trim()) {
            const v = await VoucherV2.findOne({ code: voucherCode.trim().toUpperCase() });
            if (v && v.usageLimit > 0 && new Date() <= new Date(v.expiredAt)) {
                if (v.type === 'percentage') {
                    discountAmount = Math.floor((totalPrice * v.discount) / 100);
                } else if (v.type === 'fixed') {
                    discountAmount = v.discount;
                }
            }
        }

        const finalPrice = Math.max(0, totalPrice - discountAmount);
        const orderId = (clientOrderId && String(clientOrderId).trim())
            ? String(clientOrderId).trim()
            : `TRX-${Date.now()}-${Math.floor(100 + Math.random() * 900)}`;

        const saveCancelledBalanceTrx = async () => {
            await TransactionV2.findOneAndUpdate(
                { orderId },
                {
                    $setOnInsert: {
                        orderId,
                        amount: finalPrice,
                        paymentMethod: "SALDO",
                        status: "cancelled",
                        type: "PURCHASE",
                        userEmail: user.email.toLowerCase().trim(),
                        itemDetails: {
                            nama: dbProduct.nama,
                            harga: unitPrice,
                            harga_setelah_voucher: finalPrice,
                            kategori: dbProduct.kategori,
                            gambar: Array.isArray(dbProduct.gambar) ? dbProduct.gambar[0] : dbProduct.gambar,
                            buyer: user.email,
                            qty: buyQty
                        },
                        expiredAt: new Date(),
                        createdAt: new Date(),
                        updatedAt: new Date()
                    }
                },
                { upsert: true, new: true }
            );
        };

        if (dbProduct.stok < buyQty) {
            await saveCancelledBalanceTrx();
            return res.status(400).json({ status: false, message: "Stok produk tidak mencukupi! Transaksi dibatalkan." });
        }

        const currentBalance = user.saldo || 0;

        if (currentBalance < finalPrice) {
            await saveCancelledBalanceTrx();
            return res.status(400).json({ 
                status: false, 
                insufficientBalance: true,
                message: "Saldo tidak tersedia, silahkan deposit!" 
            });
        }

        user.saldo = currentBalance - finalPrice;
        await user.save();

        await updateProductStockAndSold(dbProduct.nama, buyQty, false);
        await recordProductBuyer(dbProduct.nama, user.email);

        await TransactionV2.findOneAndUpdate(
            { orderId },
            {
                $set: {
                    orderId,
                    amount: finalPrice,
                    paymentMethod: "SALDO",
                    status: "success",
                    type: "PURCHASE",
                    userEmail: user.email.toLowerCase().trim(),
                    itemDetails: {
                        nama: dbProduct.nama,
                        harga: unitPrice,
                        harga_setelah_voucher: finalPrice,
                        kategori: dbProduct.kategori,
                        gambar: Array.isArray(dbProduct.gambar) ? dbProduct.gambar[0] : dbProduct.gambar,
                        link: dbProduct.link,
                        buyer: user.email,
                        qty: buyQty
                    },
                    productLink: dbProduct.link,
                    downloadCount: 0,
                    downloadedAt: null,
                    expiredAt: new Date(),
                    updatedAt: new Date()
                }
            },
            { upsert: true, new: true }
        );

        const linkInfo = classifyProductLink(dbProduct.link);

        return res.json({
            status: true,
            message: "Pembayaran berhasil menggunakan Saldo!",
            data: {
                orderId: orderId,
                amount: finalPrice,
                linkType: linkInfo.linkType,
                chatUrl: linkInfo.chatUrl,
                specialDescription: linkInfo.specialDescription,
                downloadCount: 0,
                maxDownloads: 1,
                remainingBalance: user.saldo
            }
        });

    } catch (err) {
        console.error("Error Pay with balance:", err);
        return res.status(500).json({ status: false, message: "Terjadi kesalahan server saat memproses transaksi saldo." });
    }
});

// ENDPOINT PENCATATAN TRANSAKSI BATAL SAAT CHECKOUT SALDO DITUTUP / DIBATALKAN
app.post('/api/store/cancel-balance-order', checkAuthSession, async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({ status: false, message: "Unauthorized" });
        }

        const { orderId, productId, qty, amount } = req.body;
        if (!orderId || !productId) {
            return res.status(400).json({ status: false, message: "Data pesanan tidak lengkap." });
        }

        const dbProduct = await ProductV2.findOne({
            $or: [{ Id: productId }, { _id: mongoose.Types.ObjectId.isValid(productId) ? productId : null }]
        }).lean();

        if (!dbProduct) {
            return res.status(404).json({ status: false, message: "Produk tidak ditemukan." });
        }

        const buyQty = Math.max(1, Number(qty) || 1);
        const unitPrice = dbProduct.harga_diskon || dbProduct.harga;
        const finalAmount = Number(amount) >= 0 ? Number(amount) : unitPrice * buyQty;
        const userEmail = (req.user.email || '').toLowerCase().trim();

        const existingTrx = await TransactionV2.findOne({ orderId: String(orderId).trim() }).lean();
        if (existingTrx) {
            return res.json({ status: true, message: "Status transaksi sudah tercatat.", data: existingTrx });
        }

        const cancelledTrx = await TransactionV2.create({
            orderId: String(orderId).trim(),
            amount: finalAmount,
            paymentMethod: "SALDO",
            status: "cancelled",
            type: "PURCHASE",
            userEmail,
            itemDetails: {
                nama: dbProduct.nama,
                harga: unitPrice,
                harga_setelah_voucher: finalAmount,
                kategori: dbProduct.kategori,
                gambar: Array.isArray(dbProduct.gambar) ? dbProduct.gambar[0] : dbProduct.gambar,
                buyer: userEmail,
                qty: buyQty
            },
            expiredAt: new Date()
        });

        return res.json({ status: true, message: "Transaksi dicatat sebagai dibatalkan.", data: cancelledTrx });
    } catch (err) {
        console.error("Error cancel balance order:", err);
        return res.status(500).json({ status: false, message: "Gagal mencatat pembatalan transaksi." });
    }
});

app.get('/api/store/download/:orderId', checkAuthSession, async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({ status: false, message: 'Silakan login terlebih dahulu!' });
        }

        const { orderId } = req.params;
        const userEmail = (req.user.email || '').toLowerCase().trim();

        const trx = await TransactionV2.findOne({ orderId });
        if (!trx) {
            return res.status(404).json({ status: false, message: 'Transaksi tidak ditemukan!' });
        }

        if (trx.userEmail && trx.userEmail.toLowerCase().trim() !== userEmail) {
            return res.status(403).json({ status: false, message: 'Anda tidak memiliki akses ke transaksi ini!' });
        }

        if (trx.type === 'DEPOSIT') {
            return res.status(400).json({ status: false, message: 'Transaksi deposit tidak memiliki file produk.' });
        }

        const status = (trx.status || '').toLowerCase();
        if (!['settlement', 'success', 'paid', 'settled'].includes(status)) {
            return res.status(400).json({ status: false, message: 'Pembayaran transaksi belum lunas!' });
        }

        let targetLink = trx.productLink || trx.itemDetails?.link || '';
        if (!targetLink && trx.itemDetails?.nama) {
            const dbProduct = await ProductV2.findOne({
                nama: { $regex: new RegExp(`^${trx.itemDetails.nama.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i') }
            }).lean();
            if (dbProduct?.link) targetLink = dbProduct.link;
        }

        if (!targetLink) {
            return res.status(404).json({ status: false, message: 'File produk tidak ditemukan.' });
        }

        const linkInfo = classifyProductLink(targetLink);
        if (linkInfo.linkType !== 'download') {
            return res.status(400).json({
                status: false,
                isChatLink: true,
                ...linkInfo
            });
        }

        const source = resolveProductSource(targetLink);
        if (!source) {
            return res.status(404).json({
                status: false,
                message: 'File produk tidak ditemukan di server. Hubungi admin.'
            });
        }

        if ((Number(trx.downloadCount) || 0) >= 1) {
            return res.status(403).json({
                status: false,
                alreadyDownloaded: true,
                message: 'Kuota download untuk transaksi ini sudah digunakan (Maksimal 1x per transaksi).'
            });
        }

        // Kunci sementara (anti klik ganda). Kuota BARU dihitung setelah file selesai terkirim,
        // jadi jika download gagal / server terputus, kuota user tidak hangus.
        const lockExpiry = new Date(Date.now() - 2 * 60 * 1000);
        const lockedTrx = await TransactionV2.findOneAndUpdate(
            {
                orderId,
                $and: [
                    { $or: [{ downloadCount: { $lt: 1 } }, { downloadCount: { $exists: false } }] },
                    { $or: [{ downloadLockedAt: null }, { downloadLockedAt: { $exists: false } }, { downloadLockedAt: { $lt: lockExpiry } }] }
                ]
            },
            { $set: { downloadLockedAt: new Date() } },
            { new: true }
        );

        if (!lockedTrx) {
            const fresh = await TransactionV2.findOne({ orderId }).lean();
            if ((Number(fresh?.downloadCount) || 0) >= 1) {
                return res.status(403).json({
                    status: false,
                    alreadyDownloaded: true,
                    message: 'Kuota download untuk transaksi ini sudah digunakan (Maksimal 1x per transaksi).'
                });
            }
            return res.status(409).json({
                status: false,
                message: 'Download untuk transaksi ini sedang berjalan. Tunggu sebentar lalu coba lagi.'
            });
        }

        const releaseLock = async () => {
            try {
                await TransactionV2.updateOne({ orderId, downloadCount: { $lt: 1 } }, { $set: { downloadLockedAt: null } });
                await deleteCache(`trx_${orderId}`);
            } catch (e) {
                console.error('Gagal melepas kunci download:', e.message);
            }
        };

        const markUsed = async () => {
            try {
                await TransactionV2.updateOne(
                    { orderId },
                    { $set: { downloadCount: 1, downloadedAt: new Date(), downloadLockedAt: null } }
                );
                await deleteCache(`trx_${orderId}`);
            } catch (e) {
                console.error('Gagal mencatat kuota download:', e.message);
            }
        };

        // Kirim stream ke client; kuota dicatat saat seluruh data sudah dibaca dari sumber
        const streamToClient = (readable) => {
            let finished = false;

            readable.on('error', async (streamErr) => {
                console.error('Stream error saat download produk:', streamErr.message);
                await releaseLock();
                if (!res.headersSent) {
                    res.removeHeader('Content-Disposition');
                    res.removeHeader('Content-Length');
                    res.removeHeader('Content-Type');
                    res.status(502).json({ status: false, message: 'Gagal mengunduh file produk dari server sumber. Silakan coba lagi.' });
                } else {
                    res.destroy();
                }
            });

            readable.on('end', async () => {
                finished = true;
                await markUsed();
                res.end();
            });

            res.on('close', () => {
                if (!finished) {
                    readable.destroy();
                    releaseLock();
                }
            });

            readable.pipe(res, { end: false });
        };

        const failJson = async (httpStatus, message) => {
            await releaseLock();
            res.removeHeader('Content-Disposition');
            res.removeHeader('Content-Length');
            res.removeHeader('Content-Type');
            return res.status(httpStatus).json({ status: false, message });
        };

        const fallbackName = sanitizeDownloadFilename(
            (trx.itemDetails?.nama || 'produk-arulzxd')
                .replace(/[^a-zA-Z0-9._-]+/g, '-')
                .replace(/^-+|-+$/g, '')
                .toLowerCase()
        );

        // ---------- FILE LOKAL (mis. base-arulz.html di folder project) ----------
        if (source.type === 'local') {
            try {
                const stat = await fs.promises.stat(source.filePath);
                const filename = sanitizeDownloadFilename(path.basename(source.filePath), fallbackName);
                setForcedDownloadHeaders(res, filename, stat.size);
                return streamToClient(fs.createReadStream(source.filePath));
            } catch (localErr) {
                console.error('Gagal membaca file lokal produk:', localErr.message);
                return failJson(500, 'Gagal membaca file produk. Silakan coba lagi.');
            }
        }

        // ---------- FILE REMOTE (MediaFire, Drive, Dropbox, GitHub, Pixeldrain, direct link, dll) ----------
        try {
            let originHeaders = {};
            try { originHeaders = { 'Referer': new URL(source.url).origin + '/' }; } catch (e) {}

            const openUpstream = (url) => axios({
                method: 'get',
                url,
                responseType: 'stream',
                maxRedirects: 8,
                timeout: 30000,
                headers: { 'User-Agent': BROWSER_UA, 'Accept': '*/*', ...originHeaders }
            });

            const looksLikeHtmlPage = (up, url) => {
                const type = (up.headers['content-type'] || '').toLowerCase();
                const disp = up.headers['content-disposition'] || '';
                let ext = '';
                try { ext = path.extname(new URL(url).pathname).toLowerCase(); } catch (e) {}
                return type.includes('text/html') && !disp && !['.html', '.htm'].includes(ext);
            };

            let directUrl = await resolveRemoteDownloadUrl(source.url);
            let upstream = await openUpstream(directUrl);

            // Jika yang terbuka ternyata halaman HTML perantara, coba cari link file langsung (1x)
            if (looksLikeHtmlPage(upstream, directUrl)) {
                const html = await readStreamAsText(upstream.data);
                const found = scrapeDirectLinkFromHtml(html, directUrl);
                if (!found || found === directUrl) {
                    return failJson(502, 'Link produk bukan link file langsung. Hubungi admin untuk memperbaiki link produk.');
                }
                directUrl = found;
                upstream = await openUpstream(directUrl);
                if (looksLikeHtmlPage(upstream, directUrl)) {
                    upstream.data.destroy();
                    return failJson(502, 'Link produk bukan link file langsung. Hubungi admin untuk memperbaiki link produk.');
                }
            }

            const upstreamType = (upstream.headers['content-type'] || '').toLowerCase();
            const contentDisp = upstream.headers['content-disposition'] || '';

            let urlBase = '';
            try {
                const finalUrl = upstream.request?.res?.responseUrl || directUrl;
                urlBase = decodeURIComponent(path.basename(new URL(finalUrl).pathname));
            } catch (e) {}

            let filename = '';
            const starMatch = contentDisp.match(/filename\*\s*=\s*(?:UTF-8|utf-8)''([^;\n]+)/i);
            const plainMatch = contentDisp.match(/filename\s*=\s*"?([^";\n]+)"?/i);
            if (starMatch && starMatch[1]) {
                try { filename = decodeURIComponent(starMatch[1].trim()); } catch (e) { filename = starMatch[1].trim(); }
            } else if (plainMatch && plainMatch[1]) {
                filename = plainMatch[1].trim();
            } else if (urlBase && urlBase.includes('.')) {
                filename = urlBase;
            }

            if (!filename) {
                const typeOnly = upstreamType.split(';')[0].trim();
                const ext = (typeOnly && typeOnly !== 'application/octet-stream' && mime.extension(typeOnly)) || 'zip';
                filename = `${fallbackName}.${ext}`;
            }
            filename = sanitizeDownloadFilename(filename, fallbackName);

            setForcedDownloadHeaders(res, filename, upstream.headers['content-length']);
            return streamToClient(upstream.data);
        } catch (fetchErr) {
            console.error('Gagal mengambil file dari upstream:', fetchErr.message);
            if (fetchErr instanceof ProductLinkError) {
                return failJson(502, fetchErr.message);
            }
            return failJson(502, 'Gagal mengunduh file produk dari server sumber. Silakan coba lagi.');
        }
    } catch (err) {
        console.error('Error One-Time Download:', err);
        if (!res.headersSent) {
            res.removeHeader('Content-Disposition');
            res.removeHeader('Content-Length');
            res.removeHeader('Content-Type');
            return res.status(500).json({ status: false, message: 'Terjadi kesalahan saat memproses download produk.' });
        }
        res.destroy();
    }
});

app.get('/transactions/:orderId', async (req, res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');

    try {
        const { orderId } = req.params;
        const forceRefresh = req.query.refresh === '1';

        if (!forceRefresh) {
            const cachedData = await getCache(`trx_${orderId}`);
            if (cachedData) {
                return res.json({ data: cachedData });
            }
        }

        let localTrx = await TransactionV2.findOne({ orderId });

        if (!localTrx) {
            return res.status(404).json({ 
                error: "TRANSACTION_NOT_FOUND", 
                message: "Transaksi tidak ditemukan" 
            });
        }

        // Jika masih pending, cek ulang ke GET /v2/transactions/:orderId jika diperlukan
        if (localTrx.status.toLowerCase() === "pending") {
            if (new Date() > new Date(localTrx.expiredAt)) {
                localTrx.status = "cancelled";
                localTrx.updatedAt = new Date();
                await localTrx.save();
            } else {
                try {
                    const checkRes = await axiosPaywuzWithRetry({
                        method: 'get',
                        url: `${PAYWUZ_BASE_URL}/transactions/${orderId}`,
                        headers: PAYWUZ_HEADERS
                    });
                    const remoteData = checkRes.data?.data || checkRes.data;
                    const remoteStatus = remoteData?.status?.toLowerCase();

                    if (remoteStatus && remoteStatus !== localTrx.status.toLowerCase()) {
                        const prevStatus = localTrx.status.toLowerCase();
                        localTrx.status = remoteStatus;
                        localTrx.updatedAt = new Date();

                        if (["settlement", "success", "paid"].includes(remoteStatus) && !["settlement", "success", "paid"].includes(prevStatus)) {
                            if (localTrx.type === 'DEPOSIT' && localTrx.userEmail) {
                                const depositAmount = localTrx.itemDetails?.harga || localTrx.amount;
                                await UserV2.findOneAndUpdate(
                                    { email: localTrx.userEmail.toLowerCase().trim() },
                                    { $inc: { saldo: depositAmount } }
                                );
                            }
                        }
                        await localTrx.save();
                    }
                } catch (syncErr) {
                    // Abaikan error sementara saat polling remote, gunakan state DB lokal
                }
            }
        }

        const currentStatus = localTrx.status.toLowerCase();
        const isSuccess = ["settlement", "success", "paid", "settled"].includes(currentStatus);

        if (isSuccess && !localTrx.productLink && localTrx.itemDetails?.nama) {
            const dbProduct = await ProductV2.findOne({
                nama: { $regex: new RegExp(`^${localTrx.itemDetails.nama.trim()}$`, 'i') }
            }).lean();
            if (dbProduct && dbProduct.link) {
                localTrx.productLink = dbProduct.link;
                await localTrx.save();
            }
        }

        const rawLink = isSuccess ? localTrx.productLink : null;
        const linkInfo = rawLink ? classifyProductLink(rawLink) : { linkType: null, chatUrl: null, specialDescription: null };

        const responseData = {
            orderId: localTrx.orderId,
            status: currentStatus,
            amount: localTrx.amount,
            paymentNumber: localTrx.paymentNumber,
            payment: {
                qrString: localTrx.paymentNumber
            },
            expiredAt: localTrx.expiredAt,
            linkType: isSuccess ? linkInfo.linkType : null,
            chatUrl: isSuccess ? linkInfo.chatUrl : null,
            specialDescription: isSuccess ? linkInfo.specialDescription : null,
            downloadCount: localTrx.downloadCount || 0,
            maxDownloads: 1,
            itemDetails: localTrx.itemDetails ? {
                nama: localTrx.itemDetails.nama,
                harga: localTrx.itemDetails.harga,
                harga_diskon: localTrx.itemDetails.harga_diskon,
                harga_setelah_voucher: localTrx.itemDetails.harga_setelah_voucher,
                kategori: localTrx.itemDetails.kategori,
                gambar: localTrx.itemDetails.gambar,
                buyer: localTrx.itemDetails.buyer,
                qty: localTrx.itemDetails.qty
            } : null
        };

        await setCache(`trx_${orderId}`, responseData);

        res.json({ data: responseData });

    } catch (error) {
        console.error("Error Status TRX v2:", error.message);
        const localTrx = await TransactionV2.findOne({ orderId: req.params.orderId });
        if (localTrx) {
            return res.json({ data: localTrx });
        }
        res.status(500).json({ 
            error: "TRANSACTION_FETCH_FAILED", 
            message: "Gagal mengambil status transaksi" 
        });
    }
});

app.post('/transactions/:orderId/cancel', async (req, res) => {
    try {
        const { orderId } = req.params;
        const localTrx = await TransactionV2.findOne({ orderId });

        if (!localTrx) {
            return res.status(404).json({ status: false, message: "Transaksi tidak ditemukan" });
        }

        const prevStatus = localTrx.status.toLowerCase();

        try {
            await axiosPaywuzWithRetry({
                method: 'post',
                url: `${PAYWUZ_BASE_URL}/transactions/${orderId}/cancel`,
                headers: PAYWUZ_HEADERS
            });
        } catch (err) {
            console.warn(`Gateway v2 cancel notice for ${orderId}:`, err.response?.data || err.message);
        }

        if (["paid", "settlement", "success"].includes(prevStatus)) {
            if (localTrx.itemDetails && localTrx.itemDetails.nama && localTrx.type !== 'DEPOSIT') {
                const qtyPurchased = localTrx.itemDetails.qty || 1;
                await updateProductStockAndSold(localTrx.itemDetails.nama, qtyPurchased, true);
            }
        }

        localTrx.status = "cancelled";
        localTrx.updatedAt = new Date();
        await localTrx.save();

        await deleteCache(`trx_${orderId}`);

        return res.json({
            status: true,
            data: { orderId, status: "cancelled" }
        });

    } catch (error) {
        console.error("Error Cancel TRX v2:", error.message);
        res.status(500).json({
            error: "CANCEL_TRANSACTION_FAILED",
            message: error.message || "Gagal membatalkan transaksi"
        });
    }
});

app.post('/webhook', async (req, res) => {
    try {
        const signature = req.headers['x-paywuz-signature'];
        const payloadToVerify = req.rawBody || JSON.stringify(req.body);

        const isValid = verifyPaywuzSignature(payloadToVerify, signature, PAYWUZ_API_KEY);

        // Respons 401 (4xx selain 429) -> Paywuz TIDAK akan mengirim ulang webhook tidak valid
        if (!isValid) {
            return res.status(401).json({ 
                error: "INVALID_SIGNATURE", 
                message: "Signature webhook X-Paywuz-Signature tidak valid!" 
            });
        }

        const payload = req.body;
        const eventName = payload?.event || payload?.type; 
        const payloadData = payload?.data || payload;
        const orderId = payloadData?.orderId;
        const status = payloadData?.status ? payloadData.status.toLowerCase() : null;

        // Respons 400 (4xx selain 429) -> Tidak perlu di-retry
        if (!orderId) {
            return res.status(400).json({ error: "MISSING_ORDER_ID", message: "orderId tidak ada!" });
        }

        let localTrx = await TransactionV2.findOne({ orderId });

        if (localTrx) {
            const prevStatus = localTrx.status.toLowerCase();
            if (status) {
                localTrx.status = status;
            } else if (eventName === "transaction.paid") {
                localTrx.status = "success";
            }
            localTrx.updatedAt = new Date();

            const isPaidEvent = eventName === "transaction.paid";
            const isCancelEvent = ["cancelled", "failed", "expired"].includes(localTrx.status);

            // Idempotency check: Cegah penambahan saldo/stok ganda jika Paywuz melakukan retry webhook
            if (isPaidEvent && !["paid", "settlement", "success"].includes(prevStatus)) {
                if (localTrx.type === 'DEPOSIT' && localTrx.userEmail) {
                    const depositAmount = localTrx.itemDetails?.harga || localTrx.amount;
                    await UserV2.findOneAndUpdate(
                        { email: localTrx.userEmail.toLowerCase().trim() },
                        { $inc: { saldo: depositAmount } }
                    );
                } else if (localTrx.itemDetails && localTrx.itemDetails.nama) {
                    const qtyPurchased = localTrx.itemDetails.qty || 1;
                    await updateProductStockAndSold(localTrx.itemDetails.nama, qtyPurchased, false);

                    const buyerIdentifier = localTrx.userEmail || localTrx.itemDetails?.buyer || localTrx.paymentNumber;
                    await recordProductBuyer(localTrx.itemDetails.nama, buyerIdentifier);
                }

                if (!localTrx.productLink && localTrx.itemDetails?.nama && localTrx.type !== 'DEPOSIT') {
                    const dbProduct = await ProductV2.findOne({ 
                        nama: { $regex: new RegExp(`^${localTrx.itemDetails.nama.trim()}$`, 'i') } 
                    }).lean();
                    if (dbProduct) localTrx.productLink = dbProduct.link;
                }
            } 
            else if (isCancelEvent && ["paid", "settlement", "success"].includes(prevStatus)) {
                if (localTrx.type !== 'DEPOSIT' && localTrx.itemDetails && localTrx.itemDetails.nama) {
                    const qtyPurchased = localTrx.itemDetails.qty || 1;
                    await updateProductStockAndSold(localTrx.itemDetails.nama, qtyPurchased, true);
                }
            }

            await localTrx.save();
            await deleteCache(`trx_${orderId}`);
        }

        // Balas 200 OK dalam < 15 detik agar Paywuz menghentikan retry
        return res.status(200).json({ status: true, message: "Webhook v2 diproses", orderId });

    } catch (err) {
        console.error("Webhook v2 Error:", err);
        // Respons 500 (5xx) -> Memicu Paywuz mengirim ulang webhook (30s -> 60s)
        return res.status(500).json({ error: "WEBHOOK_PROCESSING_ERROR", message: "Error internal webhook" });
    }
});

app.post('/api/store/manual-order', checkAuthSession, async (req, res) => {
    try {
        const productName = req.body.productName;
        const qty = req.body.qty;
        const buyQty = Number(qty) || 1;

        if (!productName) {
            return res.status(400).json({ status: false, message: "Nama produk wajib diisi!" });
        }

        const updatedProduct = await updateProductStockAndSold(productName, buyQty);

        if (!updatedProduct) {
            return res.status(404).json({ status: false, message: "Produk tidak ditemukan di database." });
        }

        const buyer = req.user ? req.user.email : (req.body.username || getUserIdentifier(req));
        await recordProductBuyer(updatedProduct.Id || updatedProduct._id, buyer);

        return res.json({
            status: true,
            message: "Stok dan jumlah terjual berhasil diperbarui secara otomatis!",
            data: updatedProduct
        });
    } catch (err) {
        console.error("Manual Order Error:", err);
        return res.status(500).json({ status: false, message: "Terjadi kesalahan server." });
    }
});

app.get(['/api/user/transactions', '/api/my-transactions'], checkAuthSession, async (req, res) => {
    try {
        let transactions = [];
        const orderIds = req.query.orderIds ? req.query.orderIds.split(',').filter(Boolean) : [];

        if (req.user && req.user.email) {
            const uIdent = req.user.email.toLowerCase().trim();
            transactions = await TransactionV2.find({
                $or: [
                    { userEmail: uIdent },
                    { "itemDetails.buyer": uIdent },
                    { orderId: { $in: orderIds } }
                ]
            }).sort({ createdAt: -1 }).lean();
        } else if (orderIds.length > 0) {
            transactions = await TransactionV2.find({
                orderId: { $in: orderIds }
            }).sort({ createdAt: -1 }).lean();
        } else {
            transactions = [];
        }

        const paidStatuses = ['settlement', 'success', 'paid', 'settled'];

        // Sanitasi penuh: productLink & itemDetails.link TIDAK dikirim ke client,
        // hanya info tipe link + sisa kuota download agar tombol download bisa tampil di riwayat
        const sanitizedTransactions = transactions.map(trx => {
            const isDeposit = (trx.type || '').toUpperCase() === 'DEPOSIT';
            const isPaid = paidStatuses.includes((trx.status || '').toLowerCase());
            const downloadCount = Number(trx.downloadCount) || 0;

            let linkType = null;
            let chatUrl = null;
            let specialDescription = null;

            if (!isDeposit && isPaid) {
                const rawLink = trx.productLink || trx.itemDetails?.link || '';
                if (rawLink) {
                    const info = classifyProductLink(rawLink);
                    linkType = info.linkType;
                    chatUrl = info.chatUrl;
                    specialDescription = info.specialDescription;
                } else {
                    // Link belum tersimpan di transaksi; endpoint download yang akan menentukan
                    linkType = 'download';
                }
            }

            return {
                orderId: trx.orderId,
                amount: trx.amount,
                paymentMethod: trx.paymentMethod,
                type: trx.type,
                status: trx.status,
                productName: trx.itemDetails?.nama || (isDeposit ? 'Deposit Saldo Akun' : 'Pembelian Produk'),
                createdAt: trx.createdAt,
                expiredAt: trx.expiredAt,
                linkType,
                chatUrl,
                specialDescription,
                downloadCount,
                maxDownloads: 1,
                canDownload: linkType === 'download' && downloadCount < 1
            };
        });

        return res.json({ status: true, transactions: sanitizedTransactions });
    } catch (err) {
        console.error("Error fetching transaction history:", err);
        return res.status(500).json({ status: false, message: "Gagal mengambil riwayat transaksi" });
    }
});

// ============================================================
// 9. AUTHENTICATION (PASSPORT, OTP, LOGIN, REGISTER, OAUTH)
// ============================================================

// AUTHENTICATION HANDLERS
app.use(express.urlencoded({ extended: true }));
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try {
        const user = await UserV2.findById(id);
        done(null, user);
    } catch (err) {
        done(err, null);
    }
});

passport.use(new LocalStrategy({ usernameField: 'username', passwordField: 'password' }, 
    async (usernameOrEmail, password, done) => {
        try {
            const user = await UserV2.findOne({
                $or: [
                    { username: usernameOrEmail }, 
                    { email: usernameOrEmail.toLowerCase() }
                ]
            });

            if (!user) return done(null, false, { message: 'Username atau Email tidak ditemukan.' });

            if (!user.password || user.provider !== 'local') {
                return done(null, false, { 
                    message: `Akun ini terdaftar via ${user.provider.toUpperCase()}. Silakan masuk dengan tombol ${user.provider.toUpperCase()}.` 
                });
            }

            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) return done(null, false, { message: 'Kata sandi salah.' });

            return done(null, user);
        } catch (err) {
            return done(err);
        }
    }
));

// ====================================================
// FITUR API OTP KODE 6 DIGIT & PEMBATASAN MAKSIMAL 5x SEHARI
// ====================================================

// 1. ENDPOINT MINTA KODE OTP
app.post('/auth/send-otp', async (req, res) => {
    try {
        const { email, type } = req.body;
        if (!email || !type) {
            return res.status(400).json({ status: false, message: 'Email/Username dan jenis aksi wajib diisi!' });
        }

        const inputClean = email.toLowerCase().trim();
        let targetEmail = inputClean;

        if (type === 'login' || type === 'forgot') {
            const user = await UserV2.findOne({
                $or: [{ email: inputClean }, { username: inputClean }]
            });
            if (!user) {
                return res.status(404).json({ status: false, message: 'Username atau Email tidak terdaftar di sistem kami!' });
            }
            if (user.provider !== 'local') {
                return res.status(400).json({ status: false, message: `Akun mendaftar via ${user.provider.toUpperCase()}, tidak membutuhkan OTP.` });
            }
            targetEmail = user.email;
        } else if (type === 'register') {
            const existingUser = await UserV2.findOne({ email: inputClean });
            if (existingUser) {
                return res.status(400).json({ status: false, message: 'Email sudah terdaftar!' });
            }
        }

        // Cek Kuota Pengiriman Harian (Maksimal 5x)
        const canSend = await checkAndIncrementEmailLimit(targetEmail);
        if (!canSend) {
            return res.status(429).json({ status: false, message: 'Batas harian pengiriman email OTP tercapai (Maksimal 5 kali sehari).' });
        }

        // Buat Kode OTP 6 Digit
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // Expire 10 Menit

        await VerificationCode.deleteMany({ email: targetEmail, type });

        const newVerification = new VerificationCode({
            email: targetEmail,
            code: otpCode,
            type,
            expiresAt
        });
        await newVerification.save();

        const typeNames = { login: 'Login Akun', register: 'Pendaftaran Akun', forgot: 'Reset Kata Sandi' };
        await sendEmailOTP(targetEmail, otpCode, typeNames[type] || 'Verifikasi');

        return res.json({ status: true, message: `Kode verifikasi 6 digit berhasil dikirim ke ${targetEmail}.` });

    } catch (err) {
        console.error("Gagal kirim OTP:", err);
        return res.status(500).json({ status: false, message: 'Gagal mengirim kode verifikasi ke email.' });
    }
});

// 2. ENDPOINT VERIFIKASI OTP
app.post('/auth/verify-otp', async (req, res) => {
    try {
        const { email, code, type } = req.body;
        if (!email || !code || !type) {
            return res.status(400).json({ status: false, message: 'Email, kode OTP, dan jenis aksi wajib diisi!' });
        }

        const inputClean = email.toLowerCase().trim();
        const cleanCode = code.toString().trim();
        let targetEmail = inputClean;

        if (type === 'login' || type === 'forgot') {
            const user = await UserV2.findOne({
                $or: [{ email: inputClean }, { username: inputClean }]
            });
            if (user) targetEmail = user.email;
        }

        const record = await VerificationCode.findOne({
            email: targetEmail,
            code: cleanCode,
            type,
            expiresAt: { $gt: new Date() }
        });

        if (!record) {
            return res.status(400).json({ status: false, message: 'Kode OTP tidak valid atau sudah kedaluwarsa!' });
        }

        await VerificationCode.deleteOne({ _id: record._id });

        return res.json({ status: true, message: 'Verifikasi kode berhasil!' });

    } catch (err) {
        return res.status(500).json({ status: false, message: 'Gagal memproses verifikasi OTP.' });
    }
});

// 3. ENDPOINT RESET PASSWORD VIA OTP
app.post('/auth/reset-password-otp', async (req, res) => {
    try {
        const { email, code, newPassword } = req.body;
        if (!email || !code || !newPassword) {
            return res.status(400).json({ status: false, message: 'Email, Kode OTP, dan Kata Sandi Baru wajib diisi!' });
        }

        if (newPassword.length < 8) {
            return res.status(400).json({ status: false, message: 'Kata sandi baru minimal 8 karakter!' });
        }

        const cleanEmail = email.toLowerCase().trim();
        const cleanCode = code.toString().trim();

        const record = await VerificationCode.findOne({
            email: cleanEmail,
            code: cleanCode,
            type: 'forgot',
            expiresAt: { $gt: new Date() }
        });

        if (!record) {
            return res.status(400).json({ status: false, message: 'Kode OTP tidak valid atau sudah kedaluwarsa!' });
        }

        const user = await UserV2.findOne({ email: cleanEmail });
        if (!user) {
            return res.status(404).json({ status: false, message: 'Pengguna tidak ditemukan.' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        await user.save();

        await VerificationCode.deleteOne({ _id: record._id });

        return res.json({ status: true, message: 'Kata sandi berhasil diperbarui! Silakan masuk kembali.' });

    } catch (err) {
        console.error("Reset Password OTP Error:", err);
        return res.status(500).json({ status: false, message: 'Gagal mengatur ulang kata sandi.' });
    }
});

// LOGIN ROUTE
app.post('/auth/login', (req, res, next) => {
    passport.authenticate('local', async (err, user, info) => { 
        if (err) return next(err);

        if (!user) {
            const pesanGagal = info && info.message ? info.message : 'Username atau password salah.';
            return sendSweetAlert(res, 'error', 'Gagal Masuk', pesanGagal, '/login');
        }

        req.logIn(user, async (err) => { 
            if (err) return next(err);

            try {
                const userPayload = {
                    id: user._id,
                    username: user.username,
                    email: user.email,
                    name: user.username,
                    avatar: user.avatar || 'https://cdn.larasxd.my.id/files/Z9zjj0RF7G7ena.png',
                    createdAt: user.createdAt
                };

                const token = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '7d' });

                res.cookie('auth_session', token, {
                    maxAge: 7 * 24 * 60 * 60 * 1000, 
                    httpOnly: true,
                    secure: true, 
                    sameSite: 'lax'
                });

                return res.redirect('/dashboard');

            } catch (error) {
                console.error("Gagal sinkronisasi data saat login:", error);
                return next(error);
            }
        });
    })(req, res, next);
});

// REGISTER ROUTE
app.post('/auth/register', async (req, res) => {
    try {
        const { username, email, password, referralCode } = req.body;

        if (!username || !email || !password) {
            return sendSweetAlert(res, 'error', 'Pendaftaran Gagal', 'Semua data wajib diisi!', '/login');
        }

        const cleanUsername = username.trim();
        const cleanEmail = email.toLowerCase().trim();

        const existingUser = await UserV2.findOne({ 
            $or: [{ username: cleanUsername }, { email: cleanEmail }] 
        });

        if (existingUser) {
            return sendSweetAlert(res, 'warning', 'Sudah Terdaftar', 'Username atau Email sudah terdaftar!', '/login');
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const defaultAvatar = 'https://cdn.larasxd.my.id/files/Z9zjj0RF7G7ena.png';
        const myReferralCode = generateReferralCode();

        let initialSaldo = 0;
        let inviterUser = null;

        const codeToUse = referralCode || req.cookies?.pending_ref;

        if (codeToUse && codeToUse.trim()) {
            inviterUser = await UserV2.findOne({ referralCode: codeToUse.trim().toUpperCase() });
            if (inviterUser) {
                initialSaldo = 500;
                inviterUser.saldo = (inviterUser.saldo || 0) + 1000;
                await inviterUser.save();
            }
        }

        res.clearCookie('pending_ref');

        const newUser = new UserV2({
            username: cleanUsername,
            email: cleanEmail,
            password: hashedPassword,
            provider: 'local',
            avatar: defaultAvatar,
            saldo: initialSaldo,
            referralCode: myReferralCode,
            referredBy: inviterUser ? inviterUser.referralCode : null,
            createdAt: new Date()
        });
        await newUser.save();

        const userPayload = {
            id: newUser._id,
            username: newUser.username,
            name: newUser.username,
            email: newUser.email,
            avatar: defaultAvatar,
            createdAt: newUser.createdAt
        };

        const token = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '7d' });

        res.cookie('auth_session', token, {
            maxAge: 7 * 24 * 60 * 60 * 1000, 
            httpOnly: true,
            secure: true, 
            sameSite: 'lax'
        });

        req.logIn(newUser, (err) => {
            if (err) return res.redirect('/login');
            const alertMsg = inviterUser 
                ? 'Pendaftaran berhasil! Anda mendapatkan bonus saldo Rp 500 dari kode undangan.' 
                : 'Pendaftaran berhasil! Selamat datang.';
            return sendSweetAlert(res, 'success', 'Berhasil!', alertMsg, '/dashboard');
        });

    } catch (error) {
        console.error(error);
        res.status(500).send('Terjadi error internal saat pendaftaran.');
    }
});

// ENDPOINT SETEL / UBAH KATA SANDI USER
app.post('/api/user/change-password', checkAuthSession, async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({ status: false, message: 'Silakan login terlebih dahulu!' });
        }

        const { currentPassword, newPassword, confirmPassword } = req.body;
        const userId = req.user.id || req.user._id;

        const user = await UserV2.findById(userId);
        if (!user) {
            return res.status(404).json({ status: false, message: 'User tidak ditemukan.' });
        }

        if (!newPassword || newPassword.length < 8) {
            return res.status(400).json({ status: false, message: 'Kata sandi baru minimal 8 karakter!' });
        }

        if (newPassword !== confirmPassword) {
            return res.status(400).json({ status: false, message: 'Konfirmasi kata sandi tidak cocok!' });
        }

        if (user.password) {
            if (!currentPassword) {
                return res.status(400).json({ status: false, message: 'Kata sandi saat ini wajib diisi!' });
            }
            const isMatch = await bcrypt.compare(currentPassword, user.password);
            if (!isMatch) {
                return res.status(400).json({ status: false, message: 'Kata sandi saat ini salah!' });
            }
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        await user.save();

        return res.json({
            status: true,
            message: user.password ? 'Kata sandi berhasil diperbarui!' : 'Kata sandi lokal berhasil disetel!'
        });

    } catch (err) {
        console.error("Gagal ubah password:", err);
        return res.status(500).json({ status: false, message: 'Terjadi kesalahan pada server saat mengubah kata sandi.' });
    }
});

// LOGOUT ROUTE
app.get('/auth/logout', (req, res, next) => {
    res.clearCookie('auth_session');
    req.logout((err) => {
        if (err) return next(err);
        res.redirect('/login');
    });
});

/* OAuth GitHub */
app.get('/auth/github', (req, res) => {
    const ref = req.query.ref ? encodeURIComponent(req.query.ref) : '';
    const state = ref ? JSON.stringify({ ref }) : '';
    const url = `https://github.com/login/oauth/authorize?client_id=${GITHUB_CLIENT_ID}&redirect_uri=${GITHUB_CALLBACK_URL}&scope=user:email${state ? '&state=' + encodeURIComponent(state) : ''}`;
    res.redirect(url);
});

app.get('/auth/github/callback', async (req, res) => {
    const { code, state } = req.query;
    if (!code) return res.send('Authentication failed: No code provided');

    let refCodeFromState = req.cookies?.pending_ref || null;
    if (state) {
        try {
            const parsedState = JSON.parse(decodeURIComponent(state));
            if (parsedState.ref) refCodeFromState = parsedState.ref;
        } catch (e) {}
    }

    try {
        const tokenResponse = await axios.post('https://github.com/login/oauth/access_token', {
            client_id: GITHUB_CLIENT_ID,
            client_secret: GITHUB_CLIENT_SECRET,
            code: code
        }, { headers: { accept: 'application/json' } });

        const accessToken = tokenResponse.data.access_token;
        if (!accessToken) return res.send('Authentication failed: Invalid access token');

        const userResponse = await axios.get('https://api.github.com/user', {
            headers: { Authorization: `token ${accessToken}` }
        });

        const userData = userResponse.data;
        let userEmail = userData.email;

        if (!userEmail) {
            try {
                const emailsResponse = await axios.get('https://api.github.com/user/emails', {
                    headers: { Authorization: `token ${accessToken}` }
                });
                const primaryEmailObj = emailsResponse.data.find(e => e.primary && e.verified) || emailsResponse.data[0];
                if (primaryEmailObj) {
                    userEmail = primaryEmailObj.email;
                }
            } catch (emailErr) {
                console.error('Gagal mengambil private email:', emailErr.message);
            }
        }

        const finalEmail = (userEmail || `${userData.login}@github.com`).toLowerCase().trim();
        const currentUsername = (userData.login || finalEmail.split('@')[0]).toLowerCase().trim();

        let dbUser = await UserV2.findOne({ email: finalEmail });

        if (!dbUser) {
            let initialSaldo = 0;
            let inviterUser = null;

            if (refCodeFromState) {
                inviterUser = await UserV2.findOne({ referralCode: refCodeFromState.trim().toUpperCase() });
                if (inviterUser) {
                    initialSaldo = 500;
                    inviterUser.saldo = (inviterUser.saldo || 0) + 1000;
                    await inviterUser.save();
                }
            }

            dbUser = new UserV2({
                username: currentUsername,
                email: finalEmail,
                provider: 'github',
                providerId: String(userData.id),
                avatar: userData.avatar_url || 'https://cdn.larasxd.my.id/files/Z9zjj0RF7G7ena.png',
                saldo: initialSaldo,
                referralCode: generateReferralCode(),
                referredBy: inviterUser ? inviterUser.referralCode : null,
                createdAt: new Date()
            });

            await dbUser.save();
        } else {
            if (userData.avatar_url && dbUser.avatar !== userData.avatar_url) {
                dbUser.avatar = userData.avatar_url;
                await dbUser.save();
            }
        }

        res.clearCookie('pending_ref');

        const userPayload = {
            id: dbUser._id,
            username: dbUser.username,
            email: dbUser.email,
            name: userData.name || dbUser.username,
            avatar: dbUser.avatar,
            createdAt: dbUser.createdAt
        };

        const token = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '7d' });

        res.cookie('auth_session', token, {
            maxAge: 7 * 24 * 60 * 60 * 1000, 
            httpOnly: true,
            secure: true, 
            sameSite: 'lax'
        });

        res.redirect('/dashboard');
    } catch (error) {
        console.error(error);
        res.send('Login Error: ' + error.message);
    }
});

/* OAuth Google */
app.get('/auth/google', (req, res) => {
    const ref = req.query.ref ? encodeURIComponent(req.query.ref) : '';
    const state = ref ? JSON.stringify({ ref }) : '';
    const url = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${GOOGLE_CLIENT_ID}&redirect_uri=${GOOGLE_CALLBACK_URL}&response_type=code&scope=profile email${state ? '&state=' + encodeURIComponent(state) : ''}`;
    res.redirect(url);
});

app.get('/auth/google/callback', async (req, res) => {
    const { code, state } = req.query;
    if (!code) return res.send('Authentication failed: No code provided');

    let refCodeFromState = req.cookies?.pending_ref || null;
    if (state) {
        try {
            const parsedState = JSON.parse(decodeURIComponent(state));
            if (parsedState.ref) refCodeFromState = parsedState.ref;
        } catch (e) {}
    }

    try {
        const params = new URLSearchParams({
            client_id: GOOGLE_CLIENT_ID,
            client_secret: GOOGLE_CLIENT_SECRET,
            code: code,
            grant_type: 'authorization_code',
            redirect_uri: GOOGLE_CALLBACK_URL
        });

        const tokenResponse = await axios.post(
            'https://oauth2.googleapis.com/token',
            params.toString(),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            }
        );

        const accessToken = tokenResponse.data.access_token;
        const userResponse = await axios.get('https://www.googleapis.com/oauth2/v2/userinfo', {
            headers: { Authorization: `Bearer ${accessToken}` }
        });

        const userData = userResponse.data;
        const email = userData.email.toLowerCase().trim();
        const currentUsername = (userData.login || email.split('@')[0]).toLowerCase().trim();

        let dbUser = await UserV2.findOne({ email: email });

        if (!dbUser) {
            let initialSaldo = 0;
            let inviterUser = null;

            if (refCodeFromState) {
                inviterUser = await UserV2.findOne({ referralCode: refCodeFromState.trim().toUpperCase() });
                if (inviterUser) {
                    initialSaldo = 500;
                    inviterUser.saldo = (inviterUser.saldo || 0) + 1000;
                    await inviterUser.save();
                }
            }

            dbUser = new UserV2({
                username: currentUsername,
                email: email,
                provider: 'google',
                providerId: String(userData.id),
                avatar: userData.picture || 'https://cdn.larasxd.my.id/files/Z9zjj0RF7G7ena.png',
                saldo: initialSaldo,
                referralCode: generateReferralCode(),
                referredBy: inviterUser ? inviterUser.referralCode : null,
                createdAt: new Date()
            });

            await dbUser.save();
        } else {
            if (userData.picture && dbUser.avatar !== userData.picture) {
                dbUser.avatar = userData.picture;
                await dbUser.save();
            }
        }

        res.clearCookie('pending_ref');

        const userPayload = {
            id: dbUser._id,
            username: dbUser.username,
            email: dbUser.email,
            name: userData.name || dbUser.username,
            avatar: dbUser.avatar,
            createdAt: dbUser.createdAt
        };

        const token = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '7d' });

        res.cookie('auth_session', token, {
            maxAge: 7 * 24 * 60 * 60 * 1000,
            httpOnly: true,
            secure: true,
            sameSite: 'lax'
        });

        res.redirect('/dashboard');
    } catch (error) {
        console.error('Google Auth Callback Error:', error.response?.data || error.message);
        res.send('Login Error: ' + (error.response?.data?.error_description || error.message));
    }
});


// ============================================================
// 10. PAGES, OPEN GRAPH, PRODUK & DASHBOARD API
// ============================================================

app.get('/login', (req, res) => {
    if (req.user) {
        return res.redirect('/profile'); 
    }
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// NAVIGASI UTAMA
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/riwayat', (req, res) => res.sendFile(path.join(__dirname, 'public', 'riwayat.html')));
app.get('/store', (req, res) => res.sendFile(path.join(__dirname, 'public', 'store.html')));
app.get('/deposit', checkAuthSession, (req, res) => {
    if (!req.user) {
        return res.redirect('/login');
    }
    res.sendFile(path.join(__dirname, 'public', 'deposit.html'));
});
app.get('/privacy', (req, res) => res.sendFile(path.join(__dirname, 'public', 'privacy.html')));
app.get('/profile', checkAuthSession, (req, res) => {
    if (!req.user) {
        return res.redirect('/login');
    }
    res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

// ENDPOINT GENERATOR OPEN GRAPH CANVAS (1200 x 630)
app.get('/api/og/product/:productId', async (req, res) => {
    try {
        await ensureOgFonts();

        const { productId } = req.params;
        const product = await ProductV2.findOne({
            $or: [
                { Id: productId },
                { _id: mongoose.Types.ObjectId.isValid(productId) ? productId : null }
            ]
        }).lean();

        const width = 1200;
        const height = 630;
        const canvas = createCanvas(width, height);
        const ctx = canvas.getContext('2d');

        const fontDisplay = ogFontLoaded ? 'SpaceGrotesk, sans-serif' : 'sans-serif';
        const fontBody = ogFontLoaded ? 'JakartaSans, sans-serif' : 'sans-serif';
        const fontMono = ogFontLoaded ? 'JetBrainsMono, monospace' : 'monospace';

        // 1. BACKGROUND CYAN DENGAN PATTERN GRID HALUS NEO-BRUTALISM
        ctx.fillStyle = '#00E5FF';
        ctx.fillRect(0, 0, width, height);

        ctx.strokeStyle = 'rgba(0, 0, 0, 0.08)';
        ctx.lineWidth = 2;
        for (let gx = 0; gx <= width; gx += 40) {
            ctx.beginPath();
            ctx.moveTo(gx, 0);
            ctx.lineTo(gx, height);
            ctx.stroke();
        }
        for (let gy = 0; gy <= height; gy += 40) {
            ctx.beginPath();
            ctx.moveTo(0, gy);
            ctx.lineTo(width, gy);
            ctx.stroke();
        }

        // Aksen Kuning Sudut Kanan Atas & Kiri Bawah
        ctx.fillStyle = '#FFDE59';
        ctx.beginPath();
        ctx.moveTo(860, 0);
        ctx.lineTo(width, 0);
        ctx.lineTo(width, 320);
        ctx.closePath();
        ctx.fill();
        ctx.lineWidth = 4;
        ctx.strokeStyle = '#000000';
        ctx.stroke();

        ctx.beginPath();
        ctx.moveTo(0, 460);
        ctx.lineTo(280, height);
        ctx.lineTo(0, height);
        ctx.closePath();
        ctx.fill();
        ctx.stroke();

        // 2. PANEL UTAMA KIRI (KARTU INFORMASI PRODUK)
        drawNeoBox(ctx, 36, 36, 650, 558, 24, '#F5F2EB', 10, 5);

        // Header Bar Panel Kiri (Window Browser Style)
        ctx.save();
        ctx.beginPath();
        ctx.roundRect(36, 36, 650, 56, [24, 24, 0, 0]);
        ctx.fillStyle = '#FFFFFF';
        ctx.fill();
        ctx.lineWidth = 4;
        ctx.strokeStyle = '#000000';
        ctx.stroke();
        ctx.restore();

        // Tiga Titik Window (Merah, Kuning, Hijau)
        const dotColors = ['#FF5F56', '#FFBD2E', '#27C93F'];
        dotColors.forEach((c, i) => {
            ctx.fillStyle = c;
            ctx.beginPath();
            ctx.arc(68 + i * 24, 64, 7, 0, Math.PI * 2);
            ctx.fill();
            ctx.lineWidth = 2;
            ctx.strokeStyle = '#000000';
            ctx.stroke();
        });

        // Brand Name di Header Bar
        ctx.fillStyle = '#000000';
        ctx.font = `800 15px ${fontMono}`;
        ctx.fillText('SHOPARULZXD.BIZ.ID // OFFICIAL STORE', 155, 69);

        // Badge Kategori & Status Instan
        const kategoriText = (product?.kategori || 'DIGITAL PRODUCT').toUpperCase();
        ctx.font = `800 15px ${fontDisplay}`;
        const katWidth = Math.min(260, Math.max(150, ctx.measureText(kategoriText).width + 36));
        drawNeoBox(ctx, 64, 114, katWidth, 38, 10, '#FFDE59', 4, 3);
        ctx.fillStyle = '#000000';
        ctx.fillText(kategoriText.slice(0, 22), 82, 139);

        // Badge "OTOMATIS 24/7"
        drawNeoBox(ctx, 64 + katWidth + 14, 114, 165, 38, 10, '#00E676', 4, 3);
        ctx.fillStyle = '#000000';
        ctx.font = `800 14px ${fontDisplay}`;
        ctx.fillText('INSTAN 24/7', 64 + katWidth + 34, 139);

        // Judul Produk Utama
        const namaProduk = product ? product.nama : 'ArulzXD Digital Store';
        ctx.fillStyle = '#000000';
        ctx.font = `800 44px ${fontDisplay}`;
        wrapText(ctx, namaProduk, 64, 206, 595, 52, 2);

        // Deskripsi Singkat Produk
        ctx.fillStyle = '#333333';
        ctx.font = `500 20px ${fontBody}`;
        const descText = product?.deskripsi || 'Source Code, REST API, & Layanan Digital Premium dengan pengiriman otomatis.';
        wrapText(ctx, descText, 64, 305, 590, 28, 3);

        // Garis Pemisah
        ctx.strokeStyle = '#000000';
        ctx.lineWidth = 3;
        ctx.setLineDash([8, 6]);
        ctx.beginPath();
        ctx.moveTo(64, 412);
        ctx.lineTo(656, 412);
        ctx.stroke();
        ctx.setLineDash([]);

        // Kotak Harga Utama
        const hargaFinal = product ? (product.harga_diskon || product.harga) : 0;
        const hargaText = new Intl.NumberFormat('id-ID', {
            style: 'currency',
            currency: 'IDR',
            minimumFractionDigits: 0
        }).format(hargaFinal);

        ctx.font = `800 28px ${fontDisplay}`;
        const priceBoxW = Math.max(220, ctx.measureText(hargaText).width + 44);
        drawNeoBox(ctx, 64, 434, priceBoxW, 58, 14, '#000000', 5, 0);
        ctx.fillStyle = '#FFDE59';
        ctx.fillText(hargaText, 86, 473);

        // Info Stok & Terjual di Samping Harga
        const infoBoxX = 64 + priceBoxW + 16;
        const infoBoxW = 656 - infoBoxX;
        drawNeoBox(ctx, infoBoxX, 434, infoBoxW, 58, 14, '#FFFFFF', 5, 3);

        ctx.fillStyle = '#00E676';
        ctx.beginPath();
        ctx.arc(infoBoxX + 24, 463, 7, 0, Math.PI * 2);
        ctx.fill();
        ctx.lineWidth = 2;
        ctx.strokeStyle = '#000000';
        ctx.stroke();

        ctx.fillStyle = '#000000';
        ctx.font = `700 16px ${fontBody}`;
        ctx.fillText(`Stok: ${product?.stok ?? 99}  •  Terjual: ${product?.terjual ?? 0}`, infoBoxX + 42, 469);

        // Tombol CTA Bawah Full-Width
        drawNeoBox(ctx, 64, 512, 592, 56, 16, '#00E5FF', 5, 4);
        ctx.fillStyle = '#000000';
        ctx.font = `800 20px ${fontDisplay}`;
        ctx.fillText('BELI SEKARANG  →', 245, 547);

        // 3. AMBIL GAMBAR PRODUK
        let rawImages = [];
        if (product && Array.isArray(product.gambar) && product.gambar.length > 0) {
            rawImages = product.gambar.slice(0, 3);
        } else if (product && typeof product.gambar === 'string' && product.gambar.trim() !== '') {
            rawImages = [product.gambar];
        } else {
            rawImages = ['https://cdn.larasxd.my.id/files/Z9zjj0RF7G7ena.png'];
        }

        const loadedImages = await Promise.all(
            rawImages.map(async (src) => {
                try {
                    if (src.startsWith('data:image/')) {
                        const base64Data = src.split(',')[1];
                        return await loadImage(Buffer.from(base64Data, 'base64'));
                    }
                    const imgRes = await axios.get(src, {
                        responseType: 'arraybuffer',
                        timeout: 4500,
                        headers: { 'User-Agent': 'Mozilla/5.0' }
                    });
                    return await loadImage(Buffer.from(imgRes.data));
                } catch (e) {
                    return null;
                }
            })
        );
        const validImages = loadedImages.filter(Boolean);

        // Header Badge Galeri di Kanan Atas
        drawNeoBox(ctx, 718, 36, 446, 56, 16, '#FFFFFF', 6, 4);
        ctx.fillStyle = '#000000';
        ctx.font = `800 16px ${fontDisplay}`;
        ctx.fillText(`PREVIEW PRODUK (${validImages.length} FOTO)`, 742, 70);

        drawNeoBox(ctx, 1042, 46, 106, 36, 10, '#FFDE59', 0, 2.5);
        ctx.font = `800 13px ${fontMono}`;
        ctx.fillText('VERIFIED', 1060, 69);

        // 4. RENDER KARTU GAMBAR PRODUK (RAPI & PROPORSIONAL)
        const cardLayouts = {
            1: [{ x: 718, y: 114, w: 446, h: 480, angle: 0 }],
            2: [
                { x: 718, y: 114, w: 446, h: 265, angle: 0 },
                { x: 718, y: 396, w: 446, h: 198, angle: 0 }
            ],
            3: [
                { x: 718, y: 114, w: 446, h: 265, angle: 0 },
                { x: 718, y: 396, w: 215, h: 198, angle: 0 },
                { x: 949, y: 396, w: 215, h: 198, angle: 0 }
            ]
        };

        const count = Math.min(validImages.length, 3);
        if (count > 0) {
            const layouts = cardLayouts[count];
            layouts.forEach((layout, idx) => {
                const img = validImages[idx];
                if (!img) return;

                drawNeoBox(ctx, layout.x, layout.y, layout.w, layout.h, 20, '#FFFFFF', 8, 4);

                const pad = 12;
                const footerH = 34;
                const imgBoxX = layout.x + pad;
                const imgBoxY = layout.y + pad;
                const imgBoxW = layout.w - pad * 2;
                const imgBoxH = layout.h - pad * 2 - footerH;

                ctx.save();
                ctx.beginPath();
                ctx.roundRect(imgBoxX, imgBoxY, imgBoxW, imgBoxH, 12);
                ctx.clip();

                const scale = Math.max(imgBoxW / img.width, imgBoxH / img.height);
                const drawW = img.width * scale;
                const drawH = img.height * scale;
                const drawX = imgBoxX + (imgBoxW - drawW) / 2;
                const drawY = imgBoxY + (imgBoxH - drawH) / 2;

                ctx.drawImage(img, drawX, drawY, drawW, drawH);
                ctx.restore();

                ctx.lineWidth = 2.5;
                ctx.strokeStyle = '#000000';
                ctx.beginPath();
                ctx.roundRect(imgBoxX, imgBoxY, imgBoxW, imgBoxH, 12);
                ctx.stroke();

                // Label Bawah Gambar
                const labelY = layout.y + layout.h - 14;
                ctx.fillStyle = '#000000';
                ctx.font = `700 13px ${fontMono}`;
                ctx.fillText(idx === 0 ? 'UTAMA' : `FOTO #${idx + 1}`, layout.x + 16, labelY);

                drawNeoBox(ctx, layout.x + layout.w - 64, layout.y + layout.h - 30, 50, 20, 6, '#FFDE59', 0, 2);
                ctx.fillStyle = '#000000';
                ctx.font = `800 11px ${fontMono}`;
                ctx.fillText(`${idx + 1}/${count}`, layout.x + layout.w - 50, layout.y + layout.h - 16);
            });
        }

        const jpegBuffer = await canvas.encode('jpeg', 92);
        res.setHeader('Content-Type', 'image/jpeg');
        res.setHeader('Content-Length', jpegBuffer.length);
        res.setHeader('Cache-Control', 'public, max-age=3600');
        return res.send(jpegBuffer);

    } catch (error) {
        console.error('Error generate OG Canvas:', error);
        return res.redirect('https://cdn.larasxd.my.id/files/t19j.jpg');
    }
});


app.get('/store/:productId', async (req, res) => {
    try {
        const { productId } = req.params;

        const product = await ProductV2.findOne({
            $or: [
                { Id: productId },
                { _id: mongoose.Types.ObjectId.isValid(productId) ? productId : null }
            ]
        }).lean();

        if (!product) {
            return res.sendFile(path.join(__dirname, 'public', 'store.html'));
        }

        // PAKSA HTTPS AGAR WHATSAPP MAU MERENDER PREVIEW
        const host = req.get('host');
        const protocol = host.includes('localhost') ? 'http' : 'https';
        const baseUrl = `${protocol}://${host}`;
        const ogCanvasUrl = `${baseUrl}/api/og/product/${productId}`;
        const fullUrl = `${baseUrl}/store/${productId}`;

        const priceFormatted = new Intl.NumberFormat('id-ID', {
            style: 'currency',
            currency: 'IDR',
            minimumFractionDigits: 0
        }).format(product.harga_diskon || product.harga);

        const escapeMeta = (str) => String(str || '')
            .replace(/&/g, '&amp;')
            .replace(/"/g, '&quot;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');

        const shareTitle = escapeMeta(`${product.nama} (${priceFormatted}) - ArulzXD Store`);
        const shareDesc = escapeMeta(
            product.deskripsi
                ? product.deskripsi.slice(0, 160)
                : 'Beli source code dan layanan digital berkualitas di ArulzXD Store.'
        );

        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.send(`<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${shareTitle}</title>
    <meta name="description" content="${shareDesc}">

    <!-- Open Graph / WhatsApp / Facebook / Telegram -->
    <meta property="og:site_name" content="ArulzXD Store">
    <meta property="og:type" content="website">
    <meta property="og:url" content="${fullUrl}">
    <meta property="og:title" content="${shareTitle}">
    <meta property="og:description" content="${shareDesc}">
    <meta property="og:image" content="${ogCanvasUrl}">
    <meta property="og:image:secure_url" content="${ogCanvasUrl}">
    <meta property="og:image:type" content="image/jpeg">
    <meta property="og:image:width" content="1200">
    <meta property="og:image:height" content="630">

    <!-- Twitter Card -->
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:url" content="${fullUrl}">
    <meta name="twitter:title" content="${shareTitle}">
    <meta name="twitter:description" content="${shareDesc}">
    <meta name="twitter:image" content="${ogCanvasUrl}">
</head>
<body style="background-color: #F4F0EA; color: #000000; font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh;">
    <p>Mengarahkan ke produk...</p>
    <script>
        setTimeout(function() {
            window.location.replace("/store?shareId=${encodeURIComponent(productId)}");
        }, 150);
    </script>
</body>
</html>`);
    } catch (error) {
        console.error("Error Open Graph Share:", error);
        res.redirect('/store');
    }
});

app.get('/database/produk', async (req, res) => {
    try {
        const produk = await ProductV2.find({}).sort({ createdAt: -1 });
        res.json(produk);
    } catch (err) {
        console.error("Gagal mengambil data produk dari Database:", err);
        res.status(500).json({ error: "Gagal memuat data produk" });
    }
});

app.get('/api/user-status', async (req, res) => {
    if (req.user) {
        try {
            const activeUser = await UserV2.findById(req.user.id || req.user._id);

            if (!activeUser) return res.json({ loggedIn: false });

            if (!activeUser.referralCode) {
                activeUser.referralCode = generateReferralCode();
                await activeUser.save();
            }

            const uEmail = activeUser.email.toLowerCase().trim();

            const [deposits, purchases, invitedUsers] = await Promise.all([
                TransactionV2.aggregate([
                    { 
                        $match: { 
                            userEmail: uEmail, 
                            type: 'DEPOSIT', 
                            status: { $in: ['settlement', 'success', 'paid', 'settled'] } 
                        } 
                    },
                    { 
                        $group: { 
                            _id: null, 
                            total: { $sum: { $ifNull: ['$itemDetails.harga', '$amount'] } } 
                        } 
                    }
                ]),
                TransactionV2.aggregate([
                    { 
                        $match: { 
                            userEmail: uEmail, 
                            type: 'PURCHASE', 
                            status: { $in: ['settlement', 'success', 'paid', 'settled'] } 
                        } 
                    },
                    { 
                        $group: { 
                            _id: null, 
                            total: { $sum: '$amount' } 
                        } 
                    }
                ]),
                UserV2.find({ referredBy: activeUser.referralCode })
                    .select('username email createdAt')
                    .sort({ createdAt: -1 })
                    .lean()
            ]);

            const totalDeposit = deposits.length > 0 ? deposits[0].total : 0;
            const totalBelanja = purchases.length > 0 ? purchases[0].total : 0;

            res.json({
                loggedIn: true,
                user: {
                    id: activeUser._id,
                    name: activeUser.username,
                    username: activeUser.username,
                    email: activeUser.email,
                    avatar: activeUser.avatar,
                    banner: activeUser.banner || '',
                    saldo: activeUser.saldo || 0,
                    provider: activeUser.provider || 'local',
                    hasPassword: Boolean(activeUser.password),
                    referralCode: activeUser.referralCode,
                    totalDeposit: totalDeposit,
                    totalBelanja: totalBelanja,
                    invitedUsers: invitedUsers,
                    createdAt: activeUser.createdAt
                }
            });
        } catch (err) {
            res.json({ loggedIn: true, user: req.user });
        }
    } else {
        res.json({ loggedIn: false });
    }
});

app.get('/api/dashboard-stats', async (req, res) => {
    try {
        const TIMEZONE = 'Asia/Jakarta';
        const now = moment().tz(TIMEZONE);
        const startOfToday = now.clone().startOf('day');
        const startOfYesterday = startOfToday.clone().subtract(1, 'day');
        const thirtyDaysAgo = startOfToday.clone().subtract(29, 'days');

        const getTrxTimeMs = (trx) => {
            if (trx.createdAt) {
                const m = moment(trx.createdAt);
                if (m.isValid()) return m.valueOf();
            }
            if (trx.updatedAt) {
                const m = moment(trx.updatedAt);
                if (m.isValid()) return m.valueOf();
            }
            if (trx._id && typeof trx._id.getTimestamp === 'function') {
                return moment(trx._id.getTimestamp()).valueOf();
            }
            return moment().valueOf();
        };

        const [
            totalUsers,
            totalProducts,
            allTrxRaw,
            latencyMetrics
        ] = await Promise.all([
            UserV2.countDocuments(),
            ProductV2.countDocuments(),
            // Ambil semua riwayat transaksi yang masuk tanpa limit
            TransactionV2.find({})
                .sort({ createdAt: -1 })
                .select('orderId userEmail amount status itemDetails createdAt updatedAt type paymentMethod')
                .lean(),
            SystemMetricsV2.aggregate([
                { $match: { timestamp: { $gte: moment().subtract(24, 'hours').toDate() } } },
                {
                    $group: {
                        _id: null,
                        avgLatency: { $avg: '$responseTimeMs' },
                        totalRequests: { $sum: 1 }
                    }
                }
            ])
        ]);

        const successStatuses = ['settlement', 'success', 'paid', 'settled'];
        const cancelStatuses = ['cancelled', 'failed', 'expire', 'expired', 'batal'];

        const todayStartMs = startOfToday.valueOf();
        const yesterdayStartMs = startOfYesterday.valueOf();

        let lunasTrx = 0;
        let cancelTrx = 0;
        let trxToday = 0;
        let trxYesterday = 0;

        const emailSet = new Set();
        allTrxRaw.forEach(trx => {
            const st = (trx.status || '').toLowerCase();
            if (successStatuses.includes(st)) lunasTrx++;
            if (cancelStatuses.includes(st)) cancelTrx++;

            const tMs = getTrxTimeMs(trx);
            if (tMs >= todayStartMs) {
                trxToday++;
            } else if (tMs >= yesterdayStartMs && tMs < todayStartMs) {
                trxYesterday++;
            }

            if (trx.userEmail) emailSet.add(trx.userEmail.toLowerCase().trim());
            if (trx.itemDetails?.buyer && trx.itemDetails.buyer.includes('@')) {
                emailSet.add(trx.itemDetails.buyer.toLowerCase().trim());
            }
        });

        const totalTrx = allTrxRaw.length;

        const users = await UserV2.find({ email: { $in: Array.from(emailSet) } })
            .select('email username avatar')
            .lean();

        const userMap = {};
        users.forEach(u => {
            if (u.email) {
                userMap[u.email.toLowerCase().trim()] = {
                    username: u.username,
                    avatar: u.avatar
                };
            }
        });

        // Urutkan terbaru -> terlama untuk Status Transaksi (seluruh data dikirim untuk slide per 10 item)
        const allTrxDesc = [...allTrxRaw].sort((a, b) => getTrxTimeMs(b) - getTrxTimeMs(a));

        const recentTrx = allTrxDesc.map(trx => {
            const emailKey = (trx.userEmail || (trx.itemDetails?.buyer?.includes('@') ? trx.itemDetails.buyer : '') || '')
                .toLowerCase()
                .trim();
            const matchedUser = userMap[emailKey];
            let cleanName = matchedUser?.username || trx.itemDetails?.buyer || 'Pembeli Tamu';
            if (cleanName.includes('@')) cleanName = cleanName.split('@')[0];

            const trxMoment = moment(getTrxTimeMs(trx)).tz(TIMEZONE).locale('id');

            return {
                orderId: trx.orderId,
                pelanggan: cleanName,
                avatar: matchedUser?.avatar || null,
                produk: trx.itemDetails?.nama || (trx.type === 'DEPOSIT' ? 'Isi Saldo Akun' : 'Produk Digital'),
                metode: trx.paymentMethod || 'QRIS',
                amount: trx.itemDetails?.harga_setelah_voucher || trx.amount || 0,
                status: trx.status,
                createdAt: trxMoment.toISOString(),
                clockWib: `${trxMoment.format('HH:mm')} WIB`
            };
        });

        // Urutkan terlama -> terbaru dari seluruh riwayat transaksi untuk membentuk candle OHLC Analisis Pasar
        const allTrxAsc = [...allTrxDesc].reverse();

        function generateStockCandles(startMs, stepMs, bucketCount, trxItems, labelFormatter) {
            const BASE_INDEX = 10000;
            let runningVal = BASE_INDEX;
            let idx = 0;

            while (idx < trxItems.length && getTrxTimeMs(trxItems[idx]) < startMs) {
                const st = (trxItems[idx].status || '').toLowerCase();
                const val = Number(trxItems[idx].itemDetails?.harga_setelah_voucher || trxItems[idx].amount || 0);
                if (successStatuses.includes(st)) {
                    runningVal += val;
                } else if (cancelStatuses.includes(st)) {
                    const dropStep = Math.max(1000, Math.round(val * 0.5));
                    runningVal = Math.max(1000, runningVal - dropStep);
                }
                idx++;
            }

            const candles = [];
            for (let b = 0; b < bucketCount; b++) {
                const bucketStart = startMs + b * stepMs;
                const bucketEnd = bucketStart + stepMs;
                const isLastBucket = b === bucketCount - 1;

                const open = runningVal;
                let high = open;
                let low = open;
                let lunasCount = 0;
                let cancelCount = 0;
                let totalCount = 0;
                let periodOmzet = 0;

                while (idx < trxItems.length) {
                    const tMs = getTrxTimeMs(trxItems[idx]);
                    if (!isLastBucket && tMs >= bucketEnd) break;

                    const st = (trxItems[idx].status || '').toLowerCase();
                    const val = Number(trxItems[idx].itemDetails?.harga_setelah_voucher || trxItems[idx].amount || 0);
                    totalCount++;

                    if (successStatuses.includes(st)) {
                        runningVal += val;
                        periodOmzet += val;
                        lunasCount++;
                        if (runningVal > high) high = runningVal;
                    } else if (cancelStatuses.includes(st)) {
                        cancelCount++;
                        const dropStep = Math.max(1500, Math.round(val * 0.6));
                        runningVal = Math.max(1000, runningVal - dropStep);
                        if (runningVal < low) low = runningVal;
                    } else {
                        const spike = runningVal + Math.max(1000, Math.round(val * 0.35));
                        if (spike > high) high = spike;
                    }
                    idx++;
                }

                let close = runningVal;
                if (cancelCount > 0 && lunasCount === 0 && close >= open) {
                    close = Math.max(500, open - Math.max(1500, cancelCount * 1500));
                    runningVal = close;
                }
                if (close > high) high = close;
                if (close < low) low = close;

                candles.push({
                    label: labelFormatter(bucketStart),
                    o: open,
                    h: high,
                    l: low,
                    c: close,
                    volume: totalCount,
                    lunas: lunasCount,
                    batal: cancelCount,
                    omzet: periodOmzet
                });
            }

            return candles;
        }

        const hourMs = 60 * 60 * 1000;
        const dayMs = 24 * hourMs;

        // 1 Hari: 24 candle (per 1 jam terakhir)
        const start1d = now.clone().subtract(23, 'hours').startOf('hour').valueOf();
        const candles1d = generateStockCandles(
            start1d,
            hourMs,
            24,
            allTrxAsc,
            (ms) => moment(ms).tz(TIMEZONE).locale('id').format('HH:mm')
        );

        // 7 Hari: 28 candle (per 6 jam selama 7 hari terakhir)
        const sixHourMs = 6 * hourMs;
        const start7d = startOfToday.clone().subtract(6, 'days').valueOf();
        const candles7d = generateStockCandles(
            start7d,
            sixHourMs,
            28,
            allTrxAsc,
            (ms) => moment(ms).tz(TIMEZONE).locale('id').format('DD MMM')
        );

        // 1 Bulan: 30 candle (per 1 hari selama 30 hari terakhir)
        const start1m = thirtyDaysAgo.valueOf();
        const candles1m = generateStockCandles(
            start1m,
            dayMs,
            30,
            allTrxAsc,
            (ms) => moment(ms).tz(TIMEZONE).locale('id').format('DD MMM')
        );

        // Semua Riwayat: dari transaksi pertama hingga sekarang
        const firstTrxMs = allTrxAsc.length > 0 ? getTrxTimeMs(allTrxAsc[0]) : start1m;
        const firstMomentWib = moment(firstTrxMs).tz(TIMEZONE).startOf('day');
        const totalSpanMs = Math.max(dayMs, now.valueOf() - firstMomentWib.valueOf() + hourMs);
        const allBuckets = 28;
        const allStepMs = Math.ceil(totalSpanMs / allBuckets);
        const isMultiYear = now.diff(firstMomentWib, 'days') > 330;

        const candlesAll = generateStockCandles(
            firstMomentWib.valueOf(),
            allStepMs,
            allBuckets,
            allTrxAsc,
            (ms) => moment(ms).tz(TIMEZONE).locale('id').format(isMultiYear ? 'DD MMM YY' : 'DD MMM')
        );

        const systemLatency = latencyMetrics.length > 0 ? Math.round(latencyMetrics[0].avgLatency) : 12;
        const totalRequests = latencyMetrics.length > 0 ? latencyMetrics[0].totalRequests : totalTrx;

        res.json({
            status: true,
            timezone: TIMEZONE,
            serverTimeWib: now.locale('id').format('DD MMM YYYY HH:mm:ss [WIB]'),
            totalUsers,
            totalProducts,
            totalTrx,
            lunasTrx,
            cancelTrx,
            trxToday,
            trxYesterday,
            systemLatency: `${systemLatency} ms`,
            totalRequests,
            recentTrx,
            tradingSeries: {
                '1d': candles1d,
                '7d': candles7d,
                '1m': candles1m,
                'all': candlesAll
            }
        });
    } catch (err) {
        console.error("Gagal mengambil statistik dashboard:", err);
        res.status(500).json({ status: false, message: "Gagal memuat data statistik" });
    }
});

// ============================================================
// 11. START SERVER
// ============================================================

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

export default app;