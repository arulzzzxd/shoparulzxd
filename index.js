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
const CANONICAL_ORIGIN = 'https://www.shoparulzxd.biz.id';
const BASE_URL = (process.env.BASE_URL || CANONICAL_ORIGIN).replace(/\/$/, '');

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
const TELEGRAM_BOT_USERNAME = (process.env.TELEGRAM_BOT_USERNAME || '').replace(/^@/, '').trim();
const TELEGRAM_CLIENT_ID = process.env.TELEGRAM_CLIENT_ID || '';
const TELEGRAM_CLIENT_SECRET = process.env.TELEGRAM_CLIENT_SECRET || '';

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
    'SMTP_USER', 'SMTP_PASS', 'TELEGRAM_BOT_TOKEN', 'TELEGRAM_ADMIN_CHAT_ID', 'TELEGRAM_BOT_USERNAME',
    'TELEGRAM_CLIENT_ID', 'TELEGRAM_CLIENT_SECRET',
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
app.use(express.json({
    verify: (req, res, buf) => {
        req.rawBody = buf.toString('utf8');
    }
}));
app.use(cookieParser());
app.set('trust proxy', 1);

// DOMAIN KANONIS: hanya domain non-kanonis yang diarahkan ke domain utama.
// Jangan masukkan www.shoparulzxd.biz.id ke LEGACY_HOSTS karena itulah
// host kanonis; mengarahkannya ke dirinya sendiri menyebabkan redirect loop.
const CANONICAL_HOST = new URL(CANONICAL_ORIGIN).hostname.toLowerCase();
const LEGACY_HOSTS = new Set([
    'shoparulzxd.biz.id'
]);
app.use((req, res, next) => {
    const hostname = String(req.hostname || '').toLowerCase();

    // Perlindungan tambahan: jangan pernah redirect jika host sudah kanonis.
    if (hostname !== CANONICAL_HOST && LEGACY_HOSTS.has(hostname)) {
        return res.redirect(301, `${CANONICAL_ORIGIN}${req.originalUrl}`);
    }

    next();
});

// Robots.txt: jangan blokir halaman noindex; Google perlu membacanya.
app.get('/robots.txt', (req, res) => {
    res.type('text/plain').send([
        'User-agent: *',
        'Allow: /',
        'Disallow: /api/',
        'Disallow: /admin/',
        `Sitemap: ${CANONICAL_ORIGIN}/sitemap.xml`,
        ''
    ].join('\n'));
});

// Sitemap hanya memuat halaman publik yang memang layak muncul di hasil pencarian.
app.get('/sitemap.xml', (req, res) => {
    const urls = [
        `${CANONICAL_ORIGIN}/`,
        `${CANONICAL_ORIGIN}/store`,
        `${CANONICAL_ORIGIN}/privacy`
    ];
    const xmlEscape = (value) => String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\"/g, '&quot;').replace(/'/g, '&apos;');
    const xml = `<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n` +
        `<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">` +
        urls.map((url) => `<url><loc>${xmlEscape(url)}</loc></url>`).join('') +
        `</urlset>`;
    res.type('application/xml; charset=utf-8').send(xml);
});

// Sajikan aset statis setelah redirect domain kanonis.
app.use(express.static(path.join(__dirname)));

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
    hasCompletedOnboarding: { type: Boolean, default: false },
    telegramChatId: { type: String, default: null, index: true },
    telegramUsername: { type: String, default: null },
    telegramLinkedAt: { type: Date, default: null },
    telegramNotifEnabled: { type: Boolean, default: true },
    emailNotifEnabled: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});

const UserV2 = mongoose.models.UserV2 || mongoose.model('UserV2', userSchemaV2);

// TIKET SEKALI PAKAI UNTUK LOGIN TELEGRAM & PENAUTAN AKUN
const telegramTicketSchema = new mongoose.Schema({
    tokenHash: { type: String, required: true, unique: true },
    type: { type: String, enum: ['login', 'link'], required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'UserV2', default: null },
    chatId: { type: String, default: null },
    telegramUsername: { type: String, default: null },
    completed: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now, expires: 600 }
});

const TelegramTicket = mongoose.models.TelegramTicket || mongoose.model('TelegramTicket', telegramTicketSchema);

// NOTIFIKASI SCHEMA V2
const notifikasiSchemaV2 = new mongoose.Schema({
    title: { type: String, required: true, trim: true },
    message: { type: String, required: true, trim: true },
    type: { type: String, enum: ['info', 'promo', 'transaksi', 'sistem'], default: 'info' },
    link: { type: String, default: null },
    targetEmail: { type: String, default: null, lowercase: true, trim: true, index: true }, // null = broadcast semua user
    readBy: [{ type: String, lowercase: true, trim: true }], // daftar email user yang sudah membaca
    createdBy: { type: String, default: 'Admin' },
    createdAt: { type: Date, default: Date.now }
});

const NotifikasiV2 = mongoose.models.NotifikasiV2 || mongoose.model('NotifikasiV2', notifikasiSchemaV2);

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
    qrisVersion: { type: String, default: "v1" }, // 'v1' (Paywuz) atau 'v2' (Manual Dynamic QRIS)
    proofImage: { type: String, default: null },  // Menyimpan Base64 / URL Bukti Pembayaran
    proofUploadedAt: { type: Date, default: null },
    type: { type: String, enum: ['PURCHASE', 'DEPOSIT'], default: 'PURCHASE' },
    userEmail: { type: String, default: null, index: true },
    status: { type: String, default: "pending" }, // pending, waiting_verification, success, cancelled
    itemDetails: {
        nama: String,
        harga: Number,
        harga_diskon: Number,
        harga_setelah_voucher: Number,
        kategori: String,
        gambar: String,
        link: String,
        buyer: String,
        qty: Number,
        phone: String
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

// --- 5A. IDENTIFIER, REFERRAL, CACHE & VALIDASI UMUM ---

function generateReferralCode() {
    return 'REF' + Math.floor(100000 + Math.random() * 900000);
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

function sanitizeReturnTo(rawUrl, fallback = '/dashboard') {
    if (!rawUrl || typeof rawUrl !== 'string') return fallback;
    const trimmed = rawUrl.trim();
    if (!trimmed.startsWith('/') || trimmed.startsWith('//')) return fallback;
    return trimmed;
}

function isValidIndonesianPhone(phone) {
    if (!phone) return false;
    const cleaned = phone.toString().replace(/[\s\-()]/g, '');
    return /^(\+62|62|08)[0-9]{8,12}$/.test(cleaned);
}

async function setCache(key, data) {
    try {
        await CacheV2.findOneAndUpdate(
            { key },
            { data, createdAt: new Date() },
            { upsert: true, returnDocument: 'after' }
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

// --- 5B. EMAIL OTP & DISPATCH NOTIFIKASI ---

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

function createFreshMailTransporter() {
    if (!SMTP_USER || !SMTP_PASS) return null;
    return nodemailer.createTransport({
        host: SMTP_HOST,
        port: SMTP_PORT,
        secure: Number(SMTP_PORT) === 465,
        auth: { user: SMTP_USER, pass: SMTP_PASS },
        tls: { rejectUnauthorized: false }
    });
}

// HELPER KIRIM EMAIL NOTIFIKASI NEO-BRUTALISME
async function sendNotificationEmail(toEmail, title, message, linkUrl = null, existingTransporter = null, notifType = 'info', createdAt = new Date()) {
    const transporter = existingTransporter || createFreshMailTransporter();
    if (!transporter || !toEmail || toEmail.endsWith('@telegram.user')) return false;

    const escapeHtml = (str) => String(str || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');

    const typeUpper = String(notifType || 'info').toUpperCase();
    let badgeBg = '#00E5FF'; // INFO (neoCyan)
    if (typeUpper === 'PROMO') badgeBg = '#FFDE59'; // neoYellow
    else if (typeUpper === 'SISTEM') badgeBg = '#FF79C6'; // neoPink
    else if (typeUpper === 'TRANSAKSI') badgeBg = '#00E676'; // neoGreen

    const formattedDate = moment(createdAt || new Date())
        .tz('Asia/Jakarta')
        .locale('id')
        .format('DD MMM YYYY, HH:mm') + ' WIB';

    const targetHref = linkUrl || `${BASE_URL}/notifikasi`;

    await transporter.sendMail({
        from: MAIL_FROM || SMTP_USER,
        to: toEmail,
        subject: `[${typeUpper}] ${title} - ArulzXD Store`,
        html: `
<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:#F4F0EA;font-size:1px;line-height:1px;">
    ${escapeHtml(title)} — ${escapeHtml(message).slice(0, 110)}
</div>

<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#F4F0EA;">
<tr>
<td align="center" style="padding:36px 14px;">

    <!-- MAIN CARD CONTAINER (notifikasi.html neo-box style) -->
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
           style="max-width:560px;background-color:#FFFFFF;border:3px solid #000000;border-radius:18px;box-shadow:6px 6px 0px #000000;font-family:'Plus Jakarta Sans','Segoe UI',Helvetica,Arial,sans-serif;overflow:hidden;">

        <!-- TOP NAVBAR BAR (Arulz Store) -->
        <tr>
            <td style="background-color:#FFDE59;border-bottom:3px solid #000000;padding:18px 24px;">
                <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                    <tr>
                        <td style="font-size:21px;font-weight:900;color:#000000;letter-spacing:-0.4px;">
                            &#9889; Arulz<span style="display:inline-block;background-color:#000000;color:#FFFFFF;padding:2px 8px;margin-left:4px;border-radius:6px;font-size:18px;">Store</span>
                        </td>
                        <td align="right">
                            <span style="display:inline-block;background-color:#00E5FF;color:#000000;border:2px solid #000000;border-radius:8px;padding:4px 10px;font-size:10px;font-weight:900;letter-spacing:0.5px;">
                                PUSAT NOTIFIKASI
                            </span>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>

        <!-- HERO SUB-HEADER -->
        <tr>
            <td style="background-color:#00E5FF;border-bottom:3px solid #000000;padding:16px 24px;">
                <p style="margin:0;color:#000000;font-size:15px;font-weight:900;">
                    &#128276; Pemberitahuan Resmi Akun Anda
                </p>
                <p style="margin:4px 0 0 0;color:#000000;font-size:12px;font-weight:700;">
                    Informasi promo, pembaruan layanan, dan pengumuman resmi dari ArulzXD Store.
                </p>
            </td>
        </tr>

        <!-- NOTIFICATION CARD BODY -->
        <tr>
            <td style="padding:24px;">
                <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
                       style="background-color:#FFFDF2;border:3px solid #000000;border-radius:16px;box-shadow:5px 5px 0px #000000;">
                    <tr>
                        <td style="padding:20px;">
                            <!-- BADGE BARU + KATEGORI + WAKTU -->
                            <div style="margin-bottom:12px;">
                                <span style="display:inline-block;background-color:#FF2E4C;color:#FFFFFF;border:2px solid #000000;border-radius:6px;padding:2px 8px;font-size:10px;font-weight:900;margin-right:6px;">
                                    &#9679; BARU
                                </span>
                                <span style="display:inline-block;background-color:${badgeBg};color:#000000;border:2px solid #000000;border-radius:6px;padding:2px 8px;font-size:10px;font-weight:900;margin-right:6px;">
                                    ${escapeHtml(typeUpper)}
                                </span>
                                <span style="display:inline-block;color:#475569;font-family:'Courier New',Courier,monospace;font-size:11px;font-weight:700;">
                                    ${escapeHtml(formattedDate)}
                                </span>
                            </div>

                            <!-- JUDUL NOTIFIKASI -->
                            <h2 style="margin:0 0 14px 0;color:#000000;font-size:18px;font-weight:900;line-height:1.35;">
                                ${escapeHtml(title)}
                            </h2>

                            <!-- KOTAK PESAN UTAMA (bg-neoBg border-2 border-black) -->
                            <div style="background-color:#F4F0EA;border:2.5px solid #000000;border-radius:12px;padding:15px 16px;color:#000000;font-size:13.5px;font-weight:700;line-height:1.65;">
                                ${escapeHtml(message).replace(/\n/g, '<br>')}
                            </div>

                            <!-- ACTION BUTTONS -->
                            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-top:18px;">
                                <tr>
                                    <td align="center">
                                        <a href="${escapeHtml(targetHref)}"
                                           style="display:inline-block;background-color:#00E676;color:#000000;border:3px solid #000000;border-radius:12px;padding:11px 22px;font-weight:900;font-size:12px;text-decoration:none;box-shadow:4px 4px 0px #000000;letter-spacing:0.4px;">
                                            BUKA PUSAT NOTIFIKASI &#8599;
                                        </a>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>

        <!-- FOOTER -->
        <tr>
            <td style="border-top:3px solid #000000;background-color:#F4F0EA;padding:16px 24px;">
                <p style="margin:0;color:#1E293B;font-size:11px;font-weight:700;line-height:1.6;">
                    Email ini dikirim otomatis oleh sistem <strong>ArulzXD Store</strong>. Ingin menerima notifikasi lebih cepat lewat chat? Tautkan akun Telegram Anda di halaman <a href="${BASE_URL}/profile" style="color:#000000;font-weight:900;text-decoration:underline;">Profil Saya</a>.
                </p>
            </td>
        </tr>
    </table>

</td>
</tr>
</table>`
    });
    return true;
}

// HELPER KIRIM PRIVATE CHAT BOT TELEGRAM KE USER (DENGAN FALLBACK PLAIN TEXT)
async function sendTelegramUserPrivateMessage(chatId, title, message, linkUrl = null) {
    if (!TELEGRAM_BOT_TOKEN || !chatId) return false;

    const cleanChatId = String(chatId).trim();
    const finalUrl = linkUrl || `${BASE_URL}/notifikasi`;

    const escapeHtml = (str) => String(str || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');

    const htmlText = [
        `🔔 <b>${escapeHtml(title)}</b>`,
        `━━━━━━━━━━━━━━━━━━━━`,
        `${escapeHtml(message)}`,
        `━━━━━━━━━━━━━━━━━━━━`,
        `🌐 <a href="${escapeHtml(finalUrl)}">Buka Pusat Notifikasi</a>`
    ].join('\n');

    try {
        await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
            chat_id: cleanChatId,
            text: htmlText,
            parse_mode: 'HTML',
            disable_web_page_preview: true
        }, { timeout: 6000 });
        return true;
    } catch (err) {
        try {
            const plainText = `🔔 ${title}\n━━━━━━━━━━━━━━━━━━━━\n${message}\n━━━━━━━━━━━━━━━━━━━━\n🌐 ${finalUrl}`;
            await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
                chat_id: cleanChatId,
                text: plainText,
                disable_web_page_preview: true
            }, { timeout: 6000 });
            return true;
        } catch (fallbackErr) {
            console.error(`❌ Gagal kirim private chat Telegram ke ${cleanChatId}:`, fallbackErr.response?.data || fallbackErr.message);
            return false;
        }
    }
}

async function dispatchNotificationToUsers(notifDoc) {
    const transporter = createFreshMailTransporter();
    try {
        let query = {};
        if (notifDoc.targetEmail && String(notifDoc.targetEmail).trim()) {
            const targets = String(notifDoc.targetEmail)
                .split(',')
                .map(e => e.toLowerCase().trim())
                .filter(Boolean);
            query = targets.length > 1 ? { email: { $in: targets } } : { email: targets[0] };
        }

        const users = await UserV2.find(query)
            .select('email username telegramChatId telegramNotifEnabled emailNotifEnabled provider providerId')
            .lean();

        if (!users.length) return { totalUsers: 0, telegramSent: 0, emailSent: 0 };

        const targetLink = notifDoc.link
            ? (notifDoc.link.startsWith('http') ? notifDoc.link : `${BASE_URL}${notifDoc.link.startsWith('/') ? '' : '/'}${notifDoc.link}`)
            : `${BASE_URL}/notifikasi`;

        let telegramSent = 0;
        let emailSent = 0;
        const sentEmails = new Set();
        const sentChatIds = new Set();

        const BATCH_SIZE = 10;
        for (let i = 0; i < users.length; i += BATCH_SIZE) {
            const batch = users.slice(i, i + BATCH_SIZE);

            await Promise.allSettled(batch.map(async (u) => {
                const tasks = [];

                // 1. Kirim ke Telegram User jika tertaut & notifikasi Telegram ON
                const tgChatId = (u.telegramChatId && String(u.telegramChatId).trim())
                    || (u.provider === 'telegram' && u.providerId ? String(u.providerId).trim() : null);

                if (tgChatId && u.telegramNotifEnabled !== false && !sentChatIds.has(tgChatId)) {
                    sentChatIds.add(tgChatId);
                    tasks.push(
                        sendTelegramUserPrivateMessage(tgChatId, notifDoc.title, notifDoc.message, targetLink)
                            .then((ok) => { if (ok) telegramSent++; })
                    );
                }

                // 2. Kirim ke Email User jika valid & notifikasi Email ON
                const cleanEmail = (u.email || '').toLowerCase().trim();
                if (cleanEmail && cleanEmail.includes('@') && !cleanEmail.endsWith('@telegram.user') && u.emailNotifEnabled !== false && !sentEmails.has(cleanEmail)) {
                    sentEmails.add(cleanEmail);
                    tasks.push(
                        sendNotificationEmail(
                            cleanEmail,
                            notifDoc.title,
                            notifDoc.message,
                            targetLink,
                            transporter,
                            notifDoc.type,
                            notifDoc.createdAt
                        )
                            .then((ok) => { if (ok) emailSent++; })
                            .catch((e) => console.error(`❌ Gagal kirim email notif ke ${cleanEmail}:`, e.message))
                    );
                }

                await Promise.allSettled(tasks);
            }));
        }

        console.log(`✅ Broadcast Notifikasi "${notifDoc.title}" -> Total User: ${users.length}, Telegram: ${telegramSent}, Email: ${emailSent}`);
        return { totalUsers: users.length, telegramSent, emailSent };
    } catch (err) {
        console.error('❌ Error dispatchNotificationToUsers:', err.message);
        return { totalUsers: 0, telegramSent: 0, emailSent: 0 };
    } finally {
        if (transporter && typeof transporter.close === 'function') {
            transporter.close();
        }
    }
}

// --- 5C. QRIS DINAMIS & TELEGRAM ADMIN HELPERS ---

const STATIC_QRIS_V2_BASE = "00020101021126570011ID.DANA.WWW011893600915396562113302099656211330303UMI51440014ID.CO.QRIS.WWW0215ID10254420078250303UMI5204481453033605802ID5914IDZHARUL STORE600409146105531936304C1E4";

function calcCRC16(str) {
    let crc = 0xFFFF;
    for (let c = 0; c < str.length; c++) {
        crc ^= str.charCodeAt(c) << 8;
        for (let i = 0; i < 8; i++) {
            if (crc & 0x8000) {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc = crc << 1;
            }
        }
    }
    let hex = (crc & 0xFFFF).toString(16).toUpperCase();
    return hex.padStart(4, '0');
}

function generateDynamicQris(staticQris, nominal) {
    // 1. Hapus 4 karakter CRC lama di akhir (setelah tag 6304)
    let qrisWithoutCrc = staticQris.slice(0, -4);

    // 2. Ubah Point of Initiation Method dari Statis (010211) menjadi Dinamis (010212)
    qrisWithoutCrc = qrisWithoutCrc.replace("010211", "010212");

    // 3. Buat Tag 54 (Transaction Amount)
    const amountStr = String(Math.floor(Number(nominal)));
    const amountLen = String(amountStr.length).padStart(2, '0');
    const tag54 = `54${amountLen}${amountStr}`;

    // 4. Sisipkan Tag 54 tepat sebelum Tag 5802ID (Country Code)
    const countryTagIndex = qrisWithoutCrc.indexOf("5802ID");
    if (countryTagIndex !== -1) {
        qrisWithoutCrc =
            qrisWithoutCrc.slice(0, countryTagIndex) +
            tag54 +
            qrisWithoutCrc.slice(countryTagIndex);
    } else {
        // Fallback jika 5802ID tidak ditemukan, sisipkan sebelum 6304
        const crcTagIndex = qrisWithoutCrc.lastIndexOf("6304");
        qrisWithoutCrc =
            qrisWithoutCrc.slice(0, crcTagIndex) +
            tag54 +
            qrisWithoutCrc.slice(crcTagIndex);
    }

    // 5. Hitung ulang CRC16-CCITT dan tempelkan di akhir
    const newCrc = calcCRC16(qrisWithoutCrc);
    return qrisWithoutCrc + newCrc;
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

let telegramWebhookRegistered = false;

async function ensureTelegramWebhook() {
    if (telegramWebhookRegistered || !TELEGRAM_BOT_TOKEN || !BASE_URL || BASE_URL.includes('localhost')) {
        return;
    }
    try {
        const webhookUrl = `${BASE_URL}/api/telegram/webhook`;
        const infoRes = await axios.get(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getWebhookInfo`, {
            timeout: 5000
        });
        if (infoRes.data?.result?.url !== webhookUrl) {
            await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/setWebhook`, {
                url: webhookUrl,
                allowed_updates: ['message', 'callback_query']
            }, { timeout: 5000 });
            console.log('✅ Telegram Webhook otomatis terdaftar:', webhookUrl);
        }
        telegramWebhookRegistered = true;
    } catch (err) {
        console.error('⚠️ Gagal auto-set Telegram webhook:', err.message);
    }
}

async function sendTelegramDepositProof(trx, username, imageBuffer, mimeType) {
    if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_ADMIN_CHAT_ID) return;
    await ensureTelegramWebhook();

    const escapeHtml = (str) => String(str || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');

    const nominalFormatted = new Intl.NumberFormat('id-ID', {
        style: 'currency',
        currency: 'IDR',
        minimumFractionDigits: 0
    }).format(trx.amount);

    const caption = `
🧾 <b>BUKTI PEMBAYARAN DEPOSIT QRIS V2</b>
━━━━━━━━━━━━━━━━━━━━
🆔 <b>Order ID:</b> <code>${escapeHtml(trx.orderId)}</code>
👤 <b>User:</b> ${escapeHtml(username)}
📧 <b>Email:</b> <code>${escapeHtml(trx.userEmail)}</code>
📱 <b>No. HP:</b> ${escapeHtml(trx.itemDetails?.phone || '-')}
💰 <b>Nominal:</b> <b>${nominalFormatted}</b>
⏳ <b>Status:</b> MENUNGGU KONFIRMASI ADMIN
━━━━━━━━━━━━━━━━━━━━
Pilih tindakan di bawah ini atau cek melalui Web Admin:
    `.trim();

    const replyMarkup = {
        inline_keyboard: [
            [
                { text: "✅ Konfirmasi Deposit", callback_data: `dep_approve_${trx.orderId}` },
                { text: "❌ Tolak / Cancel", callback_data: `dep_cancel_${trx.orderId}` }
            ],
            [
                { text: "🌐 Buka Panel Admin", url: `${BASE_URL}/admin` }
            ]
        ]
    };

    try {
        const formData = new FormData();
        const ext = mime.extension(mimeType) || 'jpg';
        const blob = new Blob([imageBuffer], { type: mimeType });

        formData.append('chat_id', TELEGRAM_ADMIN_CHAT_ID);
        formData.append('photo', blob, `bukti-${trx.orderId}.${ext}`);
        formData.append('caption', caption);
        formData.append('parse_mode', 'HTML');
        formData.append('reply_markup', JSON.stringify(replyMarkup));

        await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendPhoto`, {
            method: 'POST',
            body: formData
        });
    } catch (err) {
        console.error('❌ Gagal kirim foto bukti deposit ke Telegram:', err.message);
    }
}

// --- 5D. TRANSAKSI, PAYWUZ, STOK & VOUCHER HELPERS ---

async function approveDepositQrisV2(orderId, adminSource = 'Web Admin') {
    const trx = await TransactionV2.findOne({ orderId });
    if (!trx) return { ok: false, message: 'Transaksi tidak ditemukan.' };

    const currentStatus = (trx.status || '').toLowerCase();
    if (['success', 'settlement', 'paid', 'settled'].includes(currentStatus)) {
        return { ok: false, message: 'Transaksi ini sudah dikonfirmasi sebelumnya.' };
    }
    if (['cancelled', 'failed', 'expired'].includes(currentStatus)) {
        return { ok: false, message: 'Transaksi ini sudah dibatalkan sebelumnya.' };
    }

    const depositAmount = Number(trx.itemDetails?.harga || trx.amount || 0);
    if (trx.userEmail && depositAmount > 0) {
        await UserV2.findOneAndUpdate(
            { email: trx.userEmail.toLowerCase().trim() },
            { $inc: { saldo: depositAmount } }
        );
    }

    trx.status = 'success';
    trx.updatedAt = new Date();
    await trx.save();
    await deleteCache(`trx_${orderId}`);

    return {
        ok: true,
        message: `Deposit ${orderId} sebesar Rp ${depositAmount.toLocaleString('id-ID')} berhasil dikonfirmasi (${adminSource})!`,
        trx
    };
}

async function cancelDepositQrisV2(orderId, cancelledBy = 'Admin') {
    const trx = await TransactionV2.findOne({ orderId });
    if (!trx) return { ok: false, message: 'Transaksi tidak ditemukan.' };

    const currentStatus = (trx.status || '').toLowerCase();
    if (['success', 'settlement', 'paid', 'settled'].includes(currentStatus)) {
        return { ok: false, message: 'Transaksi sudah sukses, tidak dapat dibatalkan.' };
    }
    if (currentStatus === 'cancelled') {
        return { ok: false, message: 'Transaksi sudah dibatalkan sebelumnya.' };
    }

    trx.status = 'cancelled';
    trx.updatedAt = new Date();
    await trx.save();
    await deleteCache(`trx_${orderId}`);

    return {
        ok: true,
        message: `Deposit ${orderId} telah dibatalkan oleh ${cancelledBy}.`,
        trx
    };
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

const SETTLED_STATUSES = ['settlement', 'settled', 'paid', 'success', 'lunas'];
const CANCELLED_STATUSES = ['expired', 'expire', 'cancelled', 'cancel', 'failed', 'deny'];

function normalizeGatewayStatus(rawStatus) {
    const st = String(rawStatus || '').toLowerCase().trim();
    if (SETTLED_STATUSES.includes(st)) return 'settlement';
    if (CANCELLED_STATUSES.includes(st)) {
        return (st === 'expired' || st === 'expire') ? 'expired' : 'cancelled';
    }
    return st || 'pending';
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

function calculateDepositFee(amount, version = 'v1') {
    const nominal = Number(amount) || 0;
    if (nominal >= 150000) {
        // >= Rp 150.000: flat 0,95% tanpa biaya tetap tambahan
        return Math.ceil((nominal * 95) / 10000);
    }
    // < Rp 150.000: 0,7% + Rp 290 (v1) atau 0,7% + Rp 250 (v2)
    const flatFee = version === 'v2' ? 250 : 290;
    return Math.ceil((nominal * 70) / 10000) + flatFee;
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

async function processQrisV1Settlement(orderId, rawGatewayStatus) {
    const normalizedStatus = normalizeGatewayStatus(rawGatewayStatus);

    // 1. Jika status belum settlement (misal expired/cancelled), update status saja
    if (normalizedStatus !== 'settlement') {
        if (normalizedStatus === 'expired' || normalizedStatus === 'cancelled') {
            await TransactionV2.findOneAndUpdate(
                { orderId, status: { $nin: [...SETTLED_STATUSES, 'expired', 'cancelled'] } },
                { $set: { status: normalizedStatus, updatedAt: new Date() } }
            );
            await deleteCache(`trx_${orderId}`);
        }
        return await TransactionV2.findOne({ orderId }).lean();
    }

    // 2. Klaim transaksi secara ATOMIK hanya jika belum pernah di-settle sebelumnya
    const claimedTrx = await TransactionV2.findOneAndUpdate(
        {
            orderId,
            status: { $nin: SETTLED_STATUSES }
        },
        {
            $set: {
                status: 'settlement',
                updatedAt: new Date()
            }
        },
        { returnDocument: 'after' }
    );

    // Jika null, berarti transaksi sudah pernah di-settle (cegah saldo masuk 2x) atau tidak ada
    if (!claimedTrx) {
        return await TransactionV2.findOne({ orderId }).lean();
    }

    await deleteCache(`trx_${orderId}`);

    // 3. JIKA TRANSAKSI DEPOSIT -> TAMBAHKAN SALDO USER OTOMATIS
    if (String(claimedTrx.type || '').toUpperCase() === 'DEPOSIT') {
        const depositAmount = Number(claimedTrx.itemDetails?.harga || claimedTrx.amount || 0);
        const cleanEmail = String(claimedTrx.userEmail || claimedTrx.itemDetails?.buyer || '')
            .toLowerCase()
            .trim();

        if (cleanEmail && depositAmount > 0) {
            const updatedUser = await UserV2.findOneAndUpdate(
                { email: cleanEmail },
                { $inc: { saldo: depositAmount } },
                { returnDocument: 'after' }
            );

            console.log(`✅ [QRIS V1 SETTLEMENT] Deposit ${orderId} -> +Rp ${depositAmount.toLocaleString('id-ID')} untuk ${cleanEmail} (Saldo baru: Rp ${(updatedUser?.saldo || 0).toLocaleString('id-ID')})`);

            // Simpan riwayat notifikasi transaksi user & kirim notif Telegram/Email jika aktif
            try {
                const notifDoc = await NotifikasiV2.create({
                    title: 'Deposit QRIS V1 Berhasil!',
                    message: `Deposit sebesar Rp ${depositAmount.toLocaleString('id-ID')} (${orderId}) telah berstatus SETTLEMENT dan otomatis ditambahkan ke saldo akun Anda.`,
                    type: 'transaksi',
                    link: '/deposit',
                    targetEmail: cleanEmail,
                    createdBy: 'Sistem'
                });
                dispatchNotificationToUsers(notifDoc).catch(() => {});
            } catch (notifErr) {
                console.error('⚠️ Gagal membuat notifikasi deposit:', notifErr.message);
            }
        }
    }
    // 4. JIKA TRANSAKSI PEMBELIAN PRODUK LANGSUNG VIA QRIS V1
    else if (String(claimedTrx.type || '').toUpperCase() === 'PURCHASE') {
        const prodName = claimedTrx.itemDetails?.nama;
        const buyQty = Math.max(1, Number(claimedTrx.itemDetails?.qty) || 1);
        const buyerEmail = String(claimedTrx.userEmail || claimedTrx.itemDetails?.buyer || '').toLowerCase().trim();

        if (prodName) {
            const updatedProd = await updateProductStockAndSold(prodName, buyQty, false);
            if (buyerEmail) {
                await recordProductBuyer(prodName, buyerEmail);
            }
            if (updatedProd?.link && !claimedTrx.productLink) {
                await TransactionV2.updateOne(
                    { orderId },
                    { $set: { productLink: updatedProd.link, 'itemDetails.link': updatedProd.link } }
                );
            }
        }
    }

    return await TransactionV2.findOne({ orderId }).lean();
}

async function consumeVoucherCode(voucherCode, userIdentifier, subtotalAmount) {
    if (!voucherCode || !String(voucherCode).trim()) {
        return { valid: false, discountAmount: 0, voucher: null };
    }

    const cleanCode = String(voucherCode).trim().toUpperCase();
    const voucher = await VoucherV2.findOne({ code: cleanCode });

    if (!voucher) {
        return { valid: false, message: 'Kode voucher tidak ditemukan!', discountAmount: 0, voucher: null };
    }
    if (voucher.usageLimit <= 0) {
        return { valid: false, message: 'Kuota penggunaan voucher ini sudah habis!', discountAmount: 0, voucher: null };
    }
    if (new Date() > new Date(voucher.expiredAt)) {
        return { valid: false, message: 'Voucher telah kedaluwarsa!', discountAmount: 0, voucher: null };
    }
    if (userIdentifier && voucher.usedBy && voucher.usedBy.includes(userIdentifier)) {
        return { valid: false, message: 'Anda sudah pernah menggunakan voucher ini sebelumnya!', discountAmount: 0, voucher: null };
    }

    let discountAmount = 0;
    if (voucher.type === 'percentage') {
        discountAmount = Math.floor((subtotalAmount * Number(voucher.discount || 0)) / 100);
    } else {
        discountAmount = Number(voucher.discount || 0);
    }
    discountAmount = Math.min(subtotalAmount, Math.max(0, discountAmount));

    voucher.usedCount = (voucher.usedCount || 0) + 1;
    voucher.usageLimit = Math.max(0, voucher.usageLimit - 1);
    if (userIdentifier) {
        if (!voucher.usedBy) voucher.usedBy = [];
        voucher.usedBy.push(userIdentifier);
    }
    await voucher.save();

    return { valid: true, discountAmount, voucher };
}

// --- 5E. DIRECT DOWNLOAD STREAM & RESOLVER LINK PRODUK ---

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

// --- 5F. SWEETALERT & OPEN GRAPH CANVAS HELPERS ---

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

const uploadPaymentProofMulter = multer({
    limits: { fileSize: 5 * 1024 * 1024 }, // Maks 5MB
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Bukti pembayaran harus berupa file gambar (JPG/PNG/WEBP)!'));
        }
    }
});

// ============================================================
// 7. MIDDLEWARES
// ============================================================

// Pencatat metrik latensi API & sistem
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

// Pastikan koneksi database siap & webhook Telegram terdaftar otomatis saat pertama kali ada request
app.use(async (req, res, next) => {
    try {
        await connectDB();
        if (!telegramWebhookRegistered && TELEGRAM_BOT_TOKEN) {
            ensureTelegramWebhook().catch(() => {});
        }
        next();
    } catch (err) {
        console.error('Database connection middleware error:', err.message);
        res.status(503).json({ status: false, message: 'Database sedang bersiap, silakan muat ulang halaman.' });
    }
});

// Konfigurasi Session Store MongoDB
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

// Verifikasi JWT cookie auth_session
const checkAuthSession = async (req, res, next) => {
    const token = req.cookies?.auth_session;
    let decodedUser = null;

    if (token) {
        try {
            decodedUser = jwt.verify(token, JWT_SECRET);
        } catch {
            res.clearCookie('auth_session');
        }
    }

    req.user = decodedUser;
    next();
};

app.use(checkAuthSession);

// Validasi hak akses khusus Owner/Admin
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

// --- 8A. LIVE CHAT BANTUAN & PANEL ADMIN ---

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

app.get(['/admin', '/admin/livechat'], checkAuthSession, (req, res) => {
    const ownerEmail = OWNER_EMAIL;
    if (!req.user || req.user.email?.toLowerCase().trim() !== ownerEmail) {
        return res.redirect('/dashboard');
    }
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// --- 8B. PENGATURAN PROFIL USER (USERNAME, AVATAR, BANNER) ---

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
            { returnDocument: 'after' }
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
    } catch (err) {
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
                { returnDocument: 'after', runValidators: true }
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
                        message: `Ukuran file berkas maksimal adalah 4MB! (Ukuran file Anda: ${(fileSize / (1024 * 1024)).toFixed(2)}MB)`
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
                { returnDocument: 'after', runValidators: true }
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

// --- 8C. ULASAN PRODUK (REVIEWS) & VOUCHER DISKON ---

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
        if (!code || !String(code).trim()) {
            return res.status(400).json({ status: false, message: 'Kode voucher wajib diisi!' });
        }

        const cleanCode = String(code).trim().toUpperCase();
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

        const voucherPayload = {
            code: voucher.code,
            discount: Number(voucher.discount) || 0,
            type: voucher.type || 'percentage'
        };

        return res.json({
            status: true,
            message: 'Voucher valid & berhasil diterapkan!',
            voucher: voucherPayload,
            data: voucherPayload
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

        const voucherPayload = {
            code: voucher.code,
            discount: Number(voucher.discount) || 0,
            type: voucher.type || 'percentage'
        };

        return res.json({
            status: true,
            message: 'Voucher berhasil ditemukan!',
            voucher: voucherPayload,
            data: voucherPayload
        });
    } catch (err) {
        return res.status(500).json({ status: false, message: 'Terjadi kesalahan pada server.' });
    }
});

// --- 8D. DEPOSIT QRIS V1, PEMBAYARAN SALDO, STORE CHECKOUT & ONE-TIME DOWNLOAD ---

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

        // Aturan Fee QRIS V1: >= 150.000 -> 0.95% flat | < 150.000 -> 0.7% + Rp 290
        const calculatedFee = calculateDepositFee(amount, 'v1');
        const gatewayTotal = safeNum(transactionData.grossAmount) ||
                             safeNum(transactionData.totalAmount) ||
                             safeNum(transactionData.total);

        const finalAmount = gatewayTotal || (amount + calculatedFee);
        const appliedFee = Math.max(0, finalAmount - amount);

        const expiredAt = transactionData.expiredAt
            ? new Date(transactionData.expiredAt)
            : new Date(Date.now() + 15 * 60 * 1000);

        const newTrx = new TransactionV2({
            orderId,
            amount: finalAmount,
            paymentNumber: qrisString,
            paymentMethod: "QRIS",
            qrisVersion: "v1",
            type: "DEPOSIT",
            userEmail: customerEmail,
            status: (transactionData.status || "pending").toLowerCase(),
            itemDetails: {
                nama: `Deposit Saldo Rp ${amount.toLocaleString('id-ID')}`,
                harga: amount,
                fee: appliedFee,
                buyer: customerEmail,
                phone: customerPhone
            },
            expiredAt: expiredAt
        });

        await newTrx.save();

        return res.json({
            status: true,
            data: {
                ...newTrx.toObject(),
                depositAmount: amount,
                feeAmount: appliedFee,
                payment: {
                    qrString: qrisString
                }
            }
        });

    } catch (error) {
        console.error("Error Create Deposit TRX v1:", error.response?.data || error.message);
        return res.status(500).json({
            status: false,
            message: error.response?.data?.message || error.message || "Gagal membuat invoice deposit QRIS v1"
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
        const totalPrice = unitPrice * buyQty;
        const userIdentifier = getUserIdentifier(req);

        // Hitung diskon lebih dulu sebelum cek saldo
        let discountAmount = 0;
        let validVoucherDoc = null;
        if (voucherCode && String(voucherCode).trim()) {
            const v = await VoucherV2.findOne({ code: String(voucherCode).trim().toUpperCase() });
            if (!v || v.usageLimit <= 0 || new Date() > new Date(v.expiredAt) || (v.usedBy && v.usedBy.includes(userIdentifier))) {
                return res.status(400).json({ status: false, message: "Kode voucher sudah tidak valid atau sudah digunakan!" });
            }
            validVoucherDoc = v;
            discountAmount = v.type === 'percentage'
                ? Math.floor((totalPrice * Number(v.discount || 0)) / 100)
                : Number(v.discount || 0);
            discountAmount = Math.min(totalPrice, Math.max(0, discountAmount));
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
                { upsert: true, returnDocument: 'after' }
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

        // Potong saldo & kuota voucher hanya ketika pembayaran benar-benar berhasil
        user.saldo = currentBalance - finalPrice;
        await user.save();

        if (validVoucherDoc) {
            validVoucherDoc.usedCount = (validVoucherDoc.usedCount || 0) + 1;
            validVoucherDoc.usageLimit = Math.max(0, validVoucherDoc.usageLimit - 1);
            if (!validVoucherDoc.usedBy) validVoucherDoc.usedBy = [];
            validVoucherDoc.usedBy.push(userIdentifier);
            await validVoucherDoc.save();
        }

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
            { upsert: true, returnDocument: 'after' }
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

app.post('/api/store/create-order', checkAuthSession, async (req, res) => {
    try {
        const { orderId, productId, qty, amount, paymentMethod, username, note, voucherCode } = req.body;
        if (!orderId || !productId) {
            return res.status(400).json({ status: false, message: "Data pesanan tidak lengkap." });
        }

        const dbProduct = await ProductV2.findOne({
            $or: [{ Id: productId }, { _id: mongoose.Types.ObjectId.isValid(productId) ? productId : null }]
        }).lean();

        if (!dbProduct) {
            return res.status(404).json({ status: false, message: "Produk tidak ditemukan." });
        }

        const existingTrx = await TransactionV2.findOne({ orderId: String(orderId).trim() }).lean();
        if (existingTrx) {
            return res.json({ status: true, data: existingTrx });
        }

        const buyQty = Math.max(1, Number(qty) || 1);
        const unitPrice = dbProduct.harga_diskon || dbProduct.harga;
        const subtotal = unitPrice * buyQty;
        const userIdentifier = getUserIdentifier(req);

        let finalAmount = Number(amount) >= 0 ? Number(amount) : subtotal;
        if (voucherCode && String(voucherCode).trim()) {
            const consumed = await consumeVoucherCode(voucherCode, userIdentifier, subtotal);
            if (consumed.valid) {
                finalAmount = Math.max(0, subtotal - consumed.discountAmount);
            }
        }

        const cleanMethod = ['SALDO', 'TELEGRAM', 'WHATSAPP'].includes(String(paymentMethod || '').toUpperCase())
            ? String(paymentMethod).toUpperCase()
            : 'WHATSAPP';

        const userEmail = req.user?.email ? req.user.email.toLowerCase().trim() : null;
        const buyerLabel = userEmail || (username && String(username).trim()) || 'Pembeli Tamu';

        const newTrx = await TransactionV2.create({
            orderId: String(orderId).trim(),
            amount: finalAmount,
            paymentMethod: cleanMethod,
            status: "pending",
            type: "PURCHASE",
            userEmail,
            itemDetails: {
                nama: dbProduct.nama,
                harga: unitPrice,
                harga_setelah_voucher: finalAmount,
                kategori: dbProduct.kategori,
                gambar: Array.isArray(dbProduct.gambar) ? dbProduct.gambar[0] : dbProduct.gambar,
                buyer: buyerLabel,
                qty: buyQty,
                note: note || ''
            },
            expiredAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
        });

        return res.json({ status: true, data: newTrx });
    } catch (err) {
        console.error("Error create order:", err);
        return res.status(500).json({ status: false, message: "Gagal mencatat pesanan." });
    }
});

app.post(['/api/store/cancel-balance-order', '/api/store/cancel-order'], checkAuthSession, async (req, res) => {
    try {
        const { orderId, productId, qty, amount, paymentMethod, username } = req.body;
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

        const cleanMethodRaw = String(paymentMethod || 'SALDO').trim().toUpperCase();
        const resolvedMethod = ['SALDO', 'TELEGRAM', 'WHATSAPP'].includes(cleanMethodRaw)
            ? cleanMethodRaw
            : (cleanMethodRaw === 'MANUAL' ? 'WHATSAPP' : 'SALDO');

        const userEmail = req.user?.email ? req.user.email.toLowerCase().trim() : null;
        const buyerLabel = userEmail || (username && String(username).trim()) || 'Pembeli Tamu';

        const existingTrx = await TransactionV2.findOne({ orderId: String(orderId).trim() }).lean();
        if (existingTrx) {
            if (existingTrx.status !== 'cancelled') {
                const updated = await TransactionV2.findOneAndUpdate(
                    { orderId: String(orderId).trim() },
                    { $set: { status: 'cancelled', paymentMethod: resolvedMethod, updatedAt: new Date() } },
                    { returnDocument: 'after' }
                ).lean();
                return res.json({ status: true, message: "Status transaksi diperbarui menjadi dibatalkan.", data: updated });
            }
            return res.json({ status: true, message: "Status transaksi sudah tercatat.", data: existingTrx });
        }

        const cancelledTrx = await TransactionV2.create({
            orderId: String(orderId).trim(),
            amount: finalAmount,
            paymentMethod: resolvedMethod,
            status: "cancelled",
            type: "PURCHASE",
            userEmail,
            itemDetails: {
                nama: dbProduct.nama,
                harga: unitPrice,
                harga_setelah_voucher: finalAmount,
                kategori: dbProduct.kategori,
                gambar: Array.isArray(dbProduct.gambar) ? dbProduct.gambar[0] : dbProduct.gambar,
                buyer: buyerLabel,
                qty: buyQty
            },
            expiredAt: new Date()
        });

        return res.json({ status: true, message: "Transaksi dicatat sebagai dibatalkan.", data: cancelledTrx });
    } catch (err) {
        console.error("Error cancel order:", err);
        return res.status(500).json({ status: false, message: "Gagal mencatat pembatalan transaksi." });
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
            { returnDocument: 'after' }
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

// --- 8E. STATUS TRANSAKSI, WEBHOOK PAYWUZ & RIWAYAT TRANSAKSI USER ---

app.get('/transactions/:orderId', async (req, res) => {
    try {
        const orderId = String(req.params.orderId || '').trim();
        const forceRefresh = req.query.refresh === '1';

        if (!orderId) {
            return res.status(400).json({ status: false, message: 'Order ID wajib diisi.' });
        }

        let trx = await TransactionV2.findOne({ orderId }).lean();
        if (!trx) {
            return res.status(404).json({ status: false, message: 'Transaksi tidak ditemukan.' });
        }

        const currentStatus = String(trx.status || 'pending').toLowerCase();
        const isQrisV1 = (trx.qrisVersion === 'v1' || (!trx.qrisVersion && !orderId.startsWith('QRV2-') && trx.paymentMethod === 'QRIS'));

        // Cek langsung ke API Paywuz v2 jika status masih pending & diminta refresh
        if (forceRefresh && isQrisV1 && currentStatus === 'pending') {
            try {
                const pwRes = await axiosPaywuzWithRetry({
                    method: 'get',
                    url: `${PAYWUZ_BASE_URL}/transactions/${encodeURIComponent(orderId)}`,
                    headers: PAYWUZ_HEADERS
                }, 2, 1000);

                const pwData = pwRes.data?.data || pwRes.data || {};
                const gatewayStatus = pwData.status || pwData.transaction_status || pwRes.data?.status;

                if (gatewayStatus) {
                    const updatedTrx = await processQrisV1Settlement(orderId, gatewayStatus);
                    if (updatedTrx) trx = updatedTrx;
                }
            } catch (pwErr) {
                console.warn(`⚠️ Gagal cek status Paywuz untuk ${orderId}:`, pwErr.response?.data?.message || pwErr.message);
            }
        }

        // Cek kedaluwarsa lokal jika masih pending melewati expiredAt
        if (String(trx.status || '').toLowerCase() === 'pending' && trx.expiredAt && new Date() > new Date(trx.expiredAt)) {
            trx = await TransactionV2.findOneAndUpdate(
                { orderId, status: 'pending' },
                { $set: { status: 'expired', updatedAt: new Date() } },
                { returnDocument: 'after' }
            ).lean() || trx;
        }

        return res.json({
            status: true,
            data: {
                ...trx,
                depositAmount: trx.itemDetails?.harga || trx.amount,
                payment: {
                    qrString: trx.paymentNumber || ''
                }
            }
        });
    } catch (error) {
        console.error('❌ Error GET /transactions/:orderId:', error.message);
        return res.status(500).json({ status: false, message: 'Gagal memeriksa status transaksi.' });
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

app.post(['/webhook', '/api/webhook/paywuz'], async (req, res) => {
    try {
        const signature = req.headers['x-paywuz-signature'] || req.headers['x-signature'];
        if (signature && PAYWUZ_API_KEY) {
            const isValid = verifyPaywuzSignature(req.rawBody, signature, PAYWUZ_API_KEY);
            if (!isValid) {
                console.warn('⚠️ Signature Webhook Paywuz tidak valid!');
                return res.status(401).json({ status: false, message: 'Invalid webhook signature' });
            }
        }

        const payload = req.body?.data || req.body || {};
        const orderId = String(payload.orderId || payload.order_id || payload.referenceId || '').trim();
        const rawStatus = payload.status || payload.transaction_status || req.body?.status || req.body?.event;

        if (!orderId) {
            return res.status(400).json({ status: false, message: 'orderId tidak ditemukan pada payload webhook.' });
        }

        console.log(`📩 [WEBHOOK PAYWUZ] Order: ${orderId} | Status: ${rawStatus}`);

        const resultTrx = await processQrisV1Settlement(orderId, rawStatus);
        if (!resultTrx) {
            return res.status(404).json({ status: false, message: 'Transaksi tidak ditemukan di database.' });
        }

        return res.json({
            status: true,
            message: 'Webhook berhasil diproses',
            orderId: resultTrx.orderId,
            transactionStatus: resultTrx.status
        });
    } catch (error) {
        console.error('❌ Error Webhook Paywuz:', error.message);
        return res.status(500).json({ status: false, message: 'Internal server error saat memproses webhook.' });
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

// --- 8F. DEPOSIT QRIS V2 (DINAMIS MANUAL, BUKTI BAYAR & APPROVAL ADMIN) ---

app.post('/api/deposit-qrisv2', checkAuthSession, async (req, res) => {
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
        const customerEmail = (activeUser?.email || req.user.email).toLowerCase().trim();

        // Aturan Fee QRIS V2: >= 150.000 -> 0.95% flat | < 150.000 -> 0.7% + Rp 250
        const feeAmount = calculateDepositFee(amount, 'v2');
        const totalPayAmount = amount + feeAmount;

        const orderId = `QRV2-${Date.now()}-${Math.floor(1000 + Math.random() * 9000)}`;
        const dynamicQrisString = generateDynamicQris(STATIC_QRIS_V2_BASE, totalPayAmount);
        const expiredAt = new Date(Date.now() + 30 * 60 * 1000); // Berlaku 30 menit

        const newTrx = new TransactionV2({
            orderId,
            amount: totalPayAmount,
            paymentNumber: dynamicQrisString,
            paymentMethod: "QRIS V2",
            qrisVersion: "v2",
            type: "DEPOSIT",
            userEmail: customerEmail,
            status: "pending",
            itemDetails: {
                nama: `Deposit QRISv2 Rp ${amount.toLocaleString('id-ID')}`,
                harga: amount,
                fee: feeAmount,
                buyer: customerEmail,
                phone: customerPhone
            },
            expiredAt
        });

        await newTrx.save();

        return res.json({
            status: true,
            data: {
                ...newTrx.toObject(),
                depositAmount: amount,
                feeAmount: feeAmount,
                payment: {
                    qrString: dynamicQrisString
                }
            }
        });
    } catch (error) {
        console.error("Error Create Deposit QRISv2:", error);
        return res.status(500).json({
            status: false,
            message: error.message || "Gagal membuat pembayaran QRISv2."
        });
    }
});

app.post('/api/deposit-qrisv2/:orderId/upload-proof', checkAuthSession, (req, res) => {
    uploadPaymentProofMulter.single('proofImage')(req, res, async (err) => {
        if (err) {
            if (err.code === 'LIMIT_FILE_SIZE') {
                return res.status(400).json({ status: false, message: 'Ukuran foto bukti maksimal 5MB!' });
            }
            return res.status(400).json({ status: false, message: err.message || 'Gagal mengunggah bukti pembayaran.' });
        }

        try {
            if (!req.user) {
                return res.status(401).json({ status: false, message: 'Silakan login terlebih dahulu!' });
            }

            const { orderId } = req.params;
            if (!req.file) {
                return res.status(400).json({ status: false, message: 'Silakan pilih foto bukti pembayaran terlebih dahulu!' });
            }

            const trx = await TransactionV2.findOne({ orderId });
            if (!trx) {
                return res.status(404).json({ status: false, message: 'Transaksi deposit tidak ditemukan!' });
            }

            const userEmail = (req.user.email || '').toLowerCase().trim();
            if (trx.userEmail && trx.userEmail.toLowerCase().trim() !== userEmail) {
                return res.status(403).json({ status: false, message: 'Akses ditolak untuk transaksi ini.' });
            }

            if (['success', 'settlement', 'paid', 'settled'].includes(trx.status.toLowerCase())) {
                return res.status(400).json({ status: false, message: 'Deposit ini sudah dikonfirmasi!' });
            }

            if (trx.status.toLowerCase() === 'cancelled') {
                return res.status(400).json({ status: false, message: 'Transaksi ini sudah dibatalkan.' });
            }

            const mimeType = req.file.mimetype || mime.lookup(req.file.originalname) || 'image/jpeg';
            const base64 = req.file.buffer.toString('base64');
            const proofDataUrl = `data:${mimeType};base64,${base64}`;

            trx.proofImage = proofDataUrl;
            trx.proofUploadedAt = new Date();
            trx.status = 'waiting_verification';
            trx.updatedAt = new Date();
            await trx.save();
            await deleteCache(`trx_${orderId}`);

            const activeUser = await UserV2.findById(req.user.id || req.user._id).lean();
            const username = activeUser?.username || req.user.username || userEmail.split('@')[0];

            // Kirim notifikasi foto + tombol inline ke Telegram Admin
            await sendTelegramDepositProof(trx, username, req.file.buffer, mimeType);

            return res.json({
                status: true,
                message: 'Bukti pembayaran berhasil dikirim! Admin akan segera memverifikasi.',
                data: {
                    orderId: trx.orderId,
                    status: trx.status
                }
            });
        } catch (error) {
            console.error("Error upload proof QRISv2:", error);
            return res.status(500).json({ status: false, message: 'Terjadi kesalahan server saat mengirim bukti pembayaran.' });
        }
    });
});

app.delete('/api/deposit-qrisv2/:orderId/proof', checkAuthSession, async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({ status: false, message: 'Silakan login terlebih dahulu!' });
        }

        const { orderId } = req.params;
        const trx = await TransactionV2.findOne({ orderId });
        if (!trx) {
            return res.status(404).json({ status: false, message: 'Transaksi deposit tidak ditemukan!' });
        }

        const userEmail = (req.user.email || '').toLowerCase().trim();
        if (trx.userEmail && trx.userEmail.toLowerCase().trim() !== userEmail) {
            return res.status(403).json({ status: false, message: 'Akses ditolak untuk transaksi ini.' });
        }

        const currentStatus = (trx.status || '').toLowerCase();
        if (['success', 'settlement', 'paid', 'settled'].includes(currentStatus)) {
            return res.status(400).json({ status: false, message: 'Deposit sudah dikonfirmasi, bukti tidak dapat dihapus.' });
        }
        if (currentStatus === 'cancelled') {
            return res.status(400).json({ status: false, message: 'Transaksi sudah dibatalkan.' });
        }

        trx.proofImage = null;
        trx.proofUploadedAt = null;
        trx.status = 'pending';
        trx.updatedAt = new Date();
        await trx.save();
        await deleteCache(`trx_${orderId}`);

        return res.json({
            status: true,
            message: 'Bukti pembayaran berhasil dihapus. Silakan unggah ulang bukti yang benar.',
            data: { orderId: trx.orderId, status: trx.status }
        });
    } catch (error) {
        console.error('Error hapus bukti QRISv2:', error);
        return res.status(500).json({ status: false, message: 'Gagal menghapus bukti pembayaran.' });
    }
});

app.post('/api/deposit-qrisv2/:orderId/cancel', checkAuthSession, async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({ status: false, message: 'Silakan login terlebih dahulu!' });
        }

        const { orderId } = req.params;
        const trx = await TransactionV2.findOne({ orderId });
        if (!trx) {
            return res.status(404).json({ status: false, message: 'Transaksi tidak ditemukan.' });
        }

        const userEmail = (req.user.email || '').toLowerCase().trim();
        if (trx.userEmail && trx.userEmail.toLowerCase().trim() !== userEmail) {
            return res.status(403).json({ status: false, message: 'Akses ditolak.' });
        }

        const result = await cancelDepositQrisV2(orderId, 'User');
        if (!result.ok) {
            return res.status(400).json({ status: false, message: result.message });
        }

        // Info pembatalan ke Telegram jika bukti sudah sempat dikirim
        if (TELEGRAM_BOT_TOKEN && TELEGRAM_ADMIN_CHAT_ID) {
            axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
                chat_id: TELEGRAM_ADMIN_CHAT_ID,
                text: `🚫 <b>DEPOSIT DIBATALKAN USER</b>\nOrder ID: <code>${orderId}</code>\nEmail: <code>${userEmail}</code>`,
                parse_mode: 'HTML'
            }).catch(() => {});
        }

        return res.json({ status: true, message: result.message });
    } catch (error) {
        return res.status(500).json({ status: false, message: 'Gagal membatalkan transaksi.' });
    }
});

app.get('/api/admin/deposits-qrisv2', checkAuthSession, checkAdminRole, async (req, res) => {
    try {
        const deposits = await TransactionV2.find({
            type: 'DEPOSIT',
            $or: [{ qrisVersion: 'v2' }, { paymentMethod: 'QRIS V2' }]
        }).sort({ createdAt: -1 }).lean();

        const emails = [...new Set(deposits.map(d => d.userEmail).filter(Boolean))];
        const users = await UserV2.find({ email: { $in: emails } }).select('email username avatar').lean();
        const userMap = {};
        users.forEach(u => {
            userMap[u.email.toLowerCase().trim()] = u;
        });

        const enriched = deposits.map(d => {
            const u = userMap[(d.userEmail || '').toLowerCase().trim()];
            return {
                ...d,
                username: u?.username || (d.userEmail ? d.userEmail.split('@')[0] : 'User'),
                userAvatar: u?.avatar || null
            };
        });

        return res.json({ status: true, deposits: enriched });
    } catch (error) {
        return res.status(500).json({ status: false, message: 'Gagal memuat daftar deposit QRISv2.' });
    }
});

app.post('/api/admin/deposits-qrisv2/:orderId/approve', checkAuthSession, checkAdminRole, async (req, res) => {
    try {
        const { orderId } = req.params;
        const result = await approveDepositQrisV2(orderId, 'Web Admin');
        if (!result.ok) {
            return res.status(400).json({ status: false, message: result.message });
        }

        if (TELEGRAM_BOT_TOKEN && TELEGRAM_ADMIN_CHAT_ID) {
            axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
                chat_id: TELEGRAM_ADMIN_CHAT_ID,
                text: `✅ <b>DEPOSIT DIKONFIRMASI VIA WEB ADMIN</b>\nOrder ID: <code>${orderId}</code>\nNominal: <b>Rp ${result.trx.amount.toLocaleString('id-ID')}</b>`,
                parse_mode: 'HTML'
            }).catch(() => {});
        }

        return res.json({ status: true, message: result.message });
    } catch (error) {
        return res.status(500).json({ status: false, message: 'Gagal mengonfirmasi deposit.' });
    }
});

app.post('/api/admin/deposits-qrisv2/:orderId/cancel', checkAuthSession, checkAdminRole, async (req, res) => {
    try {
        const { orderId } = req.params;
        const result = await cancelDepositQrisV2(orderId, 'Admin Web');
        if (!result.ok) {
            return res.status(400).json({ status: false, message: result.message });
        }

        if (TELEGRAM_BOT_TOKEN && TELEGRAM_ADMIN_CHAT_ID) {
            axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
                chat_id: TELEGRAM_ADMIN_CHAT_ID,
                text: `❌ <b>DEPOSIT DIBATALKAN VIA WEB ADMIN</b>\nOrder ID: <code>${orderId}</code>`,
                parse_mode: 'HTML'
            }).catch(() => {});
        }

        return res.json({ status: true, message: result.message });
    } catch (error) {
        return res.status(500).json({ status: false, message: 'Gagal membatalkan deposit.' });
    }
});

// --- 8G. TELEGRAM OIDC LOGIN, LINK TICKET & BOT WEBHOOK ---

app.get('/auth/telegram', (req, res) => {
    if (!TELEGRAM_CLIENT_ID || !TELEGRAM_CLIENT_SECRET) {
        return res.status(503).send('Telegram Login belum dikonfigurasi. Atur TELEGRAM_CLIENT_ID dan TELEGRAM_CLIENT_SECRET.');
    }

    const returnTo = sanitizeReturnTo(req.query.returnTo, '');
    if (returnTo) {
        res.cookie('oauth_return_to', returnTo, {
            maxAge: 10 * 60 * 1000,
            httpOnly: true,
            secure: true,
            sameSite: 'lax'
        });
    }

    const state = crypto.randomBytes(32).toString('hex');
    const nonce = crypto.randomBytes(32).toString('hex');
    const verifier = crypto.randomBytes(48).toString('base64url');
    const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
    const cookieOptions = { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 10 * 60 * 1000, path: '/auth/telegram' };
    res.cookie('tg_oidc_state', state, cookieOptions);
    res.cookie('tg_oidc_nonce', nonce, cookieOptions);
    res.cookie('tg_oidc_verifier', verifier, cookieOptions);
    const callback = `${BASE_URL}/auth/telegram/callback`;
    const params = new URLSearchParams({
        client_id: TELEGRAM_CLIENT_ID,
        redirect_uri: callback,
        response_type: 'code',
        scope: 'openid profile',
        state,
        nonce,
        code_challenge: challenge,
        code_challenge_method: 'S256'
    });
    return res.redirect(`https://oauth.telegram.org/auth?${params.toString()}`);
});

app.get('/auth/telegram/callback', async (req, res) => {
    const clearOptions = { httpOnly: true, secure: true, sameSite: 'lax', path: '/auth/telegram' };
    const state = String(req.query.state || '');
    const savedState = req.cookies?.tg_oidc_state || '';
    const nonce = req.cookies?.tg_oidc_nonce || '';
    const verifier = req.cookies?.tg_oidc_verifier || '';
    const refCodeFromCookie = req.cookies?.pending_ref || null;
    const returnTo = sanitizeReturnTo(req.cookies?.oauth_return_to, '');
    res.clearCookie('tg_oidc_state', clearOptions);
    res.clearCookie('tg_oidc_nonce', clearOptions);
    res.clearCookie('tg_oidc_verifier', clearOptions);
    res.clearCookie('oauth_return_to');
    try {
        if (!TELEGRAM_CLIENT_ID || !TELEGRAM_CLIENT_SECRET) throw new Error('Telegram Login belum dikonfigurasi.');
        if (!state || !savedState || !crypto.timingSafeEqual(Buffer.from(state), Buffer.from(savedState)) || !nonce || !verifier) {
            throw new Error('Verifikasi keamanan Telegram tidak valid. Silakan coba login kembali.');
        }
        if (req.query.error) throw new Error(String(req.query.error_description || req.query.error));
        const code = String(req.query.code || '');
        if (!code) throw new Error('Kode autentikasi Telegram tidak ditemukan.');

        const tokenBody = new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            redirect_uri: `${BASE_URL}/auth/telegram/callback`,
            client_id: TELEGRAM_CLIENT_ID,
            code_verifier: verifier
        });
        const tokenResponse = await axios.post('https://oauth.telegram.org/token', tokenBody.toString(), {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            auth: { username: TELEGRAM_CLIENT_ID, password: TELEGRAM_CLIENT_SECRET },
            timeout: 15000
        });
        const idToken = tokenResponse.data?.id_token;
        if (!idToken) throw new Error('Telegram tidak mengembalikan ID token.');

        const decoded = jwt.decode(idToken, { complete: true });
        const kid = decoded?.header?.kid;
        if (!kid || decoded.header.alg !== 'RS256') throw new Error('Format token Telegram tidak didukung. Pastikan algoritma login Telegram menggunakan RS256.');
        const jwksResponse = await axios.get('https://oauth.telegram.org/.well-known/jwks.json', { timeout: 10000 });
        const jwk = (jwksResponse.data?.keys || []).find(key => key.kid === kid);
        if (!jwk) throw new Error('Kunci verifikasi Telegram tidak ditemukan.');
        const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
        const claims = jwt.verify(idToken, publicKey, {
            algorithms: ['RS256'],
            issuer: 'https://oauth.telegram.org',
            audience: String(TELEGRAM_CLIENT_ID)
        });
        if (claims.nonce !== nonce) throw new Error('Nonce Telegram tidak cocok. Silakan ulangi login.');

        const telegramId = String(claims.id || claims.sub || '');
        if (!telegramId) throw new Error('ID akun Telegram tidak tersedia.');
        let user = await UserV2.findOne({ $or: [
            { provider: 'telegram', providerId: telegramId },
            { telegramChatId: telegramId }
        ] });
        let isFirstTimeLogin = false;

        if (!user) {
            isFirstTimeLogin = true;
            let initialSaldo = 0;
            let inviterUser = null;

            if (refCodeFromCookie) {
                inviterUser = await UserV2.findOne({ referralCode: String(refCodeFromCookie).trim().toUpperCase() });
                if (inviterUser) {
                    initialSaldo = 500;
                    inviterUser.saldo = (inviterUser.saldo || 0) + 1000;
                    await inviterUser.save();
                }
            }

            const displayName = String(claims.name || claims.preferred_username || `telegram_${telegramId}`).trim();
            const base = String(claims.preferred_username || `telegram_${telegramId}`).toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 24) || `telegram_${telegramId}`;
            let username = base;
            let suffix = 1;
            while (await UserV2.exists({ username })) username = `${base}${suffix++}`;
            user = await UserV2.create({
                username: username || displayName,
                email: `tg_${telegramId}@telegram.user`,
                provider: 'telegram',
                providerId: telegramId,
                telegramChatId: telegramId,
                telegramUsername: claims.preferred_username || null,
                telegramLinkedAt: new Date(),
                telegramNotifEnabled: true,
                avatar: claims.picture || undefined,
                saldo: initialSaldo,
                referralCode: generateReferralCode(),
                referredBy: inviterUser ? inviterUser.referralCode : null,
                hasCompletedOnboarding: false
            });
        } else {
            let dirty = false;
            if (!user.hasCompletedOnboarding) {
                isFirstTimeLogin = true;
            }
            if (!user.telegramChatId) {
                user.telegramChatId = telegramId;
                user.telegramLinkedAt = new Date();
                dirty = true;
            }
            if (dirty) await user.save();
        }

        res.clearCookie('pending_ref');

        const payload = {
            id: user._id, username: user.username, email: user.email,
            name: user.username, avatar: user.avatar, createdAt: user.createdAt
        };
        const authToken = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
        res.cookie('auth_session', authToken, {
            maxAge: 7 * 24 * 60 * 60 * 1000, httpOnly: true,
            secure: true, sameSite: 'lax'
        });

        if (returnTo) return res.redirect(returnTo);
        return res.redirect(isFirstTimeLogin ? '/store?onboarding=1' : '/dashboard');
    } catch (err) {
        console.error('Telegram OIDC login error:', err.response?.data || err.message);
        return res.redirect(returnTo || '/login?error=telegram_login_failed');
    }
});

// Tiket sekali pakai ini HANYA untuk menautkan bot dari halaman profil.
app.post('/api/telegram/ticket', async (req, res) => {
    try {
        if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_BOT_USERNAME) {
            return res.status(503).json({ status: false, message: 'Bot Telegram belum dikonfigurasi.' });
        }
        if (!req.user?.id && !req.user?._id) return res.status(401).json({ status: false, message: 'Silakan login terlebih dahulu.' });
        const userId = req.user.id || req.user._id;
        const rawToken = crypto.randomBytes(24).toString('hex');
        const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
        await TelegramTicket.create({ tokenHash, type: 'link', userId });
        return res.json({ status: true, botUrl: `https://t.me/${TELEGRAM_BOT_USERNAME}?start=link_${rawToken}`, token: rawToken });
    } catch (err) {
        console.error('Telegram link ticket error:', err.message);
        return res.status(500).json({ status: false, message: 'Gagal membuat tautan Telegram.' });
    }
});

app.get('/api/telegram/ticket/:token', async (req, res) => {
    try {
        const tokenHash = crypto.createHash('sha256').update(String(req.params.token || '')).digest('hex');
        const ticket = await TelegramTicket.findOne({ tokenHash, type: 'link' }).lean();
        if (!ticket) return res.status(404).json({ status: false, message: 'Tautan kedaluwarsa. Silakan buat ulang.' });
        return res.json({ status: true, completed: ticket.completed, type: ticket.type });
    } catch {
        return res.status(500).json({ status: false, message: 'Gagal memeriksa status Telegram.' });
    }
});

app.post('/api/user/unlink-telegram', checkAuthSession, async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({ status: false, message: 'Silakan login terlebih dahulu.' });
        }

        await connectDB();
        const userId = req.user.id || req.user._id;
        await UserV2.findByIdAndUpdate(userId, {
            $set: {
                telegramChatId: null,
                telegramUsername: null,
                telegramNotifEnabled: false
            }
        });

        return res.json({ status: true, message: 'Tautan Telegram berhasil diputuskan.' });
    } catch (err) {
        return res.status(500).json({ status: false, message: 'Gagal memutuskan tautan Telegram.' });
    }
});

app.get('/api/telegram/setup-webhook', async (req, res) => {
    try {
        const webhookUrl = `${BASE_URL}/api/telegram/webhook`;
        const r = await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/setWebhook`, {
            url: webhookUrl,
            allowed_updates: ['message', 'callback_query']
        });
        telegramWebhookRegistered = true;
        return res.json({ status: true, webhookUrl, telegram: r.data });
    } catch (err) {
        return res.status(500).json({ status: false, message: err.message });
    }
});

app.post('/api/telegram/webhook', async (req, res) => {
    try {
        await connectDB();
        const update = req.body;

        // 1. HANDLER PRIVATE CHAT BOT UNTUK USER (PERINTAH /START & INFO STATUS TAUTAN)
        if (update && update.message && update.message.chat && update.message.chat.type === 'private') {
            const userChatId = String(update.message.chat.id);
            const firstName = update.message.from?.first_name || 'Kak';
            const textMsg = (update.message.text || '').trim();

            if (TELEGRAM_BOT_TOKEN && textMsg.startsWith('/start')) {
                const startPayload = textMsg.split(/\s+/)[1] || '';
                const ticketMatch = startPayload.match(/^(link)_([a-f0-9]{48})$/i);
                if (ticketMatch) {
                    const [, ticketType, rawToken] = ticketMatch;
                    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
                    const ticket = await TelegramTicket.findOne({ tokenHash, type: ticketType.toLowerCase(), completed: false });
                    if (ticket) {
                        const targetUser = await UserV2.findById(ticket.userId);
                        if (targetUser) {
                            const conflicting = await UserV2.findOne({ telegramChatId: userChatId, _id: { $ne: targetUser._id } });
                            if (!conflicting) {
                                targetUser.telegramChatId = userChatId;
                                targetUser.telegramUsername = update.message.from?.username || null;
                                targetUser.telegramLinkedAt = new Date();
                                await targetUser.save();
                                ticket.chatId = userChatId;
                                ticket.telegramUsername = update.message.from?.username || null;
                                ticket.completed = true;
                                await ticket.save();
                                await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
                                    chat_id: userChatId, text: '✅ Akun ArulzXD Store berhasil ditautkan. Notifikasi akun akan dikirim ke chat ini.'
                                }).catch(() => {});
                            } else {
                                await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
                                    chat_id: userChatId, text: '⚠️ Telegram ini sudah tertaut ke akun lain.'
                                }).catch(() => {});
                            }
                        }
                        return res.sendStatus(200);
                    }
                }
                const linkedUser = await UserV2.findOne({ telegramChatId: userChatId }).select('username email').lean();

                const replyText = linkedUser
                    ? `👋 <b>Halo, ${firstName}!</b>\n\n✅ Akun Telegram Anda sudah terhubung dengan akun ArulzXD Store:\n• <b>Username:</b> ${linkedUser.username}\n• <b>Email:</b> ${linkedUser.email}\n\nSemua notifikasi promo, informasi sistem, dan update terbaru akan dikirim langsung ke chat ini.`
                    : `👋 <b>Selamat datang di Bot Notifikasi ArulzXD Store, ${firstName}!</b>\n\nBot ini siap mengirimkan notifikasi instan langsung ke private chat Anda.\n\n🔗 <b>Cara Menautkan Akun:</b>\n1. Buka <a href="${BASE_URL}/profile">${BASE_URL}/profile</a>\n2. Gulir ke bagian <b>Notifikasi Telegram Bot</b>\n3. Klik tombol Tautkan Bot Telegram untuk menghubungkan akun Anda.`;

                await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
                    chat_id: userChatId,
                    text: replyText,
                    parse_mode: 'HTML',
                    disable_web_page_preview: true
                }).catch((e) => console.error('Gagal balas /start user:', e.response?.data || e.message));
            }

            return res.sendStatus(200);
        }

        // 2. HANDLER CALLBACK QUERY ADMIN (KONFIRMASI / BATALKAN DEPOSIT QRIS V2)
        if (update && update.callback_query) {
            const cq = update.callback_query;
            const data = cq.data || '';
            const chatId = cq.message?.chat?.id;
            const messageId = cq.message?.message_id;

            // Validasi hanya channel/grup admin yang berhak klik
            if (String(chatId) !== String(TELEGRAM_ADMIN_CHAT_ID)) {
                await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/answerCallbackQuery`, {
                    callback_query_id: cq.id,
                    text: 'Akses ditolak! Hanya Admin.',
                    show_alert: true
                }).catch(() => {});
                return res.sendStatus(200);
            }

            if (data.startsWith('dep_approve_')) {
                const orderId = data.replace('dep_approve_', '').trim();
                const result = await approveDepositQrisV2(orderId, 'Telegram Admin');

                await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/answerCallbackQuery`, {
                    callback_query_id: cq.id,
                    text: result.message.slice(0, 190),
                    show_alert: true
                }).catch(() => {});

                if (result.ok && messageId) {
                    const waktuWib = moment().tz('Asia/Jakarta').format('HH:mm:ss');
                    const baseCaption = (cq.message.caption || '').replace(/\n\n(✅|❌).*$/s, '');
                    const newCaption = `${baseCaption}\n\n✅ <b>DIKONFIRMASI OLEH ADMIN</b> (${waktuWib} WIB)`;

                    await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/editMessageCaption`, {
                        chat_id: chatId,
                        message_id: messageId,
                        caption: newCaption,
                        parse_mode: 'HTML',
                        reply_markup: { inline_keyboard: [] }
                    }).catch((e) => console.error('Edit caption gagal:', e.response?.data || e.message));
                }
            } else if (data.startsWith('dep_cancel_')) {
                const orderId = data.replace('dep_cancel_', '').trim();
                const result = await cancelDepositQrisV2(orderId, 'Telegram Admin');

                await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/answerCallbackQuery`, {
                    callback_query_id: cq.id,
                    text: result.message.slice(0, 190),
                    show_alert: true
                }).catch(() => {});

                if (result.ok && messageId) {
                    const waktuWib = moment().tz('Asia/Jakarta').format('HH:mm:ss');
                    const baseCaption = (cq.message.caption || '').replace(/\n\n(✅|❌).*$/s, '');
                    const newCaption = `${baseCaption}\n\n❌ <b>DIBATALKAN OLEH ADMIN</b> (${waktuWib} WIB)`;

                    await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/editMessageCaption`, {
                        chat_id: chatId,
                        message_id: messageId,
                        caption: newCaption,
                        parse_mode: 'HTML',
                        reply_markup: { inline_keyboard: [] }
                    }).catch((e) => console.error('Edit caption gagal:', e.response?.data || e.message));
                }
            }
        }

        return res.sendStatus(200);
    } catch (error) {
        console.error('Telegram Webhook Error:', error.message);
        return res.sendStatus(200);
    }
});

// ============================================================
// 9. AUTHENTICATION (PASSPORT, OTP, LOGIN, REGISTER, OAUTH)
// ============================================================

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// KONFIGURASI PASSPORT LOCAL STRATEGY (LOGIN MENGGUNAKAN EMAIL & PASSWORD)
passport.use(new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
}, async (email, password, done) => {
    try {
        const cleanEmail = email.toLowerCase().trim();
        const user = await UserV2.findOne({ email: cleanEmail });

        if (!user) {
            return done(null, false, { message: 'Email tidak terdaftar!' });
        }

        if (!user.password) {
            return done(null, false, { message: 'Akun ini terdaftar menggunakan Google/GitHub. Silakan login lewat sosial media.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return done(null, false, { message: 'Password salah!' });
        }

        return done(null, user);
    } catch (err) {
        return done(err);
    }
}));

// --- 9A. ENDPOINT KIRIM OTP (LOGIN, REGISTER, LUPA PASSWORD) ---

// ENDPOINT KIRIM KODE VERIFIKASI LOGIN
app.post('/api/auth/send-login-code', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email || !email.trim()) {
            return res.status(400).json({ status: false, message: 'Email wajib diisi!' });
        }

        const cleanEmail = email.toLowerCase().trim();
        const user = await UserV2.findOne({ email: cleanEmail });

        if (!user) {
            return res.status(404).json({ status: false, message: 'Email tidak terdaftar! Silakan daftar akun baru terlebih dahulu.' });
        }

        // Cek batas maksimal pengiriman email harian (5x per hari)
        const allowed = await checkAndIncrementEmailLimit(cleanEmail);
        if (!allowed) {
            return res.status(429).json({
                status: false,
                message: 'Batas pengiriman kode verifikasi harian Anda (maksimal 5x sehari) telah habis! Coba lagi besok.'
            });
        }

        // Generate 6 digit kode angka acak
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 Menit

        // Hapus kode lama jika ada
        await VerificationCode.deleteMany({ email: cleanEmail, type: 'login' });

        await VerificationCode.create({
            email: cleanEmail,
            code: otpCode,
            type: 'login',
            expiresAt
        });

        await sendEmailOTP(cleanEmail, otpCode, 'Login Akun');

        return res.json({ status: true, message: 'Kode verifikasi 6 digit telah dikirim ke email Anda!' });
    } catch (err) {
        console.error('Error send login code:', err);
        return res.status(500).json({ status: false, message: 'Gagal mengirim email verifikasi. Pastikan email benar!' });
    }
});

// ENDPOINT VERIFIKASI KODE LOGIN & BUAT SESI AKUN
app.post('/api/auth/verify-login-code', async (req, res) => {
    try {
        const { email, code } = req.body;
        if (!email || !code) {
            return res.status(400).json({ status: false, message: 'Email dan kode wajib diisi!' });
        }

        const cleanEmail = email.toLowerCase().trim();
        const verification = await VerificationCode.findOne({
            email: cleanEmail,
            code: code.trim(),
            type: 'login',
            expiresAt: { $gt: new Date() }
        });

        if (!verification) {
            return res.status(400).json({ status: false, message: 'Kode verifikasi salah atau sudah kedaluwarsa!' });
        }

        const user = await UserV2.findOne({ email: cleanEmail });
        if (!user) {
            return res.status(404).json({ status: false, message: 'Akun tidak ditemukan!' });
        }

        // Hapus kode verifikasi setelah berhasil dipakai
        await VerificationCode.deleteOne({ _id: verification._id });

        const userPayload = {
            id: user._id,
            username: user.username,
            email: user.email,
            name: user.username,
            avatar: user.avatar,
            createdAt: user.createdAt
        };

        const token = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '7d' });

        res.cookie('auth_session', token, {
            maxAge: 7 * 24 * 60 * 60 * 1000,
            httpOnly: true,
            secure: true,
            sameSite: 'lax'
        });

        const redirectUrl = !user.hasCompletedOnboarding ? '/store?onboarding=1' : '/dashboard';
        return res.json({ status: true, message: 'Login berhasil!', redirectUrl });
    } catch (err) {
        console.error('Error verify login code:', err);
        return res.status(500).json({ status: false, message: 'Gagal memverifikasi kode!' });
    }
});

// ENDPOINT KIRIM KODE VERIFIKASI REGISTER
app.post('/api/auth/send-register-code', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        if (!username || !email || !password) {
            return res.status(400).json({ status: false, message: 'Username, Email, dan Password wajib diisi!' });
        }

        const cleanEmail = email.toLowerCase().trim();
        const existingUser = await UserV2.findOne({ email: cleanEmail });

        if (existingUser) {
            return res.status(400).json({ status: false, message: 'Email ini sudah terdaftar! Silakan gunakan halaman Login.' });
        }

        // Cek batas maksimal 5 kali sehari
        const allowed = await checkAndIncrementEmailLimit(cleanEmail);
        if (!allowed) {
            return res.status(429).json({
                status: false,
                message: 'Batas pengiriman kode verifikasi harian Anda (maksimal 5x sehari) telah habis! Coba lagi besok.'
            });
        }

        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

        await VerificationCode.deleteMany({ email: cleanEmail, type: 'register' });

        await VerificationCode.create({
            email: cleanEmail,
            code: otpCode,
            type: 'register',
            expiresAt
        });

        await sendEmailOTP(cleanEmail, otpCode, 'Pendaftaran Akun');

        return res.json({ status: true, message: 'Kode verifikasi pendaftaran telah dikirim ke email Anda!' });
    } catch (err) {
        console.error('Error send register code:', err);
        return res.status(500).json({ status: false, message: 'Gagal mengirim kode verifikasi ke email!' });
    }
});

// ENDPOINT VERIFIKASI KODE REGISTER & BUAT AKUN BARU
app.post('/api/auth/verify-register-code', async (req, res) => {
    try {
        const { username, email, password, code, referral } = req.body;
        if (!username || !email || !password || !code) {
            return res.status(400).json({ status: false, message: 'Semua field & kode wajib diisi!' });
        }

        const cleanEmail = email.toLowerCase().trim();
        const verification = await VerificationCode.findOne({
            email: cleanEmail,
            code: code.trim(),
            type: 'register',
            expiresAt: { $gt: new Date() }
        });

        if (!verification) {
            return res.status(400).json({ status: false, message: 'Kode verifikasi salah atau sudah kedaluwarsa!' });
        }

        const existingUser = await UserV2.findOne({ email: cleanEmail });
        if (existingUser) {
            return res.status(400).json({ status: false, message: 'Email sudah terdaftar!' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        let initialSaldo = 0;
        let inviterUser = null;
        if (referral && referral.trim() !== '') {
            inviterUser = await UserV2.findOne({ referralCode: referral.trim().toUpperCase() });
            if (inviterUser) {
                initialSaldo = 500;
                inviterUser.saldo = (inviterUser.saldo || 0) + 1000;
                await inviterUser.save();
            }
        }

        const newUser = new UserV2({
            username: username.trim(),
            email: cleanEmail,
            password: hashedPassword,
            provider: 'local',
            saldo: initialSaldo,
            referralCode: generateReferralCode(),
            referredBy: inviterUser ? inviterUser.referralCode : null,
            hasCompletedOnboarding: false
        });

        await newUser.save();
        await VerificationCode.deleteOne({ _id: verification._id });

        const userPayload = {
            id: newUser._id,
            username: newUser.username,
            email: newUser.email,
            name: newUser.username,
            avatar: newUser.avatar,
            createdAt: newUser.createdAt
        };

        const token = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '7d' });

        res.cookie('auth_session', token, {
            maxAge: 7 * 24 * 60 * 60 * 1000,
            httpOnly: true,
            secure: true,
            sameSite: 'lax'
        });

        return res.json({ status: true, message: 'Registrasi berhasil! Selamat datang.', redirectUrl: '/store?onboarding=1' });
    } catch (err) {
        console.error('Error verify register code:', err);
        return res.status(500).json({ status: false, message: 'Terjadi kesalahan saat membuat akun!' });
    }
});

// ENDPOINT KIRIM KODE LUPA PASSWORD
app.post('/api/auth/send-forgot-code', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email || !email.trim()) {
            return res.status(400).json({ status: false, message: 'Email wajib diisi!' });
        }

        const cleanEmail = email.toLowerCase().trim();
        const user = await UserV2.findOne({ email: cleanEmail });

        if (!user) {
            return res.status(404).json({ status: false, message: 'Email tidak terdaftar di sistem kami!' });
        }

        // Cek batas maksimal 5x sehari
        const allowed = await checkAndIncrementEmailLimit(cleanEmail);
        if (!allowed) {
            return res.status(429).json({
                status: false,
                message: 'Batas pengiriman kode verifikasi harian Anda (maksimal 5x sehari) telah habis! Coba lagi besok.'
            });
        }

        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

        await VerificationCode.deleteMany({ email: cleanEmail, type: 'forgot' });

        await VerificationCode.create({
            email: cleanEmail,
            code: otpCode,
            type: 'forgot',
            expiresAt
        });

        await sendEmailOTP(cleanEmail, otpCode, 'Reset Password');

        return res.json({ status: true, message: 'Kode reset password telah dikirim ke email Anda!' });
    } catch (err) {
        console.error('Error send forgot code:', err);
        return res.status(500).json({ status: false, message: 'Gagal mengirim kode verifikasi ke email!' });
    }
});

// ENDPOINT VERIFIKASI KODE & SIMPAN PASSWORD BARU
app.post('/api/auth/reset-password-code', async (req, res) => {
    try {
        const { email, code, newPassword } = req.body;
        if (!email || !code || !newPassword) {
            return res.status(400).json({ status: false, message: 'Email, kode, dan password baru wajib diisi!' });
        }

        const cleanEmail = email.toLowerCase().trim();
        const verification = await VerificationCode.findOne({
            email: cleanEmail,
            code: code.trim(),
            type: 'forgot',
            expiresAt: { $gt: new Date() }
        });

        if (!verification) {
            return res.status(400).json({ status: false, message: 'Kode verifikasi salah atau sudah kedaluwarsa!' });
        }

        const user = await UserV2.findOne({ email: cleanEmail });
        if (!user) {
            return res.status(404).json({ status: false, message: 'User tidak ditemukan!' });
        }

        user.password = await bcrypt.hash(newPassword, 10);
        await user.save();

        await VerificationCode.deleteOne({ _id: verification._id });

        return res.json({ status: true, message: 'Password berhasil diperbarui! Silakan login dengan password baru Anda.' });
    } catch (err) {
        console.error('Error reset password code:', err);
        return res.status(500).json({ status: false, message: 'Gagal memperbarui password!' });
    }
});

// --- 9B. HALAMAN LOGIN, REGISTER, LOGOUT & OAUTH (GITHUB / GOOGLE) ---

app.get('/login', (req, res) => {
    if (req.user) {
        const returnTo = sanitizeReturnTo(req.query.returnTo, '/dashboard');
        return res.redirect(returnTo);
    }
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) {
            return sendSweetAlert(res, 'error', 'Error!', 'Terjadi kesalahan server.', '/login');
        }
        if (!user) {
            return sendSweetAlert(res, 'error', 'Login Gagal!', info ? info.message : 'Email atau Password salah!', '/login');
        }

        const userPayload = {
            id: user._id,
            username: user.username,
            email: user.email,
            name: user.username,
            avatar: user.avatar,
            createdAt: user.createdAt
        };

        const token = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '7d' });

        res.cookie('auth_session', token, {
            maxAge: 7 * 24 * 60 * 60 * 1000,
            httpOnly: true,
            secure: true,
            sameSite: 'lax'
        });

        return sendSweetAlert(res, 'success', 'Login Berhasil!', `Selamat datang kembali, ${user.username}!`, '/dashboard');
    })(req, res, next);
});

app.get('/register', (req, res) => {
    if (req.user) return res.redirect('/dashboard');

    if (req.query.ref) {
        res.cookie('pending_ref', req.query.ref.trim().toUpperCase(), {
            maxAge: 10 * 60 * 1000,
            httpOnly: true,
            secure: true,
            sameSite: 'lax'
        });
    }
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.post('/register', async (req, res) => {
    const { username, email, password, referral } = req.body;

    if (!username || !email || !password) {
        return sendSweetAlert(res, 'warning', 'Data Kurang!', 'Username, Email, dan Password wajib diisi!', '/register');
    }

    try {
        const cleanEmail = email.toLowerCase().trim();
        const existingUser = await UserV2.findOne({ email: cleanEmail });

        if (existingUser) {
            return sendSweetAlert(res, 'error', 'Gagal Daftar!', 'Email ini sudah terdaftar! Silakan gunakan halaman Login.', '/register');
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        let initialSaldo = 0;
        let inviterUser = null;

        if (referral && referral.trim() !== '') {
            inviterUser = await UserV2.findOne({ referralCode: referral.trim().toUpperCase() });
            if (inviterUser) {
                initialSaldo = 500;
                inviterUser.saldo = (inviterUser.saldo || 0) + 1000;
                await inviterUser.save();
            }
        }

        const newUser = new UserV2({
            username: username.trim(),
            email: cleanEmail,
            password: hashedPassword,
            provider: 'local',
            saldo: initialSaldo,
            referralCode: generateReferralCode(),
            referredBy: inviterUser ? inviterUser.referralCode : null
        });

        await newUser.save();

        const bonusMsg = inviterUser
            ? ' Selamat! Anda mendapatkan bonus saldo Rp 500 dari kode referral!'
            : '';

        return sendSweetAlert(res, 'success', 'Registrasi Berhasil!', `Akun berhasil dibuat!${bonusMsg} Silakan login.`, '/login');
    } catch (error) {
        console.error(error);
        return sendSweetAlert(res, 'error', 'Error!', 'Terjadi kesalahan sistem saat mendaftar.', '/register');
    }
});

app.post('/api/user/complete-onboarding', checkAuthSession, async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({ status: false, message: 'Silakan login terlebih dahulu.' });
        }

        const userId = req.user.id || req.user._id;
        await UserV2.findByIdAndUpdate(userId, { $set: { hasCompletedOnboarding: true } });

        return res.json({ status: true, message: 'Onboarding berhasil diselesaikan!' });
    } catch (err) {
        return res.status(500).json({ status: false, message: 'Gagal menyimpan status onboarding.' });
    }
});

app.get('/logout', (req, res) => {
    res.clearCookie('auth_session');
    req.logout(() => {
        res.redirect('/dashboard');
    });
});

// GITHUB OAUTH
app.get('/auth/github', (req, res) => {
    const returnTo = sanitizeReturnTo(req.query.returnTo, '');
    if (returnTo) {
        res.cookie('oauth_return_to', returnTo, {
            maxAge: 10 * 60 * 1000,
            httpOnly: true,
            secure: true,
            sameSite: 'lax'
        });
    }

    const githubAuthUrl = `https://github.com/login/oauth/authorize?client_id=${GITHUB_CLIENT_ID}&redirect_uri=${encodeURIComponent(GITHUB_CALLBACK_URL)}&scope=user:email`;
    res.redirect(githubAuthUrl);
});

app.get('/auth/github/callback', async (req, res) => {
    const { code } = req.query;
    const returnTo = sanitizeReturnTo(req.cookies?.oauth_return_to, '');
    res.clearCookie('oauth_return_to');

    if (!code) return res.redirect('/login');

    try {
        const tokenResponse = await axios.post('https://github.com/login/oauth/access_token', {
            client_id: GITHUB_CLIENT_ID,
            client_secret: GITHUB_CLIENT_SECRET,
            code: code
        }, { headers: { Accept: 'application/json' } });

        const accessToken = tokenResponse.data.access_token;

        const userResponse = await axios.get('https://api.github.com/user', {
            headers: { Authorization: `Bearer ${accessToken}` }
        });

        let email = userResponse.data.email;
        if (!email) {
            const emailsRes = await axios.get('https://api.github.com/user/emails', {
                headers: { Authorization: `Bearer ${accessToken}` }
            });
            const primaryEmailObj = emailsRes.data.find(e => e.primary) || emailsRes.data[0];
            email = primaryEmailObj ? primaryEmailObj.email : `${userResponse.data.login}@github.user`;
        }

        const cleanEmail = email.toLowerCase().trim();
        let user = await UserV2.findOne({ email: cleanEmail });

        const refCodeFromCookie = req.cookies?.pending_ref || null;
        let isFirstTimeLogin = false;

        if (!user) {
            isFirstTimeLogin = true;
            let initialSaldo = 0;
            let inviterUser = null;

            if (refCodeFromCookie) {
                inviterUser = await UserV2.findOne({ referralCode: refCodeFromCookie.trim().toUpperCase() });
                if (inviterUser) {
                    initialSaldo = 500;
                    inviterUser.saldo = (inviterUser.saldo || 0) + 1000;
                    await inviterUser.save();
                }
            }

            user = new UserV2({
                username: userResponse.data.name || userResponse.data.login,
                email: cleanEmail,
                provider: 'github',
                providerId: userResponse.data.id.toString(),
                avatar: userResponse.data.avatar_url,
                saldo: initialSaldo,
                referralCode: generateReferralCode(),
                referredBy: inviterUser ? inviterUser.referralCode : null,
                hasCompletedOnboarding: false
            });
            await user.save();
        } else if (!user.hasCompletedOnboarding) {
            isFirstTimeLogin = true;
        }

        res.clearCookie('pending_ref');

        const userPayload = {
            id: user._id,
            username: user.username,
            email: user.email,
            name: user.username,
            avatar: user.avatar,
            createdAt: user.createdAt
        };

        const token = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '7d' });

        res.cookie('auth_session', token, {
            maxAge: 7 * 24 * 60 * 60 * 1000,
            httpOnly: true,
            secure: true,
            sameSite: 'lax'
        });

        if (returnTo) return res.redirect(returnTo);
        return res.redirect(isFirstTimeLogin ? '/store?onboarding=1' : '/dashboard');
    } catch (error) {
        console.error('GitHub OAuth Error:', error.message);
        res.redirect('/login');
    }
});

// GOOGLE OAUTH
app.get('/auth/google', (req, res) => {
    const returnTo = sanitizeReturnTo(req.query.returnTo, '');
    if (returnTo) {
        res.cookie('oauth_return_to', returnTo, {
            maxAge: 10 * 60 * 1000,
            httpOnly: true,
            secure: true,
            sameSite: 'lax'
        });
    }

    const googleAuthUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${GOOGLE_CLIENT_ID}&redirect_uri=${encodeURIComponent(GOOGLE_CALLBACK_URL)}&response_type=code&scope=profile email`;
    res.redirect(googleAuthUrl);
});

app.get('/auth/google/callback', async (req, res) => {
    const { code } = req.query;
    const returnTo = sanitizeReturnTo(req.cookies?.oauth_return_to, '');
    res.clearCookie('oauth_return_to');

    if (!code) return res.redirect('/login');

    try {
        const tokenResponse = await axios.post('https://oauth2.googleapis.com/token', {
            client_id: GOOGLE_CLIENT_ID,
            client_secret: GOOGLE_CLIENT_SECRET,
            code: code,
            grant_type: 'authorization_code',
            redirect_uri: GOOGLE_CALLBACK_URL
        });

        const accessToken = tokenResponse.data.access_token;

        const userResponse = await axios.get('https://www.googleapis.com/oauth2/v2/userinfo', {
            headers: { Authorization: `Bearer ${accessToken}` }
        });

        const cleanEmail = userResponse.data.email.toLowerCase().trim();
        let user = await UserV2.findOne({ email: cleanEmail });

        const refCodeFromCookie = req.cookies?.pending_ref || null;
        let isFirstTimeLogin = false;

        if (!user) {
            isFirstTimeLogin = true;
            let initialSaldo = 0;
            let inviterUser = null;

            if (refCodeFromCookie) {
                inviterUser = await UserV2.findOne({ referralCode: refCodeFromCookie.trim().toUpperCase() });
                if (inviterUser) {
                    initialSaldo = 500;
                    inviterUser.saldo = (inviterUser.saldo || 0) + 1000;
                    await inviterUser.save();
                }
            }

            user = new UserV2({
                username: userResponse.data.name,
                email: cleanEmail,
                provider: 'google',
                providerId: userResponse.data.id,
                avatar: userResponse.data.picture,
                saldo: initialSaldo,
                referralCode: generateReferralCode(),
                referredBy: inviterUser ? inviterUser.referralCode : null,
                hasCompletedOnboarding: false
            });
            await user.save();
        } else if (!user.hasCompletedOnboarding) {
            isFirstTimeLogin = true;
        }

        res.clearCookie('pending_ref');

        const userPayload = {
            id: user._id,
            username: user.username,
            email: user.email,
            name: user.username,
            avatar: user.avatar,
            createdAt: user.createdAt
        };

        const token = jwt.sign(userPayload, JWT_SECRET, { expiresIn: '7d' });

        res.cookie('auth_session', token, {
            maxAge: 7 * 24 * 60 * 60 * 1000,
            httpOnly: true,
            secure: true,
            sameSite: 'lax'
        });

        if (returnTo) return res.redirect(returnTo);
        return res.redirect(isFirstTimeLogin ? '/store?onboarding=1' : '/dashboard');
    } catch (error) {
        console.error('Google OAuth Error:', error.message);
        res.redirect('/login');
    }
});

// ============================================================
// 10. PAGES, OPEN GRAPH, PRODUK, NOTIFIKASI & DASHBOARD API
// ============================================================

// --- 10A. HALAMAN PUBLIK (HTML) ---

app.get(['/', '/dashboard'], (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/store', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'store.html'));
});

app.get('/riwayat', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'riwayat.html'));
});

app.get('/notifikasi', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'notifikasi.html'));
});

app.get('/privacy', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'privacy.html'));
});

app.get('/deposit', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'deposit.html'));
});

app.get('/profile', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

app.get('/bantuan', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'bantuan.html'));
});

// --- 10B. DYNAMIC OPEN GRAPH PNG GENERATOR (/og-image.png) ---

app.get('/og-image.png', async (req, res) => {
    try {
        await ensureOgFonts();

        const width = 1200;
        const height = 630;
        const canvas = createCanvas(width, height);
        const ctx = canvas.getContext('2d');

        // 1. Ambil query params atau data asli dari MongoDB (jika ?productId= dikirim)
        let title = req.query.title || 'ArulzXD Store';
        let subtitle = req.query.subtitle || 'Store Produk Digital Premium, Bot Otomasi, Script & Source Code Terpercaya.';
        let priceText = req.query.price || 'MULAI RP 5.000';
        let categoryText = (req.query.category || 'DIGITAL STORE').toUpperCase();
        let stockText = req.query.stock || 'INSTAN 24/7';
        let previewImgUrl = req.query.image || null;

        if (req.query.productId) {
            const prod = await ProductV2.findOne({
                $or: [
                    { Id: req.query.productId },
                    { _id: mongoose.Types.ObjectId.isValid(req.query.productId) ? req.query.productId : null }
                ]
            }).lean();

            if (prod) {
                title = prod.nama || title;
                subtitle = prod.deskripsi || subtitle;
                categoryText = (prod.kategori || 'PRODUK DIGITAL').toUpperCase();
                const finalHarga = prod.harga_diskon || prod.harga;
                priceText = `RP ${Number(finalHarga || 0).toLocaleString('id-ID')}`;
                stockText = `STOK: ${prod.stok ?? 0} | TERJUAL: ${prod.terjual ?? 0}`;
                if (Array.isArray(prod.gambar) && prod.gambar[0]) {
                    previewImgUrl = prod.gambar[0];
                } else if (typeof prod.gambar === 'string' && prod.gambar) {
                    previewImgUrl = prod.gambar;
                }
            }
        }

        // 2. BACKGROUND NEO-BRUTALISM (#F4F0EA + Grid Pattern halus)
        ctx.fillStyle = '#F4F0EA';
        ctx.fillRect(0, 0, width, height);

        ctx.strokeStyle = 'rgba(0, 0, 0, 0.06)';
        ctx.lineWidth = 2;
        const gridSize = 40;
        for (let gx = 0; gx <= width; gx += gridSize) {
            ctx.beginPath();
            ctx.moveTo(gx, 0);
            ctx.lineTo(gx, height);
            ctx.stroke();
        }
        for (let gy = 0; gy <= height; gy += gridSize) {
            ctx.beginPath();
            ctx.moveTo(0, gy);
            ctx.lineTo(width, gy);
            ctx.stroke();
        }

        // 3. CONTAINER KARTU UTAMA PUTIH (dengan Hard Shadow 12px)
        drawNeoBox(ctx, 44, 42, width - 88, height - 84, 28, '#FFFFFF', 12, 5);

        // 4. HEADER TOP BAR KUNING (#FFDE59)
        ctx.save();
        ctx.beginPath();
        ctx.roundRect(44, 42, width - 88, 92, [28, 28, 0, 0]);
        ctx.fillStyle = '#FFDE59';
        ctx.fill();
        ctx.lineWidth = 5;
        ctx.strokeStyle = '#000000';
        ctx.stroke();
        ctx.restore();

        // Brand Logo di Header Kiri
        drawNeoBox(ctx, 76, 63, 48, 48, 12, '#000000', 0, 0);
        ctx.fillStyle = '#FFDE59';
        ctx.font = 'bold 28px "SpaceGrotesk", sans-serif';
        ctx.fillText('⚡', 87, 97);

        ctx.fillStyle = '#000000';
        ctx.font = '900 32px "SpaceGrotesk", sans-serif';
        ctx.fillText('Arulz', 138, 99);

        drawNeoBox(ctx, 226, 66, 114, 42, 10, '#000000', 0, 0);
        ctx.fillStyle = '#FFFFFF';
        ctx.font = '800 24px "SpaceGrotesk", sans-serif';
        ctx.fillText('Store', 246, 95);

        // Badge Status di Header Kanan (Pink & Cyan)
        drawNeoBox(ctx, width - 355, 65, 275, 44, 12, '#00E5FF', 4, 3);
        ctx.fillStyle = '#000000';
        ctx.font = '800 18px "JetBrainsMono", monospace';
        ctx.fillText('● OTOMATIS & INSTAN', width - 333, 93);

        // 5. KONTEN KIRI (Kategori Badge, Judul Besar, Deskripsi, Harga & CTA)
        const leftX = 80;
        const leftMaxW = 635;

        // Badge Kategori (Pink #FF79C6)
        ctx.font = '800 18px "JetBrainsMono", monospace';
        const catWidth = Math.min(340, Math.max(170, ctx.measureText(categoryText).width + 44));
        drawNeoBox(ctx, leftX, 166, catWidth, 42, 10, '#FF79C6', 4, 3);
        ctx.fillStyle = '#000000';
        ctx.fillText(categoryText.slice(0, 22), leftX + 20, 193);

        // Badge Stok / Info di sebelahnya (Hijau #00E676)
        const stockX = leftX + catWidth + 16;
        drawNeoBox(ctx, stockX, 166, 235, 42, 10, '#00E676', 4, 3);
        ctx.fillStyle = '#000000';
        ctx.font = '800 17px "JetBrainsMono", monospace';
        ctx.fillText(stockText.slice(0, 20), stockX + 18, 193);

        // Judul Utama Produk / Halaman
        ctx.fillStyle = '#000000';
        ctx.font = '900 46px "SpaceGrotesk", sans-serif';
        const afterTitleY = wrapText(ctx, title, leftX, 266, leftMaxW, 54, 2);

        // Deskripsi Singkat
        ctx.fillStyle = '#334155';
        ctx.font = '600 22px "JakartaSans", sans-serif';
        wrapText(ctx, subtitle, leftX, afterTitleY + 46, leftMaxW, 32, 2);

        // Box Harga & Domain di bagian bawah kartu kiri
        drawNeoBox(ctx, leftX, 456, 315, 76, 16, '#FFDE59', 6, 4);
        ctx.fillStyle = '#000000';
        ctx.font = '700 14px "JetBrainsMono", monospace';
        ctx.fillText('HARGA TERBAIK', leftX + 20, 482);
        ctx.font = '900 28px "SpaceGrotesk", sans-serif';
        ctx.fillText(priceText, leftX + 20, 517);

        drawNeoBox(ctx, leftX + 335, 456, 295, 76, 16, '#000000', 6, 4);
        ctx.fillStyle = '#00E5FF';
        ctx.font = '700 14px "JetBrainsMono", monospace';
        ctx.fillText('KUNJUNGI WEBSITE', leftX + 355, 482);
        ctx.fillStyle = '#FFFFFF';
        ctx.font = '800 21px "SpaceGrotesk", sans-serif';
        ctx.fillText('shoparulzxd.biz.id', leftX + 355, 516);

        // 6. KONTEN KANAN (PREVIEW THUMBNAIL PRODUK / VISUAL CARD)
        const rightX = 755;
        const rightY = 166;
        const rightW = 365;
        const rightH = 366;

        drawNeoBox(ctx, rightX, rightY, rightW, rightH, 22, '#F4F0EA', 8, 4);

        let imageDrawn = false;
        if (previewImgUrl && /^https?:\/\//i.test(previewImgUrl)) {
            try {
                const imgRes = await axios.get(previewImgUrl, {
                    responseType: 'arraybuffer',
                    timeout: 4500
                });
                const img = await loadImage(Buffer.from(imgRes.data));
                ctx.save();
                ctx.beginPath();
                ctx.roundRect(rightX + 10, rightY + 10, rightW - 20, rightH - 20, 14);
                ctx.clip();

                // Cover crop center
                const scale = Math.max((rightW - 20) / img.width, (rightH - 20) / img.height);
                const dw = img.width * scale;
                const dh = img.height * scale;
                const dx = rightX + 10 + ((rightW - 20) - dw) / 2;
                const dy = rightY + 10 + ((rightH - 20) - dh) / 2;
                ctx.drawImage(img, dx, dy, dw, dh);
                ctx.restore();
                imageDrawn = true;
            } catch (e) {
                imageDrawn = false;
            }
        }

        // Fallback Ilustrasi Neo-Brutalism keren jika gambar produk tidak dimuat
        if (!imageDrawn) {
            drawNeoBox(ctx, rightX + 26, rightY + 26, rightW - 52, 130, 16, '#00E5FF', 5, 3);
            ctx.fillStyle = '#000000';
            ctx.font = '900 26px "SpaceGrotesk", sans-serif';
            ctx.fillText('⚡ QRIS OTOMATIS', rightX + 46, rightY + 82);
            ctx.font = '700 17px "JakartaSans", sans-serif';
            ctx.fillText('Proses Cepat & Saldo Instan', rightX + 46, rightY + 118);

            drawNeoBox(ctx, rightX + 26, rightY + 180, rightW - 52, 156, 16, '#FF79C6', 5, 3);
            ctx.fillStyle = '#000000';
            ctx.font = '900 24px "SpaceGrotesk", sans-serif';
            ctx.fillText('🛡️ 100% TERPERCAYA', rightX + 46, rightY + 234);
            ctx.font = '700 17px "JakartaSans", sans-serif';
            ctx.fillText('Script, Bot, Panel & Jasa Digital', rightX + 46, rightY + 270);
            ctx.font = '800 15px "JetBrainsMono", monospace';
            ctx.fillText('✓ SUPPORT LIVE CHAT 24/7', rightX + 46, rightY + 305);
        }

        // 7. Render ke PNG & kirim dengan Cache-Control
        const pngBuffer = await canvas.encode('png');
        res.setHeader('Content-Type', 'image/png');
        res.setHeader('Cache-Control', 'public, max-age=3600, s-maxage=3600');
        return res.send(pngBuffer);
    } catch (err) {
        console.error('❌ Gagal generate OG Image:', err);
        return res.status(500).send('Failed to generate OG image');
    }
});

// --- 10C. API DATA PRODUK & ADMIN GENERATOR ---

app.get('/api/products', async (req, res) => {
    try {
        const products = await ProductV2.find({}).sort({ createdAt: -1 }).lean();

        const sanitizedProducts = products.map(prod => {
            const { link, purchasedBy, ...safeProduct } = prod;
            return safeProduct;
        });

        return res.json({ status: true, products: sanitizedProducts });
    } catch (error) {
        console.error("Error fetching products:", error);
        return res.status(500).json({ status: false, message: "Gagal mengambil daftar produk dari database" });
    }
});

app.get('/api/admin/products', checkAuthSession, checkAdminRole, async (req, res) => {
    try {
        const products = await ProductV2.find({}).sort({ createdAt: -1 }).lean();
        return res.json({ status: true, products });
    } catch (error) {
        return res.status(500).json({ status: false, message: 'Gagal memuat daftar produk.' });
    }
});

app.post('/api/admin/products', checkAuthSession, checkAdminRole, async (req, res) => {
    try {
        const { Id, nama, harga, harga_diskon, kategori, badge, terjual, stok, gambar, deskripsi, link } = req.body;

        if (!Id || !nama || harga === undefined || !kategori || !link) {
            return res.status(400).json({ status: false, message: 'ID Produk, Nama, Harga, Kategori, dan Link wajib diisi!' });
        }

        const cleanId = String(Id).trim();
        const existing = await ProductV2.findOne({ Id: cleanId });
        if (existing) {
            return res.status(409).json({ status: false, message: `Produk dengan ID "${cleanId}" sudah ada! Gunakan ID lain.` });
        }

        const gambarArray = Array.isArray(gambar)
            ? gambar.map(g => String(g).trim()).filter(Boolean)
            : typeof gambar === 'string' && gambar.trim()
                ? gambar.split('\n').map(g => g.trim()).filter(Boolean)
                : ['https://cdn.larasxd.my.id/files/Z9zjj0RF7G7ena.png'];

        const newProduct = await ProductV2.create({
            Id: cleanId,
            nama: String(nama).trim(),
            harga: Number(harga) || 0,
            harga_diskon: (harga_diskon !== null && harga_diskon !== '' && Number(harga_diskon) > 0) ? Number(harga_diskon) : null,
            kategori: String(kategori).trim(),
            badge: String(badge || '').trim(),
            terjual: Number(terjual) || 0,
            stok: Number(stok) || 0,
            gambar: gambarArray.length > 0 ? gambarArray : ['https://cdn.larasxd.my.id/files/Z9zjj0RF7G7ena.png'],
            deskripsi: String(deskripsi || '').trim(),
            link: String(link).trim()
        });

        await deleteCache('products_list');
        return res.status(201).json({ status: true, message: 'Produk berhasil ditambahkan ke database!', product: newProduct });
    } catch (error) {
        console.error('Error create product admin:', error);
        return res.status(500).json({ status: false, message: error.message || 'Gagal menyimpan produk.' });
    }
});

app.put('/api/admin/products/:id', checkAuthSession, checkAdminRole, async (req, res) => {
    try {
        const { id } = req.params;
        const { Id, nama, harga, harga_diskon, kategori, badge, terjual, stok, gambar, deskripsi, link } = req.body;

        const product = await ProductV2.findOne({
            $or: [
                { _id: mongoose.Types.ObjectId.isValid(id) ? id : null },
                { Id: id }
            ]
        });

        if (!product) {
            return res.status(404).json({ status: false, message: 'Produk tidak ditemukan.' });
        }

        if (Id && String(Id).trim() !== product.Id) {
            const dup = await ProductV2.findOne({ Id: String(Id).trim() });
            if (dup) {
                return res.status(409).json({ status: false, message: `ID "${Id}" sudah digunakan produk lain.` });
            }
            product.Id = String(Id).trim();
        }

        if (nama !== undefined) product.nama = String(nama).trim();
        if (harga !== undefined) product.harga = Number(harga) || 0;
        if (harga_diskon !== undefined) {
            product.harga_diskon = (harga_diskon !== null && harga_diskon !== '' && Number(harga_diskon) > 0) ? Number(harga_diskon) : null;
        }
        if (kategori !== undefined) product.kategori = String(kategori).trim();
        if (badge !== undefined) product.badge = String(badge).trim();
        if (terjual !== undefined) product.terjual = Number(terjual) || 0;
        if (stok !== undefined) product.stok = Number(stok) || 0;
        if (deskripsi !== undefined) product.deskripsi = String(deskripsi).trim();
        if (link !== undefined) product.link = String(link).trim();

        if (gambar !== undefined) {
            const gambarArray = Array.isArray(gambar)
                ? gambar.map(g => String(g).trim()).filter(Boolean)
                : typeof gambar === 'string'
                    ? gambar.split('\n').map(g => g.trim()).filter(Boolean)
                    : product.gambar;
            product.gambar = gambarArray.length > 0 ? gambarArray : ['https://cdn.larasxd.my.id/files/Z9zjj0RF7G7ena.png'];
        }

        await product.save();
        await deleteCache('products_list');
        return res.json({ status: true, message: 'Produk berhasil diperbarui!', product });
    } catch (error) {
        console.error('Error update product admin:', error);
        return res.status(500).json({ status: false, message: error.message || 'Gagal memperbarui produk.' });
    }
});

app.delete('/api/admin/products/:id', checkAuthSession, checkAdminRole, async (req, res) => {
    try {
        const { id } = req.params;
        const deleted = await ProductV2.findOneAndDelete({
            $or: [
                { _id: mongoose.Types.ObjectId.isValid(id) ? id : null },
                { Id: id }
            ]
        });

        if (!deleted) {
            return res.status(404).json({ status: false, message: 'Produk tidak ditemukan.' });
        }

        await deleteCache('products_list');
        return res.json({ status: true, message: `Produk "${deleted.nama}" berhasil dihapus!` });
    } catch (error) {
        return res.status(500).json({ status: false, message: 'Gagal menghapus produk.' });
    }
});

// --- 10D. API NOTIFIKASI USER & ADMIN ---

app.get('/api/notifikasi', checkAuthSession, async (req, res) => {
    try {
        const userEmail = req.user?.email ? req.user.email.toLowerCase().trim() : null;

        const filter = userEmail
            ? { $or: [{ targetEmail: null }, { targetEmail: '' }, { targetEmail: userEmail }] }
            : { $or: [{ targetEmail: null }, { targetEmail: '' }] };

        const rawList = await NotifikasiV2.find(filter).sort({ createdAt: -1 }).limit(100).lean();

        let unreadCount = 0;
        const notifications = rawList.map((n) => {
            const readByList = Array.isArray(n.readBy) ? n.readBy : [];
            const isRead = userEmail ? readByList.includes(userEmail) : false;
            if (userEmail && !isRead) unreadCount++;

            return {
                _id: n._id,
                title: n.title,
                message: n.message,
                type: n.type || 'info',
                link: n.link || null,
                isPersonal: Boolean(n.targetEmail),
                isRead,
                createdAt: n.createdAt
            };
        });

        return res.json({
            status: true,
            isLoggedIn: Boolean(userEmail),
            unreadCount,
            notifications
        });
    } catch (error) {
        console.error('Error fetch notifikasi:', error);
        return res.status(500).json({ status: false, message: 'Gagal memuat notifikasi.' });
    }
});

app.get('/api/notifikasi/unread-count', checkAuthSession, async (req, res) => {
    try {
        const userEmail = req.user?.email ? req.user.email.toLowerCase().trim() : null;
        if (!userEmail) {
            return res.json({ status: true, unreadCount: 0 });
        }

        const unreadCount = await NotifikasiV2.countDocuments({
            $or: [{ targetEmail: null }, { targetEmail: '' }, { targetEmail: userEmail }],
            readBy: { $ne: userEmail }
        });

        return res.json({ status: true, unreadCount });
    } catch (error) {
        return res.json({ status: true, unreadCount: 0 });
    }
});

app.post('/api/notifikasi/read/:id', checkAuthSession, async (req, res) => {
    try {
        if (!req.user?.email) {
            return res.status(401).json({ status: false, message: 'Silakan login terlebih dahulu.' });
        }

        const { id } = req.params;
        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).json({ status: false, message: 'ID notifikasi tidak valid.' });
        }

        const userEmail = req.user.email.toLowerCase().trim();
        await NotifikasiV2.updateOne(
            { _id: id },
            { $addToSet: { readBy: userEmail } }
        );

        return res.json({ status: true, message: 'Notifikasi ditandai sudah dibaca.' });
    } catch (error) {
        return res.status(500).json({ status: false, message: 'Gagal memperbarui status baca.' });
    }
});

app.post('/api/notifikasi/read-all', checkAuthSession, async (req, res) => {
    try {
        if (!req.user?.email) {
            return res.status(401).json({ status: false, message: 'Silakan login terlebih dahulu.' });
        }

        const userEmail = req.user.email.toLowerCase().trim();
        await NotifikasiV2.updateMany(
            {
                $or: [{ targetEmail: null }, { targetEmail: '' }, { targetEmail: userEmail }],
                readBy: { $ne: userEmail }
            },
            { $addToSet: { readBy: userEmail } }
        );

        return res.json({ status: true, message: 'Semua notifikasi ditandai sudah dibaca.' });
    } catch (error) {
        return res.status(500).json({ status: false, message: 'Gagal menandai semua notifikasi.' });
    }
});

app.get('/api/admin/notifikasi', checkAuthSession, checkAdminRole, async (req, res) => {
    try {
        const list = await NotifikasiV2.find({}).sort({ createdAt: -1 }).limit(100).lean();
        return res.json({ status: true, notifications: list });
    } catch (error) {
        return res.status(500).json({ status: false, message: 'Gagal memuat daftar notifikasi.' });
    }
});

app.post('/api/admin/notifikasi', checkAuthSession, checkAdminRole, async (req, res) => {
    try {
        const { title, message, type, link, targetEmail } = req.body;
        if (!title || !message) {
            return res.status(400).json({ status: false, message: 'Judul dan isi pesan notifikasi wajib diisi!' });
        }

        const validTypes = ['info', 'promo', 'transaksi', 'sistem'];
        const notifType = validTypes.includes(type) ? type : 'info';

        const notif = await NotifikasiV2.create({
            title: String(title).trim(),
            message: String(message).trim(),
            type: notifType,
            link: link && String(link).trim() ? String(link).trim() : null,
            targetEmail: targetEmail && String(targetEmail).trim() ? String(targetEmail).toLowerCase().trim() : null,
            createdBy: req.user.username || 'Admin'
        });

        // Kirim notifikasi ke Telegram Bot & Email seluruh user (atau target user)
        const delivery = await dispatchNotificationToUsers(notif);

        return res.status(201).json({
            status: true,
            message: `Notifikasi berhasil dikirim! (Web + ${delivery.telegramSent} Telegram + ${delivery.emailSent} Email)`,
            notification: notif,
            delivery
        });
    } catch (error) {
        console.error('Error create notifikasi admin:', error);
        return res.status(500).json({ status: false, message: 'Gagal mengirim notifikasi.' });
    }
});

app.delete('/api/admin/notifikasi/:id', checkAuthSession, checkAdminRole, async (req, res) => {
    try {
        const { id } = req.params;
        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).json({ status: false, message: 'ID notifikasi tidak valid.' });
        }

        const deleted = await NotifikasiV2.findByIdAndDelete(id);
        if (!deleted) {
            return res.status(404).json({ status: false, message: 'Notifikasi tidak ditemukan.' });
        }

        return res.json({ status: true, message: 'Notifikasi berhasil dihapus!' });
    } catch (error) {
        return res.status(500).json({ status: false, message: 'Gagal menghapus notifikasi.' });
    }
});

// --- 10E. API STATUS USER, ANALYTICS & SYSTEM DASHBOARD ---

app.get('/api/user', checkAuthSession, async (req, res) => {
    if (req.user) {
        try {
            let dbUser = await UserV2.findById(req.user.id || req.user._id).lean();
            if (dbUser) {
                if (!dbUser.referralCode) {
                    const newRef = generateReferralCode();
                    await UserV2.updateOne({ _id: dbUser._id }, { $set: { referralCode: newRef } });
                    dbUser.referralCode = newRef;
                }

                const referredCount = await UserV2.countDocuments({ referredBy: dbUser.referralCode });
                const isAdmin = dbUser.email?.toLowerCase().trim() === OWNER_EMAIL;

                return res.json({
                    loggedIn: true,
                    isAdmin,
                    user: {
                        ...dbUser,
                        isAdmin,
                        saldo: dbUser.saldo || 0,
                        referralCode: dbUser.referralCode,
                        referredCount: referredCount,
                        hasCompletedOnboarding: dbUser.hasCompletedOnboarding || false,
                        telegramLinked: Boolean(dbUser.telegramChatId || (dbUser.provider === 'telegram' && dbUser.providerId)),
                        telegramUsername: dbUser.telegramUsername || null,
                        telegramNotifEnabled: dbUser.telegramNotifEnabled !== false,
                        emailNotifEnabled: dbUser.emailNotifEnabled !== false,
                        telegramBotUsername: TELEGRAM_BOT_USERNAME || null,
                        banner: dbUser.banner || 'https://cdn.larasxd.my.id/files/Tk4GavOaHEEP2ykm.mp4'
                    }
                });
            }
        } catch (err) {
            console.error("Error fetch user balance:", err);
        }
        const isAdminFallback = req.user.email?.toLowerCase().trim() === OWNER_EMAIL;
        return res.json({ loggedIn: true, isAdmin: isAdminFallback, user: { ...req.user, isAdmin: isAdminFallback } });
    } else {
        return res.json({ loggedIn: false, isAdmin: false });
    }
});

app.get('/api/analytics-data', async (req, res) => {
    try {
        const range = req.query.range || '7d';
        const now = moment().tz('Asia/Jakarta');
        let startDate, groupFormat, labelFormat;

        if (range === '24h') {
            startDate = now.clone().subtract(23, 'hours').startOf('hour');
            groupFormat = "%Y-%m-%d %H:00";
            labelFormat = "HH:00";
        } else if (range === '30d') {
            startDate = now.clone().subtract(29, 'days').startOf('day');
            groupFormat = "%Y-%m-%d";
            labelFormat = "DD MMM";
        } else {
            startDate = now.clone().subtract(6, 'days').startOf('day');
            groupFormat = "%Y-%m-%d";
            labelFormat = "DD MMM";
        }

        const trxAgg = await TransactionV2.aggregate([
            { $match: { createdAt: { $gte: startDate.toDate() } } },
            {
                $group: {
                    _id: {
                        timeBucket: {
                            $dateToString: {
                                format: groupFormat,
                                date: "$createdAt",
                                timezone: "Asia/Jakarta"
                            }
                        }
                    },
                    successCount: {
                        $sum: {
                            $cond: [{ $in: [{ $toLower: "$status" }, ["settlement", "success", "paid", "settled"]] }, 1, 0]
                        }
                    },
                    cancelledCount: {
                        $sum: {
                            $cond: [{ $in: [{ $toLower: "$status" }, ["cancelled", "expired", "failed"]] }, 1, 0]
                        }
                    },
                    pendingCount: {
                        $sum: {
                            $cond: [{ $eq: [{ $toLower: "$status" }, "pending"] }, 1, 0]
                        }
                    },
                    revenueTotal: {
                        $sum: {
                            $cond: [
                                { $in: [{ $toLower: "$status" }, ["settlement", "success", "paid", "settled"]] },
                                "$amount",
                                0
                            ]
                        }
                    }
                }
            }
        ]);

        const perfAgg = await SystemMetricsV2.aggregate([
            { $match: { timestamp: { $gte: startDate.toDate() } } },
            {
                $group: {
                    _id: {
                        timeBucket: {
                            $dateToString: {
                                format: groupFormat,
                                date: "$timestamp",
                                timezone: "Asia/Jakarta"
                            }
                        }
                    },
                    avgLatency: { $avg: "$responseTimeMs" },
                    totalHits: { $sum: 1 }
                }
            }
        ]);

        const labels = [];
        const successSeries = [];
        const cancelledSeries = [];
        const pendingSeries = [];
        const revenueSeries = [];
        const latencySeries = [];
        const hitsSeries = [];

        const steps = range === '24h' ? 24 : (range === '30d' ? 30 : 7);
        const unit = range === '24h' ? 'hours' : 'days';

        for (let i = 0; i < steps; i++) {
            const currentSlot = startDate.clone().add(i, unit);
            const bucketKey = currentSlot.format(range === '24h' ? "YYYY-MM-DD HH:00" : "YYYY-MM-DD");
            const displayLabel = currentSlot.format(labelFormat);

            const foundTrx = trxAgg.find(item => item._id.timeBucket === bucketKey);
            const foundPerf = perfAgg.find(item => item._id.timeBucket === bucketKey);

            labels.push(displayLabel);
            successSeries.push(foundTrx ? foundTrx.successCount : 0);
            cancelledSeries.push(foundTrx ? foundTrx.cancelledCount : 0);
            pendingSeries.push(foundTrx ? foundTrx.pendingCount : 0);
            revenueSeries.push(foundTrx ? foundTrx.revenueTotal : 0);
            latencySeries.push(foundPerf ? Math.round(foundPerf.avgLatency) : 12);
            hitsSeries.push(foundPerf ? foundPerf.totalHits : 0);
        }

        const totalRev = revenueSeries.reduce((a, b) => a + b, 0);
        const totalSucc = successSeries.reduce((a, b) => a + b, 0);
        const totalCanc = cancelledSeries.reduce((a, b) => a + b, 0);
        const avgLat = latencySeries.length > 0 ? Math.round(latencySeries.reduce((a, b) => a + b, 0) / latencySeries.length) : 15;

        return res.json({
            status: true,
            range,
            labels,
            transactions: {
                success: successSeries,
                cancelled: cancelledSeries,
                pending: pendingSeries
            },
            revenue: revenueSeries,
            performance: {
                latencyMs: latencySeries,
                requests: hitsSeries
            },
            summary: {
                totalRevenue: totalRev,
                totalSuccess: totalSucc,
                totalCancelled: totalCanc,
                avgLatencyMs: avgLat
            }
        });

    } catch (error) {
        console.error("Analytics Data Error:", error);
        return res.status(500).json({ status: false, message: "Gagal memproses analitik sistem." });
    }
});

app.get('/api/system-status', async (req, res) => {
    try {
        const startPing = Date.now();
        await mongoose.connection.db.admin().ping();
        const dbLatency = Date.now() - startPing;

        const nowWib = moment().tz('Asia/Jakarta');

        const uptimeSeconds = process.uptime();
        const days = Math.floor(uptimeSeconds / (3600 * 24));
        const hours = Math.floor((uptimeSeconds % (3600 * 24)) / 3600);
        const minutes = Math.floor((uptimeSeconds % 3600) / 60);
        const seconds = Math.floor(uptimeSeconds % 60);

        const totalMem = os.totalmem();
        const freeMem = os.freemem();
        const usedMem = totalMem - freeMem;
        const memPercentage = ((usedMem / totalMem) * 100).toFixed(1);

        const totalUsers = await UserV2.countDocuments();
        const totalProducts = await ProductV2.countDocuments();
        const totalReviews = await ReviewV2.countDocuments();

        const salesAggregation = await ProductV2.aggregate([
            { $group: { _id: null, totalTerjual: { $sum: "$terjual" } } }
        ]);
        const totalTerjual = salesAggregation.length > 0 ? salesAggregation[0].totalTerjual : 0;

        const totalTrx = await TransactionV2.countDocuments();
        const settledTrx = await TransactionV2.countDocuments({ status: { $in: ["settlement", "success", "paid", "settled"] } });
        const pendingTrx = await TransactionV2.countDocuments({ status: "pending" });
        const cancelledTrx = await TransactionV2.countDocuments({ status: { $in: ["cancelled", "expired"] } });

        return res.json({
            status: true,
            server: {
                status: 'ONLINE',
                uptime: `${days}d ${hours}h ${minutes}m ${seconds}s`,
                platform: os.platform() + ' (' + os.arch() + ')',
                nodeVersion: process.version,
                cpuLoad: os.loadavg()[0].toFixed(2)
            },
            database: {
                connected: mongoose.connection.readyState === 1,
                latencyMs: dbLatency,
                statusText: mongoose.connection.readyState === 1 ? 'CONNECTED' : 'DISCONNECTED'
            },
            memory: {
                totalMB: Math.round(totalMem / 1024 / 1024),
                usedMB: Math.round(usedMem / 1024 / 1024),
                percentage: memPercentage
            },
            time: {
                wib: nowWib.format('HH:mm:ss'),
                date: nowWib.format('dddd, DD MMMM YYYY')
            },
            metrics: {
                totalUsers,
                totalProducts,
                totalTerjual,
                totalReviews,
                transactions: {
                    total: totalTrx,
                    success: settledTrx,
                    pending: pendingTrx,
                    cancelled: cancelledTrx
                }
            }
        });
    } catch (error) {
        console.error("System Status Error:", error);
        return res.status(500).json({ status: false, message: "Gagal mengambil status sistem" });
    }
});

// ============================================================
// 11. START SERVER
// ============================================================

app.listen(PORT, () => {
    console.log(`=================================================`);
    console.log(`⚡ ARULZXD DASHBOARD BERJALAN PADA PORT ${PORT}`);
    console.log(`🌐 URL Lokal: http://localhost:${PORT}`);
    console.log(`=================================================`);
});

export default app;
