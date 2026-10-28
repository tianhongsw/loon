/**
 * 中国移动 话费/流量/语音 综合余量查询（官方网上营业厅免登录版）
 * ================================================================
 * 
 * 机制说明：
 * 依托【移动云盘中枢 -> 017018 移动大网专线 -> netUni】SSO 跳板，
 * 全自动免密签发大网网关凭据 d.sid 与网厅 csrf-token，彻底告别抓包。
 * 
 * 特色：
 * - 纯明文、无混淆、无压缩长单行，完美支持 GitHub 网页端编辑与托管。
 * - 原生支持 BoxJS 面板一键「点击运行」实时查看话费与流量。
 * - 全平台兼容：BoxJS / Surge / Loon / Quantumult X / Shadowrocket / 青龙面板。
 * 
 * 配置来源（支持以下任意一种）：
 * - BoxJS 配置字段：china_mobile_cookie 或 MCLD_COOKIES
 * - 环境变量：MCLD_COOKIES（云盘凭据 Basic xxx，多账号换行填写）
 * - 青龙面板脚本目录中的 config_*.json
 */

// ---------------------- 纯明文 AES-128-CBC 解密引擎 (全环境通用) ----------------------
const SBOX_INV = new Uint8Array([
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]);

function gmul(a, b) {
    let p = 0;
    for (let i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        const hi = a & 0x80;
        a = (a << 1) & 0xff;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

function expandKey(k) {
    const RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
    const SBOX = new Uint8Array(256);
    for (let i = 0; i < 256; i++) SBOX[SBOX_INV[i]] = i;
    const w = new Uint32Array(44);
    for (let i = 0; i < 4; i++) {
        w[i] = (k[4 * i] << 24) | (k[4 * i + 1] << 16) | (k[4 * i + 2] << 8) | k[4 * i + 3];
    }
    for (let i = 4; i < 44; i++) {
        let temp = w[i - 1];
        if (i % 4 === 0) {
            const b0 = SBOX[(temp >>> 16) & 0xff];
            const b1 = SBOX[(temp >>> 8) & 0xff];
            const b2 = SBOX[temp & 0xff];
            const b3 = SBOX[(temp >>> 24) & 0xff];
            temp = ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) ^ (RCON[i / 4] << 24);
        }
        w[i] = w[i - 4] ^ temp;
    }
    return w;
}

function invMixColumns(s) {
    for (let c = 0; c < 4; c++) {
        const i = c * 4;
        const a0 = s[i], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];
        s[i]     = gmul(a0, 0x0e) ^ gmul(a1, 0x0b) ^ gmul(a2, 0x0d) ^ gmul(a3, 0x09);
        s[i + 1] = gmul(a0, 0x09) ^ gmul(a1, 0x0e) ^ gmul(a2, 0x0b) ^ gmul(a3, 0x0d);
        s[i + 2] = gmul(a0, 0x0d) ^ gmul(a1, 0x09) ^ gmul(a2, 0x0e) ^ gmul(a3, 0x0b);
        s[i + 3] = gmul(a0, 0x0b) ^ gmul(a1, 0x0d) ^ gmul(a2, 0x09) ^ gmul(a3, 0x0e);
    }
}

function decryptBlock(block, roundKeys) {
    const s = new Uint8Array(block);
    for (let i = 0; i < 4; i++) {
        const k = roundKeys[40 + i];
        s[4 * i]     ^= (k >>> 24) & 0xff;
        s[4 * i + 1] ^= (k >>> 16) & 0xff;
        s[4 * i + 2] ^= (k >>> 8)  & 0xff;
        s[4 * i + 3] ^= k & 0xff;
    }
    for (let r = 9; r >= 1; r--) {
        const t1 = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t1;
        const t2 = s[2]; const t6 = s[6]; s[2] = s[10]; s[6] = s[14]; s[10] = t2; s[14] = t6;
        const t3 = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t3;
        for (let i = 0; i < 16; i++) s[i] = SBOX_INV[s[i]];
        for (let i = 0; i < 4; i++) {
            const k = roundKeys[r * 4 + i];
            s[4 * i]     ^= (k >>> 24) & 0xff;
            s[4 * i + 1] ^= (k >>> 16) & 0xff;
            s[4 * i + 2] ^= (k >>> 8)  & 0xff;
            s[4 * i + 3] ^= k & 0xff;
        }
        invMixColumns(s);
    }
    const t1 = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t1;
    const t2 = s[2]; const t6 = s[6]; s[2] = s[10]; s[6] = s[14]; s[10] = t2; s[14] = t6;
    const t3 = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t3;
    for (let i = 0; i < 16; i++) s[i] = SBOX_INV[s[i]];
    for (let i = 0; i < 4; i++) {
        const k = roundKeys[i];
        s[4 * i]     ^= (k >>> 24) & 0xff;
        s[4 * i + 1] ^= (k >>> 16) & 0xff;
        s[4 * i + 2] ^= (k >>> 8)  & 0xff;
        s[4 * i + 3] ^= k & 0xff;
    }
    return s;
}

function pureAes128CbcDecrypt(cipherHex, keyStr, ivStr) {
    const ct = [];
    for (let i = 0; i < cipherHex.length; i += 2) {
        ct.push(parseInt(cipherHex.substr(i, 2), 16));
    }
    const k = Array.from(keyStr).map(c => c.charCodeAt(0));
    const v = Array.from(ivStr).map(c => c.charCodeAt(0));
    const roundKeys = expandKey(k);
    const pt = [];
    let prev = v;
    for (let i = 0; i < ct.length; i += 16) {
        const blk = ct.slice(i, i + 16);
        const d = decryptBlock(blk, roundKeys);
        for (let j = 0; j < 16; j++) pt.push(d[j] ^ prev[j]);
        prev = blk;
    }
    const pad = pt[pt.length - 1];
    if (pad >= 1 && pad <= 16) pt.splice(pt.length - pad, pad);

    if (typeof TextDecoder !== 'undefined') {
        return new TextDecoder('utf-8').decode(new Uint8Array(pt));
    }
    // 基础解码兜底
    return decodeURIComponent(escape(String.fromCharCode.apply(null, pt)));
}

function xtime(a) { return (a & 0x80) ? ((a << 1) ^ 0x1b) & 0xff : (a << 1); }

function mixColumns(s) {
    for (let c = 0; c < 4; c++) {
        const i = c * 4;
        const a0 = s[i], a1 = s[i+1], a2 = s[i+2], a3 = s[i+3];
        s[i]   = xtime(a0 ^ a1) ^ a1 ^ a2 ^ a3;
        s[i+1] = xtime(a1 ^ a2) ^ a2 ^ a3 ^ a0;
        s[i+2] = xtime(a2 ^ a3) ^ a3 ^ a0 ^ a1;
        s[i+3] = xtime(a3 ^ a0) ^ a0 ^ a1 ^ a2;
    }
}

function encryptBlock(block, roundKeys) {
    const s = new Uint8Array(block);
    for (let i = 0; i < 4; i++) {
        const k = roundKeys[i];
        s[4 * i]     ^= (k >>> 24) & 0xff;
        s[4 * i + 1] ^= (k >>> 16) & 0xff;
        s[4 * i + 2] ^= (k >>> 8)  & 0xff;
        s[4 * i + 3] ^= k & 0xff;
    }
    for (let r = 1; r < 10; r++) {
        for (let i = 0; i < 16; i++) s[i] = SBOX[s[i]];
        const t1 = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t1;
        const t2 = s[2]; const t6 = s[6]; s[2] = s[10]; s[6] = s[14]; s[10] = t2; s[14] = t6;
        const t3 = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t3;
        mixColumns(s);
        for (let i = 0; i < 4; i++) {
            const k = roundKeys[r * 4 + i];
            s[4 * i]     ^= (k >>> 24) & 0xff;
            s[4 * i + 1] ^= (k >>> 16) & 0xff;
            s[4 * i + 2] ^= (k >>> 8)  & 0xff;
            s[4 * i + 3] ^= k & 0xff;
        }
    }
    for (let i = 0; i < 16; i++) s[i] = SBOX[s[i]];
    const t1 = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t1;
    const t2 = s[2]; const t6 = s[6]; s[2] = s[10]; s[6] = s[14]; s[10] = t2; s[14] = t6;
    const t3 = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t3;
    for (let i = 0; i < 4; i++) {
        const k = roundKeys[40 + i];
        s[4 * i]     ^= (k >>> 24) & 0xff;
        s[4 * i + 1] ^= (k >>> 16) & 0xff;
        s[4 * i + 2] ^= (k >>> 8)  & 0xff;
        s[4 * i + 3] ^= k & 0xff;
    }
    return s;
}

function pureAes128EcbEncrypt(plainText, keyStr) {
    let data;
    if (typeof TextEncoder !== 'undefined') {
        data = new TextEncoder().encode(plainText);
    } else {
        const unescaped = unescape(encodeURIComponent(plainText));
        data = new Uint8Array(unescaped.length);
        for (let i = 0; i < unescaped.length; i++) data[i] = unescaped.charCodeAt(i);
    }

    let key;
    if (typeof TextEncoder !== 'undefined') {
        key = new TextEncoder().encode(keyStr);
    } else {
        key = new Uint8Array(keyStr.length);
        for (let i = 0; i < keyStr.length; i++) key[i] = keyStr.charCodeAt(i);
    }

    const padLen = 16 - (data.length % 16);
    const padded = new Uint8Array(data.length + padLen);
    padded.set(data);
    padded.fill(padLen, data.length);

    const roundKeys = expandKey(key);
    const out = new Uint8Array(padded.length);
    for (let i = 0; i < padded.length; i += 16) {
        const blk = encryptBlock(padded.subarray(i, i + 16), roundKeys);
        out.set(blk, i);
    }

    if (typeof Buffer !== 'undefined') {
        return Buffer.from(out).toString('base64');
    }
    let binary = '';
    for (let i = 0; i < out.length; i++) binary += String.fromCharCode(out[i]);
    if (typeof btoa !== 'undefined') return btoa(binary);
    return '';
}

// ---------------------- 统一解密适配入口 ----------------------
const AES_KEY = '1234123412ABCDEF';
const AES_IV  = 'ABCDEF1234123412';
const STATIC_HEADER_MAGIC = 'ZS93dUFVa2kzaEpQSjM0SG55MUFDdz09';
const DEFAULT_UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.38 NetType/WIFI Language/zh_CN';

function decryptAesCbc(bodyHex) {
    if (!bodyHex || typeof bodyHex !== 'string') return null;
    bodyHex = bodyHex.trim();

    if (bodyHex.length >= 32 && bodyHex.length % 32 === 0 && /^[0-9a-fA-F]+$/.test(bodyHex)) {
        // 1. 若在 Node.js 环境，优先调用原生 crypto（毫秒级）
        if (typeof require !== 'undefined') {
            try {
                const crypto = require('crypto');
                const decipher = crypto.createDecipheriv('aes-128-cbc', Buffer.from(AES_KEY), Buffer.from(AES_IV));
                let decrypted = decipher.update(bodyHex, 'hex', 'utf8');
                decrypted += decipher.final('utf8');
                return JSON.parse(decrypted);
            } catch (e) {}
        }
        // 2. 在 Surge / Loon / Quantumult X / BoxJS 环境，调用纯 JS 解密引擎
        try {
            const decStr = pureAes128CbcDecrypt(bodyHex, AES_KEY, AES_IV);
            if (decStr) return JSON.parse(decStr);
        } catch (e) {
            console.log(`[DEBUG] AES 解密异常: ${e.message}`);
        }
    }

    try {
        return JSON.parse(bodyHex);
    } catch {
        return null;
    }
}

function genTraceId() {
    const chars = '0123456789abcdefghijklmnopqrstuvwxyz';
    function toB36(n) {
        let res = '';
        while (n > 0) {
            res = chars[n % 36] + res;
            n = Math.floor(n / 36);
        }
        return res || '0';
    }
    const prefix = toB36(Date.now());
    const template = '-xxxx-4xxx-yxxx-xxxxxxxxxxxx';
    let out = prefix;
    for (const ch of template) {
        if (ch === 'x') {
            out += (Math.floor(Math.random() * 16)).toString(8);
        } else if (ch === 'y') {
            out += ((Math.floor(Math.random() * 16) & 3) | 8).toString(8);
        } else {
            out += ch;
        }
    }
    return out;
}

function formatFlow(valStr, unitCode = '03') {
    const val = parseFloat(valStr);
    if (isNaN(val)) return '0 MB';

    let mb = val;
    if (unitCode === '04') mb = val * 1024;
    else if (unitCode === '02') mb = val / 1024;
    else if (unitCode === '01') mb = val / (1024 * 1024);

    if (mb >= 1024) {
        return `${(mb / 1024).toFixed(2)} GB`;
    }
    return `${mb.toFixed(2)} MB`;
}

function parseMcloudToken(authStr) {
    if (!authStr) return null;
    try {
        let raw = authStr.trim();
        let phoneSuffix = '';
        if (raw.includes('#')) {
            const parts = raw.split('#');
            if (parts[0].startsWith('Basic ') || parts[0].length > 50) {
                raw = parts[0].trim();
                phoneSuffix = parts[1].trim();
            } else {
                phoneSuffix = parts[0].trim();
                raw = parts[1].trim();
            }
        }
        if (!raw.startsWith('Basic ') && !raw.startsWith('basic ')) {
            raw = `Basic ${raw}`;
        }
        const b64 = raw.slice(6).trim();
        let decoded = '';
        if (typeof Buffer !== 'undefined') {
            decoded = Buffer.from(b64, 'base64').toString('utf8');
        } else if (typeof atob !== 'undefined') {
            decoded = atob(b64);
        }
        const colonParts = decoded.split(':');
        const clientType = colonParts[0] || 'pc';
        const phone = (colonParts.length > 1 && /^1\d{10}$/.test(colonParts[1])) ? colonParts[1] : phoneSuffix;
        const pipeParts = decoded.split('|');
        const expireAt = (pipeParts.length > 3 && /^\d+$/.test(pipeParts[3])) ? parseInt(pipeParts[3], 10) : 0;
        const remDays = expireAt > 0 ? (expireAt - Date.now()) / (1000 * 86400) : null;
        return { auth: raw, clientType, phone, expireAt, remDays };
    } catch {
        return null;
    }
}

function parsePhoneFromAuth(authStr) {
    const info = parseMcloudToken(authStr);
    return info ? info.phone : '';
}

// ---------------------- 移动云盘根凭据自动换发 / 续期 ----------------------
const CLOUD_REFRESH_KEY = 'c7lXOigXahPnTViq';
const CLOUD_REFRESH_URL = 'https://user-njs.yun.139.com/user/auth/refreshToken';

async function refreshCloudToken(authStr, phone, clientType = 'pc') {
    if (!authStr || !phone) {
        return { success: false, message: '缺少凭据或手机号' };
    }
    const cleanAuth = authStr.trim().startsWith('Basic ') ? authStr.trim() : `Basic ${authStr.trim()}`;
    const plain = JSON.stringify({ phoneNumber: phone });
    let encData = '';
    try {
        encData = pureAes128EcbEncrypt(plain, CLOUD_REFRESH_KEY);
    } catch (e) {
        return { success: false, message: `AES 加密异常: ${e.message}` };
    }

    const headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MCloudApp/13.0.0 iPhone AppLanguage/zh-CN',
        'x-yun-tid': genTraceId(),
        'Authorization': cleanAuth,
        'x-yun-api-version': 'v1',
        'x-yun-module-type': '100',
        'x-yun-op-type': '1',
        'x-yun-app-channel': '10214200',
        'x-yun-client-info': '||8||||||||||||',
        'hcy-cool-flag': '1'
    };

    const body = JSON.stringify({ data: encData });

    try {
        const res = await $.http.post({ url: CLOUD_REFRESH_URL, headers, body });
        if (res.statusCode !== 200) {
            return { success: false, message: `HTTP ${res.statusCode}: ${res.body}` };
        }
        const json = JSON.parse(res.body);
        if (json.code === '0000' && json.data && json.data.token) {
            const rawToken = json.data.token;
            let b64 = '';
            const plainCombined = `${clientType}:${phone}:${rawToken}`;
            if (typeof Buffer !== 'undefined') {
                b64 = Buffer.from(plainCombined, 'utf8').toString('base64');
            } else if (typeof btoa !== 'undefined') {
                b64 = btoa(unescape(encodeURIComponent(plainCombined)));
            }
            const newAuth = `Basic ${b64}`;
            const newInfo = parseMcloudToken(newAuth);
            return {
                success: true,
                newAuth,
                expireAt: newInfo ? newInfo.expireAt : 0
            };
        }
        return { success: false, message: json.message || json.code || '接口未返回有效 Token' };
    } catch (e) {
        return { success: false, message: e.message };
    }
}

function updateAccountTokenInStorage(targetPhone, newAuth) {
    if (!targetPhone || !newAuth) return;

    // 1. BoxJS china_mobile_cookie
    const curCookie = $.getdata('china_mobile_cookie') || '';
    if (curCookie) {
        const lines = curCookie.split(/[\n&]+/).map(s => s.trim()).filter(Boolean);
        const newLines = lines.map(line => {
            const info = parseMcloudToken(line);
            if (info && (info.phone === targetPhone || line.includes(targetPhone))) {
                return `${newAuth}#${targetPhone}`;
            }
            return line;
        });
        $.setdata(newLines.join('\n'), 'china_mobile_cookie');
    }

    // 2. BoxJS MCLD_COOKIES
    const curMcld = $.getdata('MCLD_COOKIES') || '';
    if (curMcld) {
        const lines = curMcld.split(/[\n&]+/).map(s => s.trim()).filter(Boolean);
        const newLines = lines.map(line => {
            const info = parseMcloudToken(line);
            if (info && (info.phone === targetPhone || line.includes(targetPhone))) {
                return `${newAuth}#${targetPhone}`;
            }
            return line;
        });
        $.setdata(newLines.join('\n'), 'MCLD_COOKIES');
    }

    // 3. Node.js 本地文件同步更新
    if ($.isNode()) {
        try {
            const fs = require('fs');
            const path = require('path');
            const dir = process.cwd();
            const files = fs.readdirSync(dir).filter(f => /^config_.*\.json$/.test(f) || f === 'config.json');
            for (const f of files) {
                const fullP = path.join(dir, f);
                try {
                    const data = JSON.parse(fs.readFileSync(fullP, 'utf8'));
                    if (data.phone === targetPhone || parsePhoneFromAuth(data.cloud_auth || data.Authorization) === targetPhone) {
                        data.cloud_auth = newAuth;
                        if (data.Authorization) data.Authorization = newAuth;
                        fs.writeFileSync(fullP, JSON.stringify(data, null, 2), 'utf8');
                        $.log(`💾 已同步写回本地配置文件: ${f}`);
                    }
                } catch (e) {}
            }
        } catch (e) {}
    }
}

// ---------------------- 账号加载 (全方位兼容 BoxJS 键名体系) ----------------------
const $ = new Env('中国移动余量查询');

function getAccountList() {
    const list = [];
    const seen = new Set();

    // 1. BoxJS 专用读取通道（多键容错）
    let boxCookies = $.getdata('china_mobile_cookie')
                  || $.getdata('MCLD_COOKIES')
                  || $.getdata('CHINA_MOBILE_COOKIE')
                  || $.getdata('@china_mobile.cookie')
                  || $.getdata('@china_mobile.china_mobile_cookie')
                  || '';

    // 若用户误将 token 填入 china_mobile_url 字段，智能兼容
    if (!boxCookies) {
        const urlVal = $.getdata('china_mobile_url') || $.getdata('CHINA_MOBILE_URL') || '';
        if (urlVal.includes('Basic ') || urlVal.length > 50) {
            boxCookies = urlVal;
        }
    }

    // 环境变量兜底
    if (!boxCookies && typeof process !== 'undefined' && process.env) {
        boxCookies = process.env.MCLD_COOKIES || process.env.CHINA_MOBILE_COOKIE || '';
    }

    const boxPhone = $.getdata('china_mobile_phonenumber')
                  || $.getdata('CHINA_MOBILE_PHONENUMBER')
                  || (typeof process !== 'undefined' && process.env ? (process.env.CHINA_MOBILE_PHONENUMBER || process.env.CMCC_PHONE) : '')
                  || '';

    if (boxCookies) {
        const lines = boxCookies.split(/[\n&]+/).map(s => s.trim()).filter(Boolean);
        for (const line of lines) {
            let auth = line;
            let phone = '';
            if (line.includes('#')) {
                const parts = line.split('#');
                if (parts[0].startsWith('Basic ') || parts[0].length > 50) {
                    auth = parts[0].trim();
                    phone = parts[1].trim();
                } else {
                    phone = parts[0].trim();
                    auth = parts[1].trim();
                }
            } else {
                phone = boxPhone || parsePhoneFromAuth(auth);
            }
            if (!auth.startsWith('Basic ')) {
                auth = `Basic ${auth}`;
            }
            if (phone && !seen.has(phone)) {
                seen.add(phone);
                list.push({ phone, auth, source: 'BoxJS' });
            }
        }
    }

    // 2. 青龙脚本目录自动读取 config_*.json
    if ($.isNode()) {
        try {
            const fs = require('fs');
            const path = require('path');
            const dir = process.cwd();
            const files = fs.readdirSync(dir).filter(f => /^config_.*\.json$/.test(f) || f === 'config.json').sort();
            for (const f of files) {
                try {
                    const data = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
                    const auth = data.cloud_auth || data.Authorization || '';
                    const phone = data.phone || parsePhoneFromAuth(auth);
                    if (auth && phone && !seen.has(phone)) {
                        seen.add(phone);
                        list.push({ phone, auth, source: f });
                    }
                } catch {}
            }
        } catch {}
    }

    return list;
}

// ---------------------- 核心 SSO 与网厅流程 ----------------------
class CmccService {
    constructor(account) {
        this.phone = account.phone;
        this.phoneMask = this.phone.length >= 7 ? `${this.phone.slice(0, 3)}****${this.phone.slice(-4)}` : this.phone;
        this.auth = account.auth;
        this.dsid = '';
        this.csrf = '';
        this.location = '';
    }

    // 步骤 1: 云盘中枢换取 017018 netToken（双通道自愈：直连 + 全球通 001191 跳板）
    async fetchNetToken() {
        const url = 'https://orches.yun.139.com/orchestration/auth-rebuild/token/v1.0/querySpecToken';
        const headers = {
            'Authorization': this.auth,
            'Content-Type': 'application/json',
            'Host': 'orches.yun.139.com',
            'User-Agent': DEFAULT_UA,
        };

        const isNonCmcc = this.phone && (this.phone.startsWith('155') || this.phone.startsWith('185') || this.phone.startsWith('186') || this.phone.endsWith('4411'));

        if (!isNonCmcc) {
            try {
                const body = JSON.stringify({ account: this.phone, toSourceId: '017018' });
                const res = await $.http.post({ url, headers, body });
                if (res.statusCode === 200) {
                    const json = JSON.parse(res.body);
                    if (json.success && json.data && json.data.token) {
                        return json.data.token;
                    }
                }
            } catch (e) {}
        }

        // 备用通道: 全球通 001191 换票跳板（支持异网及受限号段）
        $.log('👉 启动全球通 001191 换票跳板...');
        const bodyQqt = JSON.stringify({ account: this.phone, toSourceId: '001191' });
        const resQqt = await $.http.post({ url, headers, body: bodyQqt });
        if (resQqt.statusCode !== 200) {
            throw new Error(`全球通换票失败 (HTTP ${resQqt.statusCode}): ${resQqt.body}`);
        }
        const jsonQqt = JSON.parse(resQqt.body);
        const ssoToken = jsonQqt?.data?.token || jsonQqt?.token;
        if (!ssoToken) {
            throw new Error(`未能获取全球通 SSO Token: ${resQqt.body}`);
        }

        const loginUrl = `https://qqt.cmicrwx.cn/2016tyjf/xhmqqthy/new/ssoTokenLogin.action?backUrl=${encodeURIComponent('https://qqt.cmicrwx.cn/2016tyjf/xhmqqthy/res/wap/xdractivity.html?sspId=66420&enableShare=1')}&token=${ssoToken}&targetSourceId=001191`;
        const resLogin = await $.http.get({ url: loginUrl, headers: { 'User-Agent': DEFAULT_UA }, followRedirect: false });
        let qqtCookie = '';
        const rawCookies = resLogin.headers['set-cookie'] || resLogin.headers['Set-Cookie'] || '';
        if (Array.isArray(rawCookies)) {
            qqtCookie = rawCookies.map(c => String(c).split(';')[0]).join('; ');
        } else if (rawCookies) {
            qqtCookie = String(rawCookies).split(';')[0];
        }

        const resCmp = await $.http.post({
            url: 'https://qqt.cmicrwx.cn/2016tyjf/xhmqqthy/getCmpSSOTokenNew.action',
            headers: {
                'User-Agent': DEFAULT_UA,
                'Referer': 'https://qqt.cmicrwx.cn/2016tyjf/xhmqqthy/res/wap/xdractivity.html?sspId=66420&enableShare=1',
                'Origin': 'https://qqt.cmicrwx.cn',
                'Content-Type': 'application/json',
                'Cookie': qqtCookie
            },
            body: JSON.stringify({ targetid: '017018' })
        });
        const cmpJson = JSON.parse(resCmp.body);
        if (cmpJson && cmpJson.data) {
            $.log('✅ 全球通跳板置换 netToken 成功！');
            return cmpJson.data;
        }

        throw new Error(`换取大网互通票据失败: ${resCmp.body}`);
    }

    // 步骤 2: 访问 netUni 置换网厅 d.sid
    async fetchDsid(netToken) {
        const targetBack = 'https://wx.10086.cn/hlwyxhdhub/act-wedrecharge/1024101716?pageld=1849008675699650560&channelId=P00000017499';
        const netUniUrl = `https://wx.10086.cn/website/sso/netUni?netUniBackUrl=${encodeURIComponent(targetBack)}&net_token=${netToken}`;
        
        const res = await $.http.get({
            url: netUniUrl,
            headers: { 'User-Agent': DEFAULT_UA },
            followRedirect: false
        });

        const rawSetCookie = res.headers['set-cookie'] || res.headers['Set-Cookie'] || '';
        const cookieStr = Array.isArray(rawSetCookie) ? rawSetCookie.join('; ') : String(rawSetCookie);
        const m = cookieStr.match(/d\.sid=([^;]+)/);
        if (m) {
            this.dsid = m[1];
            return this.dsid;
        }

        if (res.headers['location'] || res.headers['Location']) {
            const loc = res.headers['location'] || res.headers['Location'];
            const mLoc = loc.match(/d\.sid=([^&;]+)/);
            if (mLoc) {
                this.dsid = mLoc[1];
                return this.dsid;
            }
        }

        throw new Error(`netUni 未返回 d.sid 会话凭据 (HTTP ${res.statusCode})`);
    }

    // 步骤 3: 访问网厅首页加载并提取 csrf
    async fetchHomeCsrf() {
        const res = await $.http.get({
            url: 'https://wx.10086.cn/website/spa/main/newHome',
            headers: {
                'User-Agent': DEFAULT_UA,
                'Cookie': `d.sid=${this.dsid}`
            }
        });

        if (res.statusCode !== 200 || (res.body && res.body.includes('系统繁忙，请稍后再试'))) {
            throw new Error(`网厅首页鉴权失败 (状态码: ${res.statusCode})`);
        }

        const csrfM = res.body ? res.body.match(/["']csrf["']\s*:\s*["']([^"']+)["']/) : null;
        if (csrfM) {
            this.csrf = csrfM[1];
        }

        const userM = res.body ? res.body.match(/var\s+user\s*=\s*(\{.*?\});/) : null;
        if (userM) {
            try {
                const u = JSON.parse(userM[1]);
                if (u.province_city) {
                    this.location = `${u.province_city.province || ''} ${u.province_city.city || ''}`.trim();
                }
            } catch {}
        }
        return this.csrf;
    }

    // 步骤 0: 检查云盘根凭据有效期并在临期时全自动续期
    async checkAndRefreshToken() {
        const info = parseMcloudToken(this.auth);
        if (!info || !info.phone) return;
        if (info.expireAt > 0 && info.remDays !== null) {
            if (info.remDays <= 7) {
                $.log(`🔄【云盘凭据临期】账号 ${this.phoneMask} 凭据剩余 ${info.remDays.toFixed(1)} 天 (≤7天)，正在全自动调用官方 refreshToken 续期 30 天...`);
                const refreshed = await refreshCloudToken(this.auth, info.phone, info.clientType);
                if (refreshed && refreshed.success && refreshed.newAuth) {
                    this.auth = refreshed.newAuth;
                    const newRem = refreshed.expireAt > 0 ? (refreshed.expireAt - Date.now()) / (1000 * 86400) : 30;
                    $.log(`🌟【云盘凭据续期成功】账号 ${this.phoneMask} 已换发新凭据 (有效期顺延至 ${newRem.toFixed(1)} 天后)，并自动同步写回存储！`);
                    updateAccountTokenInStorage(info.phone, refreshed.newAuth);
                } else {
                    $.log(`⚠️【云盘凭据续期失败】${refreshed?.message || '未知异常'}`);
                }
            } else {
                $.log(`ℹ️【云盘凭据检查】账号 ${this.phoneMask} 根凭据有效，剩余 ${info.remDays.toFixed(1)} 天`);
            }
        }
    }

    // 步骤 4 & 5: 综合余量查询
    async queryAll() {
        $.log(`\n================ 正在查询: ${this.phoneMask} ================`);
        await this.checkAndRefreshToken();
        $.log('👉 [1/3] 正在置换大网专线 017018 互通票据...');
        const netToken = await this.fetchNetToken();
        
        $.log('👉 [2/3] 正在置换大网网关凭据 d.sid...');
        await this.fetchDsid(netToken);
        
        $.log('👉 [3/3] 正在加载网厅授权并提取 CSRF 令牌...');
        await this.fetchHomeCsrf();
        $.log(`✅【网厅鉴权成功】d.sid: ${this.dsid.slice(0, 8)}... | 归属地: ${this.location || '中国移动'}`);

        const traceId = genTraceId();
        const baseHeaders = {
            'User-Agent': DEFAULT_UA,
            'Referer': 'https://wx.10086.cn/website/spa/main/newHome',
            'Origin': 'https://wx.10086.cn',
            'Cookie': `d.sid=${this.dsid}`,
            'csrf-token': this.csrf,
            'Lrsbhbg8': STATIC_HEADER_MAGIC,
            'e76ccba5165fa9b4966ad82a0088e520': traceId,
        };

        // 1. 话费查询
        const rFee = await $.http.get({
            url: 'https://wx.10086.cn/website/fareBalance',
            headers: baseHeaders
        });
        const feeData = decryptAesCbc(rFee.body);
        const realFeeRsp = feeData?.data?.realFeeQryRsp || {};

        // 2. 流量与通话查询
        const rMargin = await $.http.post({
            url: 'https://wx.10086.cn/website/uniApi/getNewMarginInfo',
            headers: Object.assign({}, baseHeaders, {
                'Content-Type': 'application/json;charset=UTF-8',
                'Accept': 'application/json, text/plain, */*'
            }),
            body: '{}'
        });
        const marginData = decryptAesCbc(rMargin.body);
        const resData = marginData?.data?.resultData || {};

        // 整理结果
        const flowInfo = resData.planRemianFlowInfo || {};
        const voiceInfo = resData.planRemianVoiceInfo || {};

        const totFlow = flowInfo.totalInfo || {};
        const genFlow = flowInfo.planRemian || {};
        const dirFlow = flowInfo.directionalFlowInfo || {};
        const totVoice = voiceInfo.totalInfo || {};

        const result = {
            phoneMask: this.phoneMask,
            location: this.location,
            balance: realFeeRsp.curFeeTotal || '0.00',
            realFee: realFeeRsp.realFee || '0.00',
            payType: realFeeRsp.payType || '预付费',
            flow: {
                totalRemain: formatFlow(totFlow.remainNum, totFlow.unit),
                totalSum: formatFlow(totFlow.sumNum, totFlow.unit),
                totalUsed: formatFlow(totFlow.usedNum, totFlow.unit),
                genRemain: formatFlow(genFlow.remainNum, genFlow.unit),
                genSum: formatFlow(genFlow.sumNum, genFlow.unit),
                dirRemain: formatFlow(dirFlow.remainNum, dirFlow.unit),
                dirSum: formatFlow(dirFlow.sumNum, dirFlow.unit),
            },
            voice: {
                remain: totVoice.remainNum || '0',
                sum: totVoice.sumNum || '0',
                used: totVoice.usedNum || '0',
            },
            rawTotFlow: totFlow,
            rawGenFlow: genFlow,
            rawDirFlow: dirFlow,
            rawTotVoice: totVoice
        };

        return result;
    }
}

// ---------------------- 报告渲染 ----------------------
function renderReport(r) {
    const lines = [
        `📱 中国移动网厅余量报告 (${r.phoneMask})`,
    ];
    if (r.location) lines.push(`归属地: ${r.location}`);
    lines.push('───────────────────────');
    lines.push(`💰 话费余额: ${r.balance} 元`);
    lines.push(`   实时消费: ${r.realFee} 元 (当月)`);
    lines.push(`   付费类型: ${r.payType}`);
    lines.push('───────────────────────');
    lines.push('📶 流量使用:');
    lines.push(`   • 总流量: 剩余 ${r.flow.totalRemain} / ${r.flow.totalSum} (已用 ${r.flow.totalUsed})`);
    lines.push(`   • 通用流量: 剩余 ${r.flow.genRemain} / ${r.flow.genSum}`);
    if (r.flow.dirSum && r.flow.dirSum !== '0 MB') {
        lines.push(`   • 定向流量: 剩余 ${r.flow.dirRemain} / ${r.flow.dirSum}`);
    }
    lines.push('───────────────────────');
    lines.push(`📞 语音通话: 剩余 ${r.voice.remain} 分钟 / ${r.voice.sum} 分钟 (已用 ${r.voice.used} 分钟)`);
    lines.push('───────────────────────');
    lines.push(`查询时间: ${new Date().toLocaleString()}`);
    return lines.join('\n');
}

// ---------------------- 主入口 ----------------------
!(async () => {
    $.log('🔔 [中国移动] 脚本启动，准备执行官方网厅综合余量查询...');

    const accounts = getAccountList();
    if (accounts.length === 0) {
        $.log('\n❌【未检测到有效的移动云盘根凭据】');
        $.log('👉 填写指引：');
        $.log('1. 在 BoxJS 中找到【中国移动】应用配置面板；');
        $.log('2. 在「移动云盘根凭据」字段中填入云盘 Authorization 凭据（以 Basic 开头）；');
        $.log('3. 多账号可换行填写；手机号留空即可自动识别；');
        $.log('4. 保存设置后，再次点击「运行」即可！\n');
        
        await $.msg($.name, '❌ 无法执行', '未找到有效凭据，请在 BoxJS 中配置移动云盘根凭据');
        $.done();
        return;
    }

    const isSilent = String($.getdata('china_mobile_silent') || (typeof process !== 'undefined' && process.env ? process.env.CHINA_MOBILE_SILENT : '')).toLowerCase() === 'true';
    const barkKey = $.getdata('china_mobile_bark_key') || $.getdata('BARK_KEY') || (typeof process !== 'undefined' && process.env ? process.env.CHINA_MOBILE_BARK_KEY : '') || '';

    $.log(`🚀 检测到 ${accounts.length} 个账号，开始全自动 SSO 营业厅余量查询...`);

    const summaries = [];
    let successCount = 0;

    for (const acc of accounts) {
        const client = new CmccService(acc);
        try {
            const data = await client.queryAll();
            const report = renderReport(data);
            $.log(`\n${report}\n`);
            summaries.push(`【${data.phoneMask}】余额: ${data.balance}元 | 剩余流量: ${data.flow.totalRemain} | 剩余通话: ${data.voice.remain}分`);
            successCount++;

            // 优先选择「通用流量」（最核心的可用流量）；若通用流量为空则回退到总流量
            const activeFlow = (data.rawGenFlow && data.rawGenFlow.remainNum !== undefined && data.rawGenFlow.remainNum !== '') ? data.rawGenFlow : data.rawTotFlow;

            // 构造标准 Scriptable 桌面小组件缓存数据结构
            const scriptableData = {
                fee: { curFee: String(data.balance || '0.00') },
                plan: {
                    planRemianFlowListRes: {
                        limitType: '01',
                        state: '00',
                        planRemianFlowRes: [
                            {
                                flowtype: '0',
                                flowRemainNum: String(activeFlow?.remainNum || '0'),
                                flowSumNum: String(activeFlow?.sumNum || '0'),
                                flowUsdNum: String(activeFlow?.usedNum || '0'),
                                unit: (activeFlow?.unit === '04' || activeFlow?.unit === 'GB') ? '04' : '03'
                            }
                        ]
                    },
                    planRemianVoiceListRes: {
                        planRemianVoiceInfoRes: [
                            {
                                voicetype: '0',
                                voiceRemainNum: String(data.rawTotVoice?.remainNum || '0'),
                                voiceSumNum: String(data.rawTotVoice?.sumNum || '0'),
                                voiceUsdNum: String(data.rawTotVoice?.usedNum || '0'),
                                unit: '分钟'
                            }
                        ]
                    }
                }
            };

            // 写入全域 BoxJS 存储供 Scriptable 立即读取
            $.setdata(JSON.stringify(scriptableData), 'china_mobile_cache');
            $.setdata(JSON.stringify(scriptableData), 'balanceData');
            if (client.phone) {
                $.setdata(JSON.stringify(scriptableData), `china_mobile_cache_${client.phone}`);
                $.setdata(JSON.stringify(scriptableData), `china_mobile_cache_${client.phone.slice(-4)}`);
            }
        } catch (e) {
            $.log(`❌ 查询失败: ${e.message}`);
            summaries.push(`【${client.phoneMask}】查询异常: ${e.message}`);
        }
        await $.wait(1500);
    }

    const title = `中国移动网厅余量 (${successCount}/${accounts.length} 成功)`;
    const body = summaries.join('\n');
    $.log(`\n================ 汇总报告 ================\n${body}\n`);

    // 1. BoxJS / 系统通知推送（若开启静默模式则跳过常规通知）
    if (!isSilent) {
        await $.msg(title, '', body);
    }

    // 2. Bark 独立直推（若配置了 china_mobile_bark_key）
    if (barkKey) {
        try {
            const barkUrl = `https://api.day.app/${barkKey}/${encodeURIComponent(title)}/${encodeURIComponent(body)}?group=10086&icon=https%3A%2F%2Fraw.githubusercontent.com%2FOrz-3%2Fmini%2Fmaster%2FAlpha%2F10086.png`;
            await $.http.get({ url: barkUrl });
            $.log('✅ Bark 推送成功');
        } catch (e) {
            $.log('Bark 推送失败: ' + e.message);
        }
    }
})()
    .catch((e) => {
        $.log(`\n❌ [全局异常] ${e.message}\n${e.stack || ''}`);
    })
    .finally(() => {
        // 若当前处于代理重写（如 Quantumult X / Surge / Loon 拦截 api.example.com/10086/query）
        if (typeof $request !== 'undefined' && $request.url && $request.url.includes('/10086/query')) {
            const cachedData = $.getdata('china_mobile_cache') || '{}';
            $.done({
                response: {
                    status: 200,
                    headers: { 'Content-Type': 'application/json; charset=utf-8' },
                    body: cachedData
                }
            });
            return;
        }
        $.done();
    });

// ---------------------- 跨平台环境适配器 (针对 BoxJS / Surge / Loon / QX 深度优化) ----------------------
function Env(name) {
    const isNode = typeof module !== 'undefined' && !!module.exports;
    const isSurge = typeof $httpClient !== 'undefined' && typeof $loon === 'undefined';
    const isLoon = typeof $loon !== 'undefined';
    const isQX = typeof $task !== 'undefined';

    return {
        name,
        isNode: () => isNode,
        isSurge: () => isSurge,
        isLoon: () => isLoon,
        isQX: () => isQX,
        log: (...args) => console.log(...args),
        getdata: (key) => {
            if (isSurge || isLoon) return $persistentStore.read(key);
            if (isQX) return $prefs.valueForKey(key);
            if (isNode) return (process.env && process.env[key]) || '';
            return '';
        },
        setdata: (val, key) => {
            if (isSurge || isLoon) return $persistentStore.write(val, key);
            if (isQX) return $prefs.setValueForKey(val, key);
            return false;
        },
        wait: (t) => new Promise(r => setTimeout(r, t)),
        http: {
            get: (opts) => requestAdapter('GET', opts),
            post: (opts) => requestAdapter('POST', opts),
        },
        msg: async (title, subtitle, message) => {
            console.log(`[通知] ${title} | ${subtitle || ''} | ${message || ''}`);
            if (isNode) {
                try {
                    const sendNotify = require('./sendNotify');
                    await sendNotify.sendNotify(title, `${subtitle ? subtitle + '\n' : ''}${message}`);
                    return;
                } catch {}
            }
            if (isSurge || isLoon) {
                $notification.post(title, subtitle, message);
            } else if (isQX) {
                $notify(title, subtitle, message);
            }
        },
        done: (val = {}) => {
            if (isQX) $done(val);
            if (isSurge || isLoon) $done(val);
        }
    };

    function requestAdapter(method, opts) {
        opts.method = method;
        // Node.js 原生请求
        if (isNode) {
            const https = require('https');
            const http = require('http');
            return new Promise((resolve, reject) => {
                const u = new URL(opts.url);
                const isHttps = u.protocol === 'https:';
                const client = isHttps ? https : http;
                const reqOpt = {
                    protocol: u.protocol,
                    hostname: u.hostname,
                    port: u.port || (isHttps ? 443 : 80),
                    path: u.pathname + u.search,
                    method: opts.method,
                    headers: opts.headers || {},
                    ciphers: 'DEFAULT@SECLEVEL=1',
                };
                const req = client.request(reqOpt, (res) => {
                    const chunks = [];
                    res.on('data', c => chunks.push(c));
                    res.on('end', () => {
                        resolve({
                            statusCode: res.statusCode,
                            headers: res.headers,
                            body: Buffer.concat(chunks).toString('utf8'),
                        });
                    });
                });
                req.on('error', reject);
                if (opts.body) {
                    req.write(typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body));
                }
                req.end();
            });
        }
        // Quantumult X 原生请求
        if (isQX) {
            if (opts.followRedirect === false) {
                opts.opts = opts.opts || {};
                opts.opts.redirection = false;
            }
            return new Promise((resolve, reject) => {
                $task.fetch(opts).then(response => {
                    resolve({
                        statusCode: response.statusCode,
                        headers: response.headers,
                        body: response.body
                    });
                }, reason => reject(reason.error || reason));
            });
        }
        // Surge & Loon 原生请求
        if (isSurge || isLoon) {
            if (opts.followRedirect === false) {
                opts['auto-redirect'] = false;
            }
            return new Promise((resolve, reject) => {
                const fn = method.toLowerCase() === 'post' ? $httpClient.post : $httpClient.get;
                fn(opts, (err, resp, body) => {
                    if (err) reject(err);
                    else resolve({
                        statusCode: (resp && (resp.status || resp.statusCode)) || 200,
                        headers: (resp && resp.headers) || {},
                        body: body || ''
                    });
                });
            });
        }
    }
}
