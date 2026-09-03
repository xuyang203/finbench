// 韭圈儿大盘恐贪指数 + 6 大成分指标 代理 Worker
// 浏览器定时 fetch 本 Worker 即可实现「纯前端自动更新」，不依赖 WorkBuddy。
// 服务端完成 fadrefa 签名 + AES-256-CBC(crypto-js) 解密，authtoken 只留服务端（env.JQK_TOKEN），绝不下发前端。
//
// 部署：
//   1) cd cloudflare-worker && npm install
//   2) npx wrangler secret put JQK_TOKEN   （粘贴你的 authtoken；切勿写进本文件或提交到仓库）
//   3) npx wrangler deploy
//   4) 把你的 Worker 地址填进 finbench-main/index.html 的 JQK_WORKER_URL（形如 https://jqk.xxx.workers.dev/jqk）

import CryptoJS from 'crypto-js';

const SALT = 'EWf45rlv#kfsr@k#gfksgkr';
const VERSION = '2.2.7';
const BASE = 'https://api.jiucaishuo.com';
const KEY_BASE = 'eveqocftukbotqjcequcnkrqlw1oi'; // H.e()
const IV_BASE  = 'bvroqevdjqibsdkq';               // H.a()

// 真实 b 函数（app.fear.js 逐字，32 子串 -> 32 混淆字段）
function realB(t, e, n, a, i, o, r, u, l, c, s, d, _, f, h, p, m, g, v, y, b, k, w, x, j, P, z, q, E, H, O, A, C) {
  t.data.tirgkjfs = f; t.data.abiokytke = _; t.data.u54rg5d = e; t.data.kf54ge7 = q;
  t.data.tiklsktr4 = d; t.data.lksytkjh = P; t.data.sbnoywr = z; t.data.bgd7h8tyu54 = w;
  t.data.y654b5fs3tr = O; t.data.bioduytlw = n; t.data.bd4uy742 = j; t.data.h67456y = r;
  t.data.bvytikwqjk = s; t.data.ngd4uy551 = b; t.data.bgiuytkw = v; t.data.nd354uy4752 = g;
  t.data.ghtoiutkmlg = x; t.data.bd24y6421f = a; t.data.tbvdiuytk = u; t.data.ibvytiqjek = p;
  t.data.jnhf8u5231 = C; t.data.fjlkatj = A; t.data.hy5641d321t = E; t.data.iogojti = o;
  t.data.ngd4yut78 = i; t.data.nkjhrew = c; t.data.yt447e13f = H; t.data.n3bf4uj7y7 = k;
  t.data.nbf4uj7y432 = h; t.data.yi854tew = l; t.data.h13ey474 = m; t.data.quikgdky = y;
}

function md5(o) { return CryptoJS.MD5(String(o)).toString(); }

function sign(data) {
  data.type = 'pc'; data.version = VERSION; data.act_time = +new Date();
  const keys = Object.keys(data).sort();
  let o = '';
  for (const r of keys) {
    let val = data[r];
    if (val == null) { data[r] = ''; val = ''; }
    if ((!val && val !== 0) || typeof val === 'object') continue;
    o += String(val);
  }
  o += SALT;
  const u = md5(o);
  const c = u.substr(29, 2), d = u.substr(2, 2), f = u.substr(5, 1), h = u.substr(26, 1),
    m = u.substr(6, 2), v = u.substr(1, 1), y = u.substr(0, 2), k = u.substr(6, 2),
    w = u.substr(8, 1), x = u.substr(30, 1), j = u.substr(11, 3), P = u.substr(11, 1),
    z = u.substr(2, 3), q = u.substr(9, 2), E = u.substr(23, 2), H = u.substr(31, 1),
    O = u.substr(25, 2), A = u.substr(9, 2), C = u.substr(27, 2), T = u.substr(17, 2),
    I = u.substr(26, 1), U = u.substr(12, 2), S = u.substr(25, 1), R = u.substr(16, 3),
    F = u.substr(17, 4), B = u.substr(18, 1), K = u.substr(21, 2), D = u.substr(14, 2),
    dollar = u.substr(29, 3), N = u.substr(21, 2), V = u.substr(24, 2), L = u.substr(16, 1);
  realB({ data }, d, f, V, U, S, R, L, c, h, m, v, N, y, K, D, dollar, x, A, C, T, B, k, j, I, F, E, H, O, w, P, z, q);
  return data;
}

// 解密：override 必须仅作用于 AES 的 key/iv parse，绝不可污染 MD5（MD5 内部也走 enc.Utf8.parse）
function decrypt(t, H, O) {
  const _p = O.enc.Utf8.parse.bind(O.enc.Utf8);
  const origParse = O.enc.Utf8.parse, origDecrypt = O.AES.decrypt;
  O.enc.Utf8.parse = (xx) => _p(xx + '1');
  O.AES.decrypt = (tt, ee, nn) => { ee = O.enc.Utf8.parse(ee + 'll'); nn.iv = O.enc.Utf8.parse(nn.iv + 'll'); return origDecrypt(tt, ee, nn); };
  let res = null;
  try {
    const e = { iv: H.a(), mode: O.mode.CBC, padding: O.pad.Pkcs7 }, n = H.e();
    res = JSON.parse(O.AES.decrypt(t, n, e).toString(O.enc.Utf8));
  } catch (err) { res = null; }
  finally { O.enc.Utf8.parse = origParse; O.AES.decrypt = origDecrypt; }
  return res;
}

async function postSigned(path_, extra) {
  const data = Object.assign({ authtoken: TOKEN }, extra || {});
  sign(data);
  const r = await fetch(BASE + path_, {
    method: 'POST',
    headers: { 'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  const j = await r.json();
  const ct = (typeof j === 'string') ? j : (j && j.data);
  if (!ct) throw new Error('empty ciphertext @' + path_ + ': ' + JSON.stringify(j).slice(0, 120));
  const obj = decrypt(ct, { e: () => KEY_BASE, a: () => IV_BASE }, CryptoJS);
  if (!obj) throw new Error('decrypt fail @' + path_);
  return obj;
}

// 6 大成分维度 id（与 getalltypes 对齐）
const COMP_IDS = [1, 2, 3, 4, 5, 6];

let _cache = null, _cacheAt = 0;
let TOKEN = '';

async function getJqk(token) {
  TOKEN = token;
  const now = Date.now();
  if (_cache && now - _cacheAt < 5 * 60 * 1000) return _cache; // 5 分钟内复用，避免频繁打韭圈儿

  // 1) 主指数
  const base = await postSigned('/v2/kjtl/getbasedata', {});
  const bd = base.data || base;
  const main = {
    value: (typeof bd.num === 'number') ? bd.num : null,
    status: bd.status_str || null,
    date: bd.current_time || null
  };

  // 2) 成分短名映射（getalltypes 明文，无需签名）
  const labels = {};
  try {
    const ra = await fetch(BASE + '/v2/kjtl/getalltypes', {
      method: 'POST',
      headers: { 'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json' },
      body: JSON.stringify({ authtoken: token })
    });
    const ja = await ra.json();
    (ja.data || []).forEach(x => { if (x && x.id != null) labels[x.id] = (x.name || '').split('：')[0] || x.name; });
  } catch (e) { /* labels 缺失不致命 */ }

  // 3) 逐成分取值
  const components = [];
  for (const id of COMP_IDS) {
    try {
      const li = await postSigned('/v2/kjtl/getlist', { id });
      const d = li.data || li;
      const ser = d.canvas_data && d.canvas_data.series && d.canvas_data.series[0] && d.canvas_data.series[0].data;
      const last = Array.isArray(ser) && ser.length ? ser[ser.length - 1] : null;
      const val = Array.isArray(last) ? last[1] : (typeof last === 'number' ? last : null);
      components.push({
        id,
        name: labels[id] || (d.title ? d.title.split('：')[0] : ('成分' + id)),
        full: d.title || null,
        value: (typeof val === 'number') ? val : null,
        unit: (d.canvas_data && d.canvas_data.y_company) || '',
        status: d.status_name || null,
        color: d.status_color || null
      });
    } catch (e) { /* 单成分失败跳过 */ }
  }

  const out = {
    main,
    components,
    updatedAt: new Date().toISOString(),
    source: 'jiucaishuo kjtl'
  };
  _cache = out; _cacheAt = now;
  return out;
}

export default {
  async fetch(request, env) {
    const headers = {
      'Access-Control-Allow-Origin': '*',
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=300'
    };
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers });
    try {
      if (!env.JQK_TOKEN) throw new Error('JQK_TOKEN 未配置（wrangler secret put JQK_TOKEN）');
      const out = await getJqk(env.JQK_TOKEN);
      return new Response(JSON.stringify(out), { status: 200, headers });
    } catch (e) {
      return new Response(JSON.stringify({ error: String(e.message) }), { status: 502, headers });
    }
  }
};
