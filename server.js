// 东岳阁课程站：静态文件服务 + 单一浏览密码入口
// 密码通过环境变量 SITE_PASSWORD 设置，不写入代码与仓库；
// 输对密码后种下 Cookie，之后即可正常浏览全部课程。
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT = __dirname;
const PORT = process.env.PORT || 10000;
const PASSWORD = process.env.SITE_PASSWORD || "";
const COOKIE_NAME = "dongyue_pass";
const TOKEN = crypto.createHash("sha256").update(PASSWORD).digest("hex");

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".htm": "text/html; charset=utf-8",
  ".md": "text/markdown; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".yaml": "text/plain; charset=utf-8",
  ".yml": "text/plain; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
};

const LOGIN_PAGE = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>浏览密码</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f5efe2;font-family:"Noto Serif SC","Songti SC",SimSun,serif;color:#2b2723}
.card{background:#fbf6ea;border:1px solid #d8ccb4;border-radius:12px;padding:42px 46px;width:min(92vw,360px);text-align:center;box-shadow:0 10px 30px rgba(74,56,34,.12)}
p{color:#2b2723;font-size:17px;letter-spacing:.2em;margin:0 0 24px}
input{width:100%;box-sizing:border-box;padding:12px 14px;font-size:16px;border:1px solid #c9bda5;border-radius:8px;background:#fffdf6;text-align:center;letter-spacing:.2em;outline:none}
input:focus{border-color:#9c3a28}
button{margin-top:16px;width:100%;padding:12px;font-size:16px;letter-spacing:.3em;background:#9c3a28;color:#f7eeda;border:none;border-radius:8px;cursor:pointer;font-family:inherit}
button:hover{background:#7c2d1e}
.err{color:#9c3a28;font-size:13px;margin-top:14px}
</style>
</head>
<body>
<div class="card">
<p>请输入浏览密码</p>
<form method="post" action="/login">
<input type="password" name="password" placeholder="密码" autofocus autocomplete="current-password">
<button type="submit">进 入</button>
</form>
<div class="err">__ERROR__</div>
</div>
</body>
</html>`;

function loginPage(error) {
  return LOGIN_PAGE.replace("__ERROR__", error ? "密码不正确，请重试" : "");
}

function hasValidCookie(req) {
  const raw = req.headers.cookie || "";
  return raw.split(";").some((part) => {
    const i = part.indexOf("=");
    const name = i >= 0 ? part.slice(0, i).trim() : part.trim();
    const value = i >= 0 ? part.slice(i + 1).trim() : "";
    return name === COOKIE_NAME && value === TOKEN;
  });
}

function readBody(req, cb) {
  let body = "";
  req.on("data", (chunk) => {
    body += chunk;
    if (body.length > 1024 * 1024) req.destroy();
  });
  req.on("end", () => cb(body));
}

function parseForm(body) {
  const params = {};
  for (const pair of body.split("&")) {
    const i = pair.indexOf("=");
    if (i < 0) continue;
    const k = decodeURIComponent(pair.slice(0, i).replace(/\+/g, " "));
    const v = decodeURIComponent(pair.slice(i + 1).replace(/\+/g, " "));
    params[k] = v;
  }
  return params;
}

function setCookieHeader(req) {
  const secure = req.headers["x-forwarded-proto"] === "https" ? "; Secure" : "";
  return `${COOKIE_NAME}=${TOKEN}; Path=/; HttpOnly; SameSite=Lax${secure}`;
}

function serveFile(res, filePath) {
  fs.stat(filePath, (err, st) => {
    if (err || !st.isFile()) {
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      return res.end("Not Found");
    }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, {
      "Content-Type": MIME[ext] || "application/octet-stream",
      "Cache-Control": "no-store",
    });
    fs.createReadStream(filePath).pipe(res);
  });
}

const server = http.createServer((req, res) => {
  let urlPath;
  try {
    urlPath = decodeURIComponent(new URL(req.url, "http://localhost").pathname);
  } catch {
    urlPath = "/";
  }

  if (urlPath === "/login") {
    if (req.method === "POST") {
      readBody(req, (body) => {
        const pass = parseForm(body).password || "";
        if (pass === PASSWORD) {
          res.writeHead(302, { Location: "/", "Set-Cookie": setCookieHeader(req) });
          return res.end();
        }
        res.writeHead(200, {
          "Content-Type": "text/html; charset=utf-8",
          "Cache-Control": "no-store",
        });
        res.end(loginPage(true));
      });
      return;
    }
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
    });
    return res.end(loginPage(false));
  }

  if (!hasValidCookie(req)) {
    res.writeHead(302, { Location: "/login" });
    return res.end();
  }

  if (urlPath === "/") urlPath = "/index.html";
  const filePath = path.normalize(path.join(ROOT, urlPath));
  if (!filePath.startsWith(ROOT)) {
    res.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" });
    return res.end("Forbidden");
  }
  serveFile(res, filePath);
});

server.listen(PORT, () => {
  console.log("dongyue-ge server listening on " + PORT);
});
