// Szyfruje src/report.html do index.html (AES-256-GCM, klucz z PBKDF2-SHA256).
// Użycie: SF_PAGE_PASSWORD=... node build.mjs
import { readFileSync, writeFileSync } from "node:fs";
import { webcrypto as crypto } from "node:crypto";

const password = process.env.SF_PAGE_PASSWORD;
if (!password) throw new Error("Brak SF_PAGE_PASSWORD");
const ITER = 600000;
const plain = readFileSync(new URL("./src/report.html", import.meta.url), "utf8");
const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: ITER, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plain)));
const b64 = (u) => Buffer.from(u).toString("base64");

const page = `<!doctype html>
<html lang="pl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>SimFactor — raport z postępu</title>
<style>
:root{--bg:#fbfaf7;--ink:#1f1e1b;--ink3:#8a867c;--line:#e4e0d6;--accent:#2c55c8;--res:#bf3b27}
@media (prefers-color-scheme: dark){:root{--bg:#151513;--ink:#ece9e1;--ink3:#848176;--line:#33322d;--accent:#86a3f6;--res:#ef806c}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;padding:16px}
form{width:100%;max-width:360px}h1{font:700 24px/1.2 Georgia,serif;margin:0 0 6px}p{color:var(--ink3);margin:0 0 20px;font-size:14px}
input[type=password]{width:100%;font:inherit;padding:13px 14px;border:1px solid var(--line);border-radius:10px;background:transparent;color:var(--ink)}
button{width:100%;margin-top:10px;font-weight:600;font-size:16px;font-family:inherit;padding:13px;border:0;border-radius:10px;background:var(--accent);color:#fff;cursor:pointer}
label{display:flex;gap:8px;align-items:center;margin-top:12px;font-size:14px;color:var(--ink3)}#err{color:var(--res);font-size:14px;min-height:22px;margin-top:8px}
</style></head><body>
<form id="f" autocomplete="on">
<h1>SimFactor</h1><p>Raport z postępu projektu. Dostęp chroniony hasłem.</p>
<input type="password" id="pw" placeholder="Hasło" autocomplete="current-password" autofocus required>
<button type="submit" id="go">Otwórz raport</button>
<label><input type="checkbox" id="rem" checked> Zapamiętaj na tym urządzeniu</label>
<div id="err" role="alert"></div>
</form>
<script>
(()=>{
const S="${b64(salt)}",I="${b64(iv)}",C="${b64(ct)}",N=${ITER};
const u=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
async function decryptPage(pw){
  const base=await crypto.subtle.importKey("raw",new TextEncoder().encode(pw),"PBKDF2",false,["deriveKey"]);
  const key=await crypto.subtle.deriveKey({name:"PBKDF2",salt:u(S),iterations:N,hash:"SHA-256"},base,{name:"AES-GCM",length:256},false,["decrypt"]);
  return new TextDecoder().decode(await crypto.subtle.decrypt({name:"AES-GCM",iv:u(I)},key,u(C)));
}
function show(html){const h=location.hash;document.open();document.write(html);document.close();
  if(h)setTimeout(()=>{const el=document.getElementById(h.slice(1));if(el)el.scrollIntoView();},400);}
async function tryPw(pw,remember){
  try{const html=await decryptPage(pw);if(remember){try{localStorage.setItem("sf_pw",pw)}catch(e){}}show(html);return true;}
  catch(e){return false;}
}
document.getElementById("f").addEventListener("submit",async e=>{e.preventDefault();
  const b=document.getElementById("go");b.disabled=true;b.textContent="Otwieram…";
  const ok=await tryPw(document.getElementById("pw").value,document.getElementById("rem").checked);
  if(!ok){b.disabled=false;b.textContent="Otwórz raport";document.getElementById("err").textContent="Nieprawidłowe hasło.";}
});
(async()=>{let p=null;if(location.hash.startsWith("#k=")){const k=decodeURIComponent(location.hash.slice(3));history.replaceState(null,"",location.pathname);if(await tryPw(k,true))return;document.getElementById("err").textContent="Klucz w linku jest nieprawidłowy.";}
  try{p=localStorage.getItem("sf_pw")}catch(e){}
  if(p&&!(await tryPw(p,false))){try{localStorage.removeItem("sf_pw")}catch(e){}}})();
})();
</script>
</body></html>
`;
writeFileSync(new URL("./index.html", import.meta.url), page);
console.log("index.html", page.length, "B; ciphertext", ct.length, "B");
