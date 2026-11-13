// Local login form for the extension test: node page.mjs [port] (default 8765, 127.0.0.1 only).
import http from "node:http";

const port = Number(process.argv[2] ?? 8765);
const html = `<!doctype html><title>Login</title>
<form id=f method=post action="/done">
  <input id=u name=username autocomplete=username>
  <input id=p name=password type=password autocomplete=current-password>
  <button type=submit>Sign in</button>
</form>`;

http
  .createServer((req, res) => {
    res.writeHead(200, { "content-type": "text/html" });
    res.end(req.url.startsWith("/done") ? "done" : html);
  })
  .listen(port, "127.0.0.1", () => console.log(`page on ${port}`));
