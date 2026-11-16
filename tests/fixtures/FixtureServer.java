// A tiny HTTP API for rules_zap's own tests: the JDK's built-in
// com.sun.net.httpserver, so it needs nothing but the JDK ZAP runs on.
//
//   FixtureServer <vulnerable|clean>     listens on 127.0.0.1:$PORT
//
// Both modes serve the same API (tests/fixtures/openapi.yaml, also served
// at /openapi.yaml):
//   GET /api/greet?name=<text>   a greeting
//   GET /api/items/{id}          an item, or 404
// `vulnerable` reflects `name` unescaped into an HTML page: reflected XSS,
// which ZAP's active scan rule 40012 (Cross Site Scripting (Reflected),
// High) finds on every run. `clean` answers JSON, escapes its input, and
// sets the headers ZAP's passive rules look for.
package fixtures;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Executors;

public final class FixtureServer {
    private static boolean vulnerable;
    private static byte[] openapi;

    public static void main(String[] args) throws IOException {
        if (args.length < 2 || !(args[0].equals("vulnerable") || args[0].equals("clean"))) {
            System.err.println("usage: FixtureServer <vulnerable|clean> <openapi.yaml>");
            System.exit(2);
        }
        vulnerable = args[0].equals("vulnerable");
        openapi = Files.readAllBytes(Path.of(args[1]));
        int port = Integer.parseInt(System.getenv("PORT"));
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 64);
        server.createContext("/", FixtureServer::handle);
        server.setExecutor(Executors.newFixedThreadPool(8));
        server.start();
        System.err.println("fixture server (" + args[0] + ") listening on 127.0.0.1:" + port);
    }

    private static void handle(HttpExchange ex) throws IOException {
        try (InputStream in = ex.getRequestBody()) {
            in.readAllBytes();
        }
        String path = ex.getRequestURI().getPath();
        if (!ex.getRequestMethod().equals("GET")) {
            send(ex, 405, "application/json", "{\"error\":\"method not allowed\"}");
        } else if (path.equals("/openapi.yaml")) {
            send(ex, 200, "application/yaml", new String(openapi, StandardCharsets.UTF_8));
        } else if (path.equals("/api/greet")) {
            String name = query(ex, "name");
            if (vulnerable) {
                send(ex, 200, "text/html; charset=utf-8",
                        "<html><body><p>Hello " + name + "</p></body></html>");
            } else {
                send(ex, 200, "application/json", "{\"greeting\":\"Hello " + json(name) + "\"}");
            }
        } else if (path.startsWith("/api/items/")) {
            String id = path.substring("/api/items/".length());
            if (id.matches("[0-9]{1,6}")) {
                send(ex, 200, "application/json", "{\"id\":" + Integer.parseInt(id) + ",\"name\":\"item\"}");
            } else {
                send(ex, 404, "application/json", "{\"error\":\"no such item\"}");
            }
        } else {
            send(ex, 404, "application/json", "{\"error\":\"not found\"}");
        }
    }

    private static String query(HttpExchange ex, String key) {
        String q = ex.getRequestURI().getRawQuery();
        if (q == null) {
            return "";
        }
        for (String kv : q.split("&")) {
            int eq = kv.indexOf('=');
            String k = eq < 0 ? kv : kv.substring(0, eq);
            if (k.equals(key)) {
                return eq < 0 ? "" : URLDecoder.decode(kv.substring(eq + 1), StandardCharsets.UTF_8);
            }
        }
        return "";
    }

    private static String json(String s) {
        StringBuilder b = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') {
                b.append('\\').append(c);
            } else if (c < 0x20 || c == '<' || c == '>' || c == '&' || c > 0x7e) {
                b.append(String.format("\\u%04x", (int) c));
            } else {
                b.append(c);
            }
        }
        return b.toString();
    }

    private static void send(HttpExchange ex, int status, String type, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        var h = ex.getResponseHeaders();
        h.set("Content-Type", type);
        if (!vulnerable) {
            h.set("X-Content-Type-Options", "nosniff");
            h.set("Cache-Control", "no-store");
            h.set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
            h.set("X-Frame-Options", "DENY");
            h.set("Cross-Origin-Resource-Policy", "same-origin");
        }
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = ex.getResponseBody()) {
            out.write(bytes);
        }
    }
}
