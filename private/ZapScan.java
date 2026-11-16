// rules_zap's driver. Runs on the pinned JDK (the same one ZAP runs on); it
// is compiled at build time by //private:driver, so it uses only the JDK.
//
//   check-config  --config <path> [--out <marker>]
//       Validate a rules_config file (build-time validation action).
//   config-test   --config <rloc> [--expect-error <regex>] --label <label>
//       zap_rules_config_test: the check must pass, or fail with a message
//       matching the regex.
//   scan          ... (see Scan below)
//       zap_api_scan_test: start the server on a free port, run ZAP's
//       Automation Framework (OpenAPI import, active + passive scan,
//       reports) against it, fail on alerts at or above --fail-on that
//       rules_config doesn't accept.
//   judge         --report <rloc> --origin <url> --fail-on <risk> --label <l>
//                 [--rules-config <rloc> --rules-config-name <name>]
//       The verdict on an existing traditional-xml report, as `scan` gives
//       it (rules_zap's own tests use it on a checked-in report).
//   cli           --install <rloc> --jar <rloc> --addon <rloc>... -- <zap args>
//       `bazel run //:zap`: ZAP with a fresh home and the pinned add-ons.
//
// Exit status: 0 pass, 1 test failure (alerts, expired accepted alerts,
// config-test mismatch), 2 error (bad rules_config, server or ZAP failed).
package rules_zap;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Duration;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public final class ZapScan {
    static final int EXIT_FAIL = 1;
    static final int EXIT_ERROR = 2;

    /** "Job report set reportFile = ...": the plan echoed back; not printed. */
    static final Pattern SETTING = Pattern.compile("^Job \\S+ set ");

    static final String[] RISKS = {"Informational", "Low", "Medium", "High"};

    /** A failure with a message for the user; `status` is the exit status. */
    static final class Failure extends Exception {
        final int status;

        Failure(int status, String message) {
            super(message);
            this.status = status;
        }
    }

    public static void main(String[] argv) {
        int status;
        try {
            if (argv.length == 0) {
                throw new Failure(EXIT_ERROR, "usage: ZapScan <check-config|config-test|scan|cli> ...");
            }
            Args args = new Args(argv, 1);
            switch (argv[0]) {
                case "check-config":
                    status = checkConfig(args);
                    break;
                case "config-test":
                    status = configTest(args);
                    break;
                case "scan":
                    status = new Scan(args).run();
                    break;
                case "judge":
                    status = new Scan(args).judgeReport();
                    break;
                case "cli":
                    status = cli(args);
                    break;
                default:
                    throw new Failure(EXIT_ERROR, "unknown mode " + argv[0]);
            }
        } catch (Failure f) {
            System.out.flush();
            System.err.println(f.getMessage());
            status = f.status;
        } catch (IOException | UncheckedIOException e) {
            System.out.flush();
            System.err.println("rules_zap: " + e);
            status = EXIT_ERROR;
        }
        System.out.flush();
        System.err.flush();
        // exit runs the shutdown hooks, which stop any process still running.
        System.exit(status);
    }

    // ---- arguments ----------------------------------------------------------

    /** `--key value` pairs (repeatable), then everything after `--`. */
    static final class Args {
        final Map<String, List<String>> opts = new HashMap<>();
        final List<String> rest = new ArrayList<>();

        Args(String[] argv, int start) throws Failure {
            for (int i = start; i < argv.length; i++) {
                String a = argv[i];
                if (a.equals("--")) {
                    for (int j = i + 1; j < argv.length; j++) {
                        rest.add(argv[j]);
                    }
                    return;
                }
                if (!a.startsWith("--") || i + 1 >= argv.length) {
                    throw new Failure(EXIT_ERROR, "rules_zap: bad driver argument " + a);
                }
                opts.computeIfAbsent(a.substring(2), k -> new ArrayList<>()).add(argv[++i]);
            }
        }

        String get(String key, String dflt) {
            List<String> v = opts.get(key);
            return v == null ? dflt : v.get(v.size() - 1);
        }

        String need(String key) throws Failure {
            String v = get(key, null);
            if (v == null) {
                throw new Failure(EXIT_ERROR, "rules_zap: missing driver argument --" + key);
            }
            return v;
        }

        List<String> all(String key) {
            return opts.getOrDefault(key, List.of());
        }

        Path runfile(String key) throws Failure {
            return Path.of(need("runfiles"), need(key));
        }
    }

    // ---- rules_config -------------------------------------------------------

    static final Pattern ID = Pattern.compile("[0-9]+(-[0-9]+)?");
    static final Pattern KEY_VALUE = Pattern.compile("([A-Za-z_][A-Za-z0-9_-]*):(?:[ ]+(.*))?");
    static final List<String> KEYS = List.of("expires", "id", "reason", "url");

    /** One accepted alert. */
    static final class Entry {
        final int index;
        final int line;
        String id;
        String urlText;
        Pattern url;
        String reason;
        LocalDate expires;
        int matched;

        Entry(int index, int line) {
            this.index = index;
            this.line = line;
        }

        boolean matches(Alert a, String uri) {
            if (!id.equals(a.pluginId) && !id.equals(a.alertRef)) {
                return false;
            }
            return url == null || url.matcher(uri).find();
        }

        String describe() {
            return "accept[" + index + "] (id " + id + (urlText != null ? ", url " + urlText : "") + ")";
        }
    }

    /**
     * Parses a rules_config: a YAML subset, a top-level `accept:` list of flat
     * mappings with scalar values. Every error is collected; a non-empty list
     * throws them all at once.
     */
    static List<Entry> parseConfig(Path path, String name) throws Failure, IOException {
        List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
        List<String> errors = new ArrayList<>();
        List<Entry> entries = new ArrayList<>();
        Map<Entry, Map<String, String>> fields = new LinkedHashMap<>();
        boolean seenAccept = false;
        boolean emptyList = false;
        Entry cur = null;
        int itemIndent = -1;
        int keyIndent = -1;
        for (int i = 0; i < lines.size(); i++) {
            int lineNo = i + 1;
            String raw = lines.get(i);
            String where = name + ":" + lineNo + ": ";
            int indent = 0;
            while (indent < raw.length() && raw.charAt(indent) == ' ') {
                indent++;
            }
            String text = raw.substring(indent).stripTrailing();
            if (text.isEmpty() || text.startsWith("#")) {
                continue;
            }
            if (text.startsWith("\t")) {
                errors.add(where + "tab in indentation; YAML indents with spaces");
                continue;
            }
            if (!seenAccept) {
                String t = stripComment(text);
                if (indent == 0 && t.matches("accept:\\s*(\\[\\s*\\])?")) {
                    seenAccept = true;
                    emptyList = t.contains("[");
                    continue;
                }
                errors.add(where + "expected `accept:` (the list of accepted alerts) first, got `" + text + "`");
                break;
            }
            if (emptyList) {
                errors.add(where + "nothing may follow `accept: []`");
                break;
            }
            if (indent == 0) {
                errors.add(where + "unexpected top-level `" + text + "`; the only top-level key is `accept:`");
                continue;
            }
            String kv;
            int kvIndent;
            if (text.equals("-") || text.startsWith("- ")) {
                if (itemIndent >= 0 && indent != itemIndent) {
                    errors.add(where + "list items must line up (indent " + itemIndent + ", got " + indent + ")");
                    continue;
                }
                itemIndent = indent;
                cur = new Entry(entries.size(), lineNo);
                entries.add(cur);
                fields.put(cur, new LinkedHashMap<>());
                keyIndent = -1;
                String after = text.substring(1);
                kv = after.strip();
                kvIndent = indent + 1 + (after.length() - after.stripLeading().length());
                if (kv.isEmpty()) {
                    continue;
                }
            } else {
                if (cur == null) {
                    errors.add(where + "expected a list item (`- id: ...`) under `accept:`");
                    continue;
                }
                if (indent <= itemIndent) {
                    errors.add(where + "bad indentation: keys of an item go under its `-`");
                    continue;
                }
                kv = text;
                kvIndent = indent;
            }
            if (keyIndent < 0) {
                keyIndent = kvIndent;
            } else if (kvIndent != keyIndent) {
                errors.add(where + "keys of accept[" + cur.index + "] must line up (column "
                        + (keyIndent + 1) + ", got " + (kvIndent + 1) + ")");
                continue;
            }
            if (kv.startsWith("{") || kv.startsWith("[")) {
                errors.add(where + "accept[" + cur.index + "]: flow-style YAML (`{...}`, `[...]`) isn't supported;"
                        + " write one `key: value` per line");
                continue;
            }
            Matcher m = KEY_VALUE.matcher(kv);
            if (!m.matches()) {
                errors.add(where + "accept[" + cur.index + "]: expected `key: value`, got `" + kv + "`");
                continue;
            }
            String key = m.group(1);
            String value;
            try {
                value = scalar(m.group(2) == null ? "" : m.group(2));
            } catch (IllegalArgumentException e) {
                errors.add(where + "accept[" + cur.index + "] " + key + ": " + e.getMessage());
                continue;
            }
            Map<String, String> f = fields.get(cur);
            if (f.containsKey(key)) {
                errors.add(where + "accept[" + cur.index + "]: `" + key + "` given twice");
                continue;
            }
            if (!KEYS.contains(key)) {
                errors.add(where + "accept[" + cur.index + "]: unknown key '" + key + "' (known: "
                        + String.join(", ", KEYS) + ")");
                continue;
            }
            f.put(key, value);
            f.put("@" + key, Integer.toString(lineNo));
        }
        if (!seenAccept && errors.isEmpty()) {
            errors.add(name + ": empty; a rules_config is `accept:` and a list of accepted alerts (or `accept: []`)");
        }
        Map<String, Entry> seen = new HashMap<>();
        for (Entry e : entries) {
            Map<String, String> f = fields.get(e);
            String where = name + ":" + e.line + ": accept[" + e.index + "]";
            e.id = f.get("id");
            if (e.id == null || e.id.isEmpty()) {
                errors.add(where + ": missing 'id' (a ZAP plugin id such as 40012, or an alert reference such as 10020-1)");
            } else if (!ID.matcher(e.id).matches()) {
                errors.add(where + ": id must be a ZAP plugin id (40012) or alert reference (10020-1), got '" + e.id + "'");
            }
            String reason = f.get("reason");
            if (reason == null || reason.isBlank()) {
                errors.add(where + (e.id != null ? " (id " + e.id + ")" : "")
                        + ": missing 'reason': every accepted alert needs one, saying why it is safe to accept");
            } else {
                e.reason = reason.strip();
            }
            String url = f.get("url");
            if (url != null) {
                if (url.isEmpty()) {
                    errors.add(where + ": url is empty; leave it out to accept the alert on every URL");
                } else {
                    try {
                        e.url = Pattern.compile(url);
                        e.urlText = url;
                    } catch (PatternSyntaxException x) {
                        errors.add(where + ": url is not a valid regular expression: "
                                + x.getDescription() + " near index " + x.getIndex() + " of '" + url + "'");
                    }
                }
            }
            String expires = f.get("expires");
            if (expires != null) {
                try {
                    if (!expires.matches("[0-9]{4}-[0-9]{2}-[0-9]{2}")) {
                        throw new DateTimeParseException("", expires, 0);
                    }
                    e.expires = LocalDate.parse(expires);
                } catch (DateTimeParseException x) {
                    errors.add(where + ": expires must be a date, YYYY-MM-DD, got '" + expires + "'");
                }
            }
            if (e.id != null) {
                String k = e.id + "\u0000" + (url == null ? "" : url);
                Entry prev = seen.putIfAbsent(k, e);
                if (prev != null) {
                    errors.add(where + ": duplicate of accept[" + prev.index + "] (line " + prev.line + ")");
                }
            }
        }
        if (!errors.isEmpty()) {
            throw new Failure(EXIT_ERROR, "rules_config " + name + ": " + errors.size() + " error(s):\n  "
                    + String.join("\n  ", errors));
        }
        return entries;
    }

    static String stripComment(String s) {
        int h = s.indexOf(" #");
        return (h < 0 ? s : s.substring(0, h)).strip();
    }

    /** A YAML scalar: "double-quoted", 'single-quoted' or plain, with an optional trailing # comment. */
    static String scalar(String v) {
        v = v.strip();
        if (v.isEmpty() || v.startsWith("#")) {
            return "";
        }
        char c = v.charAt(0);
        int end;
        StringBuilder b = new StringBuilder();
        if (c == '"') {
            int i = 1;
            for (; i < v.length(); i++) {
                char ch = v.charAt(i);
                if (ch == '"') {
                    break;
                }
                if (ch == '\\') {
                    if (++i >= v.length()) {
                        break;
                    }
                    char esc = v.charAt(i);
                    switch (esc) {
                        case '"': case '\\': case '/': b.append(esc); break;
                        case 'n': b.append('\n'); break;
                        case 't': b.append('\t'); break;
                        default:
                            throw new IllegalArgumentException("unsupported escape \\" + esc
                                    + " in a double-quoted value (use 'single quotes' for regexes)");
                    }
                } else {
                    b.append(ch);
                }
            }
            if (i >= v.length()) {
                throw new IllegalArgumentException("unterminated double-quoted value");
            }
            end = i + 1;
        } else if (c == '\'') {
            int i = 1;
            for (; i < v.length(); i++) {
                char ch = v.charAt(i);
                if (ch == '\'') {
                    if (i + 1 < v.length() && v.charAt(i + 1) == '\'') {
                        b.append('\'');
                        i++;
                        continue;
                    }
                    break;
                }
                b.append(ch);
            }
            if (i >= v.length()) {
                throw new IllegalArgumentException("unterminated single-quoted value");
            }
            end = i + 1;
        } else {
            if ("[]{}|>&*!%@`".indexOf(c) >= 0) {
                throw new IllegalArgumentException("unsupported YAML (`" + c
                        + "`): rules_config values are plain or quoted scalars; quote it");
            }
            String plain = stripComment(" " + v);
            if (plain.contains(": ")) {
                throw new IllegalArgumentException("a plain value can't contain `: `; quote it");
            }
            return plain;
        }
        String tail = v.substring(end).strip();
        if (!tail.isEmpty() && !tail.startsWith("#")) {
            throw new IllegalArgumentException("unexpected `" + tail + "` after the quoted value");
        }
        return b.toString();
    }

    static int checkConfig(Args args) throws Failure, IOException {
        Path config = Path.of(args.need("config"));
        String name = args.get("name", config.toString());
        List<Entry> entries = parseConfig(config, name);
        String out = args.get("out", null);
        if (out != null) {
            Files.writeString(Path.of(out), "ok: " + entries.size() + " accepted alert(s)\n");
        }
        return 0;
    }

    static int configTest(Args args) throws Failure, IOException {
        String label = args.need("label");
        String name = args.need("name");
        String expect = args.get("expect-error", "");
        Path config = args.runfile("config");
        String error = null;
        int n = 0;
        try {
            n = parseConfig(config, name).size();
        } catch (Failure f) {
            error = f.getMessage();
        }
        System.out.println("zap_rules_config_test " + label + ": " + name);
        if (error != null) {
            System.out.println(error);
        } else {
            System.out.println("rules_config " + name + ": ok, " + n + " accepted alert(s)");
        }
        if (expect.isEmpty()) {
            if (error != null) {
                throw new Failure(EXIT_FAIL, "FAIL: the check failed; expected it to pass");
            }
        } else if (error == null) {
            throw new Failure(EXIT_FAIL, "FAIL: the check passed; expected an error matching /" + expect + "/");
        } else if (!Pattern.compile(expect).matcher(error).find()) {
            throw new Failure(EXIT_FAIL, "FAIL: the error doesn't match /" + expect + "/");
        }
        System.out.println("PASS");
        return 0;
    }

    // ---- ZAP home and processes -------------------------------------------

    /** A fresh ZAP home: `plugin/` holds exactly the pinned add-ons. */
    static Path freshHome(Path home, List<Path> addons) throws IOException {
        deleteTree(home);
        Files.createDirectories(home.resolve("plugin"));
        for (Path a : addons) {
            Files.createSymbolicLink(home.resolve("plugin").resolve(a.getFileName()), a.toAbsolutePath());
        }
        return home;
    }

    static void deleteTree(Path p) throws IOException {
        if (!Files.exists(p, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        Files.walkFileTree(p, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(Path f, BasicFileAttributes attrs) throws IOException {
                Files.delete(f);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path d, IOException e) throws IOException {
                Files.delete(d);
                return FileVisitResult.CONTINUE;
            }
        });
    }

    /**
     * The ZAP command line. -silent: no unsolicited requests (update checks,
     * news, telemetry); the -config options turn every update and add-on
     * download off as well, so the install never changes.
     */
    static List<String> zapCommand(Path jar, Path install, Path home, List<String> jvmFlags) {
        List<String> cmd = new ArrayList<>();
        cmd.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
        cmd.addAll(jvmFlags);
        cmd.add("-Djava.awt.headless=true");
        cmd.add("-Duser.home=" + home);
        cmd.add("-Djava.net.useSystemProxies=false");
        cmd.add("-jar");
        cmd.add(jar.toString());
        cmd.add("-silent");
        cmd.add("-installdir");
        cmd.add(install.toString());
        cmd.add("-dir");
        cmd.add(home.toString());
        for (String c : new String[] {
            "start.checkForUpdates=false",
            "start.downloadNewRelease=false",
            "start.checkAddonUpdates=false",
            "start.installAddonUpdates=false",
            "start.installScannerRules=false",
            "start.reportReleaseAddons=false",
            "start.reportBetaAddons=false",
            "start.reportAlphaAddons=false",
            "database.recoverylog=false",
        }) {
            cmd.add("-config");
            cmd.add(c);
        }
        return cmd;
    }

    /** Stops a process and everything it started: TERM, then KILL after a grace period. */
    static void stopTree(Process p, Duration grace) {
        if (p == null) {
            return;
        }
        List<ProcessHandle> tree = new ArrayList<>();
        p.toHandle().descendants().forEach(tree::add);
        tree.add(p.toHandle());
        for (ProcessHandle h : tree) {
            h.destroy();
        }
        long deadline = System.nanoTime() + grace.toNanos();
        for (ProcessHandle h : tree) {
            try {
                long left = Math.max(0, deadline - System.nanoTime());
                h.onExit().get(left, TimeUnit.NANOSECONDS);
            } catch (Exception e) {
                // fall through to KILL
            }
        }
        for (ProcessHandle h : tree) {
            if (h.isAlive()) {
                h.destroyForcibly();
            }
        }
        try {
            p.waitFor(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    static String tail(Path f, int n) {
        try {
            List<String> l = Files.readAllLines(f, StandardCharsets.UTF_8);
            return "    " + String.join("\n    ", l.subList(Math.max(0, l.size() - n), l.size()));
        } catch (IOException | UncheckedIOException e) {
            return "    (can't read " + f + ": " + e + ")";
        }
    }

    static Path tmpDir() throws IOException {
        String t = System.getenv("TEST_TMPDIR");
        return t != null ? Path.of(t) : Files.createTempDirectory("rules_zap-");
    }

    // ---- bazel run //:zap -----------------------------------------------------

    static int cli(Args args) throws Failure, IOException {
        Path jar = args.runfile("jar");
        Path install = args.runfile("install");
        List<Path> addons = new ArrayList<>();
        for (String a : args.all("addon")) {
            addons.add(Path.of(args.need("runfiles"), a));
        }
        Path tmp = Files.createTempDirectory("rules_zap-");
        try {
            Path home = freshHome(tmp.resolve("home"), addons);
            List<String> cmd = zapCommand(jar, install, home, List.of("-Xmx1g"));
            List<String> user = args.rest;
            if (!user.contains("-cmd") && !user.contains("-daemon")) {
                cmd.add("-cmd");
            }
            cmd.addAll(user);
            ProcessBuilder pb = new ProcessBuilder(cmd).inheritIO();
            String wd = System.getenv("BUILD_WORKING_DIRECTORY");
            if (wd != null) {
                pb.directory(Path.of(wd).toFile());
            }
            pb.environment().put("HOME", tmp.toString());
            Process p = pb.start();
            Thread hook = new Thread(() -> stopTree(p, Duration.ofSeconds(10)));
            Runtime.getRuntime().addShutdownHook(hook);
            int rc = p.waitFor();
            Runtime.getRuntime().removeShutdownHook(hook);
            return rc;
        } catch (InterruptedException e) {
            return EXIT_ERROR;
        } finally {
            deleteTree(tmp);
        }
    }

    // ---- the scan -------------------------------------------------------------

    static final class Instance {
        String uri = "";
        String method = "";
        String param = "";
        String attack = "";
        String evidence = "";
        Entry acceptedBy;
    }

    static final class Alert {
        String pluginId;
        String alertRef;
        String name;
        int risk;
        int confidence;
        String confidenceDesc;
        List<Instance> instances = new ArrayList<>();

        String key() {
            return alertRef.equals(pluginId) ? pluginId : alertRef;
        }
    }

    static final class Scan {
        final Args args;
        final String label;
        final int failOn;
        Process server;
        Process zap;

        Scan(Args args) throws Failure {
            this.args = args;
            this.label = args.need("label");
            int f = -1;
            for (int i = 0; i < RISKS.length; i++) {
                if (RISKS[i].equals(args.need("fail-on"))) {
                    f = i;
                }
            }
            if (f < 0) {
                throw new Failure(EXIT_ERROR, "rules_zap: bad --fail-on " + args.need("fail-on"));
            }
            this.failOn = f;
        }

        int run() throws Failure, IOException {
            long t0 = System.nanoTime();
            String prefix = "zap_api_scan_test " + label + ": ";

            // 1. rules_config: valid, and nothing in it has expired.
            List<Entry> accepted = List.of();
            String configName = args.get("rules-config-name", null);
            if (configName != null) {
                accepted = parseConfig(args.runfile("rules-config"), configName);
                LocalDate today = LocalDate.now(ZoneOffset.UTC);
                List<String> expired = new ArrayList<>();
                for (Entry e : accepted) {
                    if (e.expires != null && !today.isBefore(e.expires)) {
                        expired.add(configName + ":" + e.line + ": " + e.describe() + " expired on " + e.expires
                                + " (reason given: " + e.reason + ")");
                    }
                }
                if (!expired.isEmpty()) {
                    throw new Failure(EXIT_FAIL, prefix + expired.size() + " accepted alert(s) in rules_config have expired:\n  "
                            + String.join("\n  ", expired)
                            + "\nReview each: remove it if the alert is fixed, or extend `expires` with a current reason.");
                }
            }

            Path tmp = tmpDir();
            String undeclared = System.getenv("TEST_UNDECLARED_OUTPUTS_DIR");
            Path out = undeclared != null ? Path.of(undeclared) : tmp.resolve("outputs");
            Files.createDirectories(out);
            List<Path> addons = new ArrayList<>();
            for (String a : args.all("addon")) {
                addons.add(Path.of(args.need("runfiles"), a));
            }
            Path home = freshHome(tmp.resolve("zap-home"), addons);

            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                stopTree(zap, Duration.ofSeconds(5));
                stopTree(server, Duration.ofSeconds(5));
            }));

            // 2. The server, on a free loopback port.
            int port = freePort();
            String origin = "http://127.0.0.1:" + port;
            startServer(port, out.resolve("server.log"));
            waitReady(port, out.resolve("server.log"));
            System.out.println(prefix + "server up at " + origin + " ("
                    + secs(System.nanoTime() - t0) + "); starting ZAP " + args.need("zap-version"));

            // 3. ZAP's Automation Framework.
            Path plan = tmp.resolve("zap-plan.yaml");
            Files.writeString(plan, plan(origin, out));
            List<String> cmd = zapCommand(args.runfile("jar"), args.runfile("install"), home, args.all("jvm-flag"));
            cmd.add("-cmd");
            cmd.add("-autorun");
            cmd.add(plan.toString());
            ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(true).directory(tmp.toFile());
            pb.environment().put("HOME", tmp.toString());
            long tz = System.nanoTime();
            zap = pb.start();
            List<String> zapOut = new ArrayList<>();
            try (BufferedReader r = new BufferedReader(new InputStreamReader(zap.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) {
                    zapOut.add(line);
                    boolean setting = SETTING.matcher(line).find() && !line.contains(" rule ");
                    if ((line.startsWith("Job ") && !setting) || line.startsWith("Automation plan")
                            || line.contains("ERROR") || line.contains("WARN") || line.startsWith("Exception")) {
                        System.out.println("  zap| " + line);
                    }
                }
            }
            int rc;
            try {
                rc = zap.waitFor();
            } catch (InterruptedException e) {
                throw new Failure(EXIT_ERROR, "interrupted");
            }
            Files.write(out.resolve("zap-stdout.log"), zapOut, StandardCharsets.UTF_8);
            copyIfExists(home.resolve("zap.log"), out.resolve("zap.log"));
            Files.copy(plan, out.resolve("zap-plan.yaml"), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            long zapNanos = System.nanoTime() - tz;

            boolean serverAlive = server.isAlive();
            stopTree(server, Duration.ofSeconds(5));
            if (!serverAlive) {
                throw new Failure(EXIT_ERROR, prefix + "the server exited (status " + server.exitValue()
                        + ") during the scan. Its log (server.log in the test outputs):\n" + tail(out.resolve("server.log"), 30));
            }
            // 0: succeeded; 2: succeeded with warnings (failOnWarning is off).
            if (rc != 0 && rc != 2) {
                throw new Failure(EXIT_ERROR, prefix + "ZAP's automation plan failed (exit status " + rc
                        + "). Its output (zap-stdout.log, zap.log in the test outputs):\n    "
                        + String.join("\n    ", zapOut.subList(Math.max(0, zapOut.size() - 40), zapOut.size())));
            }
            int urls = -1;
            Pattern added = Pattern.compile("Job openapi added (\\d+) URLs?");
            for (String l : zapOut) {
                Matcher m = added.matcher(l);
                if (m.find()) {
                    urls = Integer.parseInt(m.group(1));
                }
            }
            if (urls <= 0) {
                throw new Failure(EXIT_ERROR, prefix + "ZAP imported no URLs from the OpenAPI document ("
                        + describeOpenapi(origin) + "), so nothing was scanned. Its output:\n    "
                        + String.join("\n    ", zapOut.subList(Math.max(0, zapOut.size() - 40), zapOut.size())));
            }
            Path xml = out.resolve("zap-report.xml");
            if (!Files.exists(xml)) {
                throw new Failure(EXIT_ERROR, prefix + "ZAP wrote no report (" + xml + ")");
            }

            // 4. The verdict.
            List<Alert> alerts = parseReport(xml);
            String header = prefix + "ZAP scanned " + urls + " URL(s) from the OpenAPI document in " + secs(zapNanos)
                    + " (" + secs(System.nanoTime() - t0) + " in all); ";
            return judge(header, origin, alerts, accepted, configName, out);
        }

        /** `judge`: the verdict on an existing report (traditional-xml), as `scan` would give it. */
        int judgeReport() throws Failure, IOException {
            List<Entry> accepted = List.of();
            String configName = args.get("rules-config-name", null);
            if (configName != null) {
                accepted = parseConfig(args.runfile("rules-config"), configName);
            }
            List<Alert> alerts = parseReport(args.runfile("report"));
            return judge("zap judge " + label + ": ", args.need("origin"), alerts, accepted, configName, null);
        }

        static String secs(long nanos) {
            return String.format(Locale.ROOT, "%.1fs", nanos / 1e9);
        }

        String describeOpenapi(String origin) throws Failure {
            String p = args.get("openapi-path", null);
            return p != null ? "fetched from " + origin + p : args.need("openapi");
        }

        static int freePort() throws IOException {
            try (ServerSocket s = new ServerSocket(0, 0, InetAddress.getLoopbackAddress())) {
                s.setReuseAddress(true);
                return s.getLocalPort();
            }
        }

        void startServer(int port, Path log) throws Failure, IOException {
            List<String> cmd = new ArrayList<>();
            cmd.add(args.runfile("server").toString());
            for (String a : args.all("server-arg")) {
                cmd.add(a.replace("{port}", Integer.toString(port)));
            }
            ProcessBuilder pb = new ProcessBuilder(cmd)
                    .redirectErrorStream(true)
                    .redirectOutput(log.toFile());
            Path wd = Path.of(args.need("runfiles"), args.need("workspace"));
            if (Files.isDirectory(wd)) {
                pb.directory(wd.toFile());
            }
            Map<String, String> env = pb.environment();
            env.put("PORT", Integer.toString(port));
            env.put("HOST", "127.0.0.1");
            env.put("RUNFILES_DIR", args.need("runfiles"));
            env.put("JAVA_RUNFILES", args.need("runfiles"));
            for (String kv : args.all("server-env")) {
                int eq = kv.indexOf('=');
                env.put(kv.substring(0, eq), kv.substring(eq + 1).replace("{port}", Integer.toString(port)));
            }
            server = pb.start();
        }

        void waitReady(int port, Path log) throws Failure {
            String readyPath = args.get("ready-path", "");
            int timeout = Integer.parseInt(args.need("ready-timeout"));
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeout);
            String last = "nothing listening on port " + port;
            while (System.nanoTime() < deadline) {
                if (!server.isAlive()) {
                    throw new Failure(EXIT_ERROR, "zap_api_scan_test " + label + ": the server exited (status "
                            + server.exitValue() + ") before it was ready. Its log (server.log in the test outputs):\n"
                            + tail(log, 30));
                }
                try (Socket s = new Socket()) {
                    s.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 500);
                    if (readyPath.isEmpty()) {
                        return;
                    }
                    HttpURLConnection c = (HttpURLConnection) URI.create("http://127.0.0.1:" + port + readyPath)
                            .toURL().openConnection(Proxy.NO_PROXY);
                    c.setConnectTimeout(1000);
                    c.setReadTimeout(2000);
                    int code = c.getResponseCode();
                    c.disconnect();
                    if (code < 500) {
                        return;
                    }
                    last = "GET " + readyPath + " answered " + code;
                } catch (IOException e) {
                    // not yet
                }
                try {
                    Thread.sleep(200);
                } catch (InterruptedException e) {
                    throw new Failure(EXIT_ERROR, "interrupted");
                }
            }
            throw new Failure(EXIT_ERROR, "zap_api_scan_test " + label + ": the server wasn't ready within "
                    + timeout + "s (" + last + "). It must listen on 127.0.0.1:$PORT. Its log:\n" + tail(log, 30));
        }

        /** The Automation Framework plan. Strings are JSON-quoted, which YAML reads as double-quoted. */
        String plan(String origin, Path out) throws Failure {
            StringBuilder p = new StringBuilder();
            p.append("# Generated by rules_zap for ").append(label).append("\n");
            p.append("env:\n");
            p.append("  contexts:\n");
            p.append("    - name: \"api\"\n");
            p.append("      urls:\n");
            p.append("        - ").append(q(origin)).append("\n");
            p.append("      includePaths:\n");
            p.append("        - ").append(q(Pattern.quote(origin) + ".*")).append("\n");
            p.append("  parameters:\n");
            p.append("    failOnError: true\n");
            p.append("    failOnWarning: false\n");
            p.append("    progressToStdout: true\n");
            p.append("jobs:\n");
            p.append("  - type: openapi\n");
            p.append("    parameters:\n");
            String openapiPath = args.get("openapi-path", null);
            if (openapiPath != null) {
                p.append("      apiUrl: ").append(q(origin + openapiPath)).append("\n");
            } else {
                p.append("      apiFile: ").append(q(args.runfile("openapi").toAbsolutePath().toString())).append("\n");
            }
            p.append("      targetUrl: ").append(q(origin)).append("\n");
            p.append("      context: \"api\"\n");
            p.append("  - type: passiveScan-wait\n");
            p.append("    parameters:\n");
            p.append("      maxDuration: 2\n");
            p.append("  - type: activeScan\n");
            p.append("    parameters:\n");
            p.append("      context: \"api\"\n");
            p.append("      maxScanDurationInMins: ").append(args.need("max-scan-minutes")).append("\n");
            p.append("      threadPerHost: ").append(args.need("threads")).append("\n");
            p.append("    policyDefinition:\n");
            p.append("      defaultStrength: ").append(q(args.need("strength"))).append("\n");
            p.append("      defaultThreshold: \"medium\"\n");
            p.append("      rules:\n");
            // HTTP Only Site: probes for HTTPS on the same host. The server
            // under test is plain HTTP on loopback by construction.
            p.append("        - id: 10106\n");
            p.append("          threshold: \"off\"\n");
            p.append("  - type: passiveScan-wait\n");
            p.append("    parameters:\n");
            p.append("      maxDuration: 2\n");
            String[][] reports = {
                {"traditional-xml", "zap-report.xml"},
                {"traditional-json", "zap-report.json"},
                {"traditional-html", "zap-report.html"},
            };
            for (String[] r : reports) {
                p.append("  - type: report\n");
                p.append("    parameters:\n");
                p.append("      template: ").append(q(r[0])).append("\n");
                p.append("      reportDir: ").append(q(out.toAbsolutePath().toString())).append("\n");
                p.append("      reportFile: ").append(q(r[1])).append("\n");
                p.append("      reportTitle: ").append(q("ZAP API scan: " + label)).append("\n");
                p.append("      displayReport: false\n");
            }
            return p.toString();
        }

        int judge(String header, String origin, List<Alert> alerts, List<Entry> accepted,
                String configName, Path out) throws IOException {
            List<Alert> failing = new ArrayList<>();
            List<Alert> acceptedAlerts = new ArrayList<>();
            List<Alert> below = new ArrayList<>();
            for (Alert a : alerts) {
                if (a.confidence == 0) {
                    continue; // ZAP's own "False Positive" confidence
                }
                boolean anyOpen = false;
                boolean anyAccepted = false;
                for (Instance in : a.instances) {
                    for (Entry e : accepted) {
                        if (e.matches(a, in.uri)) {
                            in.acceptedBy = e;
                            e.matched++;
                            break;
                        }
                    }
                    if (in.acceptedBy == null) {
                        anyOpen = true;
                    } else {
                        anyAccepted = true;
                    }
                }
                if (a.risk >= failOn && anyOpen) {
                    failing.add(a);
                } else if (anyAccepted) {
                    acceptedAlerts.add(a);
                } else {
                    below.add(a);
                }
            }
            Comparator<Alert> order = Comparator.<Alert>comparingInt(a -> -a.risk).thenComparing(a -> a.key());
            failing.sort(order);
            acceptedAlerts.sort(order);
            below.sort(order);

            StringBuilder s = new StringBuilder();
            s.append(header).append(alerts.size()).append(" alert type(s) raised; failing at ").append(RISKS[failOn])
                    .append(" and above.\n");
            if (!failing.isEmpty()) {
                s.append("FAIL: ").append(failing.size()).append(" alert(s) at or above ").append(RISKS[failOn])
                        .append(" not accepted by rules_config:\n");
                for (Alert a : failing) {
                    s.append("  [").append(RISKS[a.risk]).append("] ").append(a.key()).append(" ").append(a.name)
                            .append(" (confidence ").append(a.confidenceDesc).append(")\n");
                    int shown = 0;
                    for (Instance in : a.instances) {
                        if (in.acceptedBy != null) {
                            continue;
                        }
                        if (shown++ == 5) {
                            s.append("      ... and more; see zap-report.html\n");
                            break;
                        }
                        s.append("      ").append(in.method.isEmpty() ? "" : in.method + " ")
                                .append(relative(in.uri, origin))
                                .append(in.param.isEmpty() ? "" : "  param: " + in.param).append("\n");
                        if (!in.evidence.isEmpty()) {
                            s.append("        evidence: ").append(clip(in.evidence)).append("\n");
                        } else if (!in.attack.isEmpty()) {
                            s.append("        attack: ").append(clip(in.attack)).append("\n");
                        }
                    }
                    List<String> by = new ArrayList<>();
                    int n = 0;
                    for (Instance in : a.instances) {
                        if (in.acceptedBy != null) {
                            n++;
                            if (!by.contains("accept[" + in.acceptedBy.index + "]")) {
                                by.add("accept[" + in.acceptedBy.index + "]");
                            }
                        }
                    }
                    if (n > 0) {
                        s.append("      (").append(n).append(" other instance(s) accepted by ")
                                .append(String.join(", ", by)).append(")\n");
                    }
                }
            }
            if (!acceptedAlerts.isEmpty()) {
                s.append("Accepted by ").append(configName).append(":\n");
                for (Alert a : acceptedAlerts) {
                    List<String> reasons = new ArrayList<>();
                    int n = 0;
                    for (Instance in : a.instances) {
                        if (in.acceptedBy != null) {
                            n++;
                            String r = "accept[" + in.acceptedBy.index + "]: " + in.acceptedBy.reason;
                            if (!reasons.contains(r)) {
                                reasons.add(r);
                            }
                        }
                    }
                    s.append("  [").append(RISKS[a.risk]).append("] ").append(a.key()).append(" ").append(a.name)
                            .append(", ").append(n).append(" instance(s): ").append(String.join("; ", reasons))
                            .append("\n");
                }
            }
            if (!below.isEmpty()) {
                s.append("Below ").append(RISKS[failOn]).append(" (reported, not failing):\n");
                for (Alert a : below) {
                    s.append("  [").append(RISKS[a.risk]).append("] ").append(a.key()).append(" ").append(a.name)
                            .append(" (").append(a.instances.size()).append(" instance(s))\n");
                }
            }
            for (Entry e : accepted) {
                if (e.matched == 0) {
                    s.append("Note: ").append(configName).append(":").append(e.line).append(": ").append(e.describe())
                            .append(" matched no alert; remove it if the alert is gone.\n");
                }
            }
            if (out != null) {
                s.append("Reports: zap-report.html, zap-report.json, zap-report.xml (and zap.log, server.log) in ")
                    .append(System.getenv("TEST_UNDECLARED_OUTPUTS_DIR") != null
                            ? "the test's outputs (bazel-testlogs/<package>/<name>/test.outputs/)"
                            : out.toString())
                    .append("\n");
            }
            if (!failing.isEmpty()) {
                Alert a = failing.get(0);
                String path = "";
                for (Instance in : a.instances) {
                    if (in.acceptedBy == null) {
                        path = URI.create(in.uri.isEmpty() ? origin : in.uri).getPath();
                        break;
                    }
                }
                s.append("Fix the server, or, for a reviewed false positive, accept the alert in rules_config with a reason:\n")
                        .append("  accept:\n")
                        .append("    - id: ").append(a.key()).append("\n")
                        .append(path == null || path.isEmpty() ? "" : "      url: " + yamlQuote(path) + "\n")
                        .append("      reason: <why this is safe>\n");
            } else {
                s.append("PASS\n");
            }
            System.out.print(s);
            writeJunit(alerts, failing, accepted);
            return failing.isEmpty() ? 0 : EXIT_FAIL;
        }

        void writeJunit(List<Alert> alerts, List<Alert> failing, List<Entry> accepted) throws IOException {
            String path = System.getenv("XML_OUTPUT_FILE");
            if (path == null) {
                return;
            }
            StringBuilder x = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
            x.append("<testsuites><testsuite name=").append(xa(label)).append(" tests=\"").append(alerts.size())
                    .append("\" failures=\"").append(failing.size()).append("\">\n");
            for (Alert a : alerts) {
                x.append("  <testcase classname=").append(xa(label)).append(" name=")
                        .append(xa("[" + RISKS[a.risk] + "] " + a.key() + " " + a.name)).append(">");
                if (failing.contains(a)) {
                    StringBuilder body = new StringBuilder();
                    for (Instance in : a.instances) {
                        if (in.acceptedBy == null) {
                            body.append(in.method).append(" ").append(in.uri).append(" ").append(in.param).append("\n");
                        }
                    }
                    x.append("<failure message=").append(xa(RISKS[a.risk] + " alert " + a.key() + ": " + a.name))
                            .append(">").append(xt(body.toString())).append("</failure>");
                }
                x.append("</testcase>\n");
            }
            x.append("</testsuite></testsuites>\n");
            Files.writeString(Path.of(path), x.toString());
        }
    }

    static String relative(String uri, String origin) {
        return uri.startsWith(origin) ? uri.substring(origin.length()) : uri;
    }

    static String clip(String s) {
        s = s.replace("\n", "\\n").replace("\r", "");
        return s.length() > 160 ? s.substring(0, 160) + "..." : s;
    }

    static String yamlQuote(String s) {
        return "'" + s.replace("'", "''") + "'";
    }

    static String q(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') {
                b.append('\\').append(c);
            } else if (c < 0x20) {
                b.append(String.format("\\u%04x", (int) c));
            } else {
                b.append(c);
            }
        }
        return b.append('"').toString();
    }

    static String xt(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    static String xa(String s) {
        return "\"" + xt(s).replace("\"", "&quot;") + "\"";
    }

    static void copyIfExists(Path from, Path to) throws IOException {
        if (Files.exists(from)) {
            Files.copy(from, to, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }
    }

    /** ZAP's traditional-xml report: OWASPZAPReport/site/alerts/alertitem. */
    static List<Alert> parseReport(Path xml) throws IOException {
        Document doc;
        try {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            f.setExpandEntityReferences(false);
            doc = f.newDocumentBuilder().parse(xml.toFile());
        } catch (Exception e) {
            throw new IOException("can't parse ZAP's report " + xml + ": " + e, e);
        }
        List<Alert> alerts = new ArrayList<>();
        NodeList items = doc.getElementsByTagName("alertitem");
        for (int i = 0; i < items.getLength(); i++) {
            Element el = (Element) items.item(i);
            Alert a = new Alert();
            a.pluginId = text(el, "pluginid");
            a.alertRef = text(el, "alertRef");
            if (a.alertRef.isEmpty()) {
                a.alertRef = a.pluginId;
            }
            a.name = text(el, "alert");
            a.risk = Integer.parseInt(text(el, "riskcode"));
            a.confidence = Integer.parseInt(text(el, "confidence"));
            a.confidenceDesc = text(el, "confidencedesc");
            NodeList ins = el.getElementsByTagName("instance");
            for (int j = 0; j < ins.getLength(); j++) {
                Element ie = (Element) ins.item(j);
                Instance in = new Instance();
                in.uri = text(ie, "uri");
                in.method = text(ie, "method");
                in.param = text(ie, "param");
                in.attack = text(ie, "attack");
                in.evidence = text(ie, "evidence");
                a.instances.add(in);
            }
            if (a.instances.isEmpty()) {
                a.instances.add(new Instance());
            }
            alerts.add(a);
        }
        return alerts;
    }

    static String text(Element el, String tag) {
        for (Node n = el.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element && ((Element) n).getTagName().equals(tag)) {
                return n.getTextContent().strip();
            }
        }
        return "";
    }
}
