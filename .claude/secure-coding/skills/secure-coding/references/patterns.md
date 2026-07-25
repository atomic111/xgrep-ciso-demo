# Secure Coding Guide for AI Agents

When generating or modifying code, follow these rules to avoid introducing
security vulnerabilities. Each entry shows the dangerous pattern and the safe
alternative, organized by vulnerability class and language.

This guide is derived from real CVEs in production open-source projects.

---

## 1. Secret Comparison -- Use Constant-Time Compare

Never compare secrets (passwords, tokens, API keys, HMAC digests, signatures)
with `==` or `.equals()`. These operators short-circuit on the first differing
byte, leaking information via timing.

| Language | Dangerous | Safe |
|----------|-----------|------|
| Go | `secret == expected` | `subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1` |
| Python | `token == expected` | `hmac.compare_digest(a, b)` or `secrets.compare_digest(a, b)` |
| JavaScript | `hash === expected` | `crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))` |
| Java | `token.equals(expected)` | `MessageDigest.isEqual(a.getBytes(), b.getBytes())` |
| Java | `Arrays.equals(proof, expected)` | `MessageDigest.isEqual(proof, expected)` |
| Ruby | `digest == expected` | `Rack::Utils.secure_compare(a, b)` |
| C# | `secret == expected` | `CryptographicOperations.FixedTimeEquals(bytesA, bytesB)` |

Real CVEs: Harbor CVE-2023-20902, vLLM CVE-2025-59425, Armeria CVE-2019-16771,
fastify-bearer-auth CVE-2022-31142, Rails pre-2.3.4.

---

## 2. SQL Injection -- Use Parameterized Queries

Never concatenate user input into SQL strings. Use parameterized queries with
placeholders.

| Language | Dangerous | Safe |
|----------|-----------|------|
| Go | `db.Query("SELECT * FROM t WHERE id=" + id)` | `db.Query("SELECT * FROM t WHERE id=?", id)` |
| Python | `cursor.execute("SELECT * FROM t WHERE id=" + id)` | `cursor.execute("SELECT * FROM t WHERE id=%s", (id,))` |
| JavaScript | `` pool.query(`SELECT * FROM t WHERE id='${id}'`) `` | `pool.query("SELECT * FROM t WHERE id=$1", [id])` |
| Java | `stmt.execute("SELECT * FROM t WHERE id=" + id)` | `PreparedStatement` with `?` placeholders |
| Ruby | `where("name = '#{name}'")` | `where("name = ?", name)` or `where(name: name)` |
| C# | `FromSqlRaw($"SELECT * WHERE id={id}")` | `FromSqlInterpolated($"SELECT * WHERE id={id}")` |

Real CVEs: Django CVE-2024-42005, Sequelize CVE-2023-25813, EaseProbe CVE-2023-33967.

---

## 3. SSRF -- Validate URLs Against Allowlist

Never pass user-controlled URLs directly to HTTP client libraries. Validate
against an allowlist of permitted hosts and schemes.

| Language | Dangerous | Safe |
|----------|-----------|------|
| Python | `requests.get(user_url)` | Validate host against allowlist, block private IPs |
| Go | `http.Get(user_url)` | Validate URL, block `127.0.0.1`, `169.254.169.254`, `10.*` |
| JavaScript | `axios.get(user_url)` | URL allowlist validation before request |
| C# | `httpClient.GetAsync(user_uri)` | `HasValidBaseUri()` check against known hosts |
| Ruby | `OpenURI.open_uri(url)` | Use `ssrf_filter` gem: `SsrfFilter.get(uri)` |
| Java | `UriComponentsBuilder.fromUriString(url)` | Validate parsed host against allowlist |

Real CVEs: Gradio SSRF, Django CVE-2021-33571, TrueLayer GHSA-67m4, CarrierWave GHSA-fwcm.

---

## 4. Path Traversal -- Validate Resolved Paths

Never use user input directly in file paths. Strip directory components or
verify the resolved path stays within the expected directory.

| Language | Dangerous | Safe |
|----------|-----------|------|
| Python | `open(user_filename)` | `os.path.basename(filename)` then `os.path.join(base, safe)` |
| Python | `send_file(user_path)` | `send_from_directory(directory, filename)` |
| Go | `os.Open(filepath.Join(base, userInput))` | Verify `filepath.Abs` starts with base dir |
| JavaScript | `fs.readFile(req.query.file)` | `path.resolve` then check prefix |
| C# | `Path.Combine(base, filename)` | Check `Path.GetFullPath` starts with base (Path.Combine ignores base if filename is absolute!) |
| Ruby | `File.open(File.join(base, name))` | Verify `File.realpath` stays within base |
| Swift | `URL.appendingPathComponent(entry)` | Check `standardizedFileURL.path.hasPrefix(base)` |

Real CVEs: Grafana CVE-2021-43798, Starlette GHSA-v5gw, django-s3file, Rails CVE-2026-33195, Zip Swift CVE-2023-39135.

---

## 5. Code Injection -- Never eval() User Input

Never pass user-controlled input to dynamic code execution functions.

| Language | Dangerous | Safe |
|----------|-----------|------|
| Python | `eval(user_input)` / `exec(user_input)` | `json.loads()`, `ast.literal_eval()`, `int()` |
| JavaScript | `eval(user_input)` / `new Function(user_input)` | `JSON.parse()`, dedicated parsers |
| Ruby | `eval(user_input)` | `JSON.parse()`, `Integer()`, dedicated parsers |

Real CVEs: Langroid CVE-2025-46725, MetaGPT eval injection.

---

## 6. XSS -- Encode Output for Context

Never insert user input into HTML without encoding for the output context.

| Context | Encoding |
|---------|----------|
| HTML body | HTML-entity encode (`&lt;`, `&gt;`, `&amp;`, `&quot;`) |
| HTML attribute | HTML-entity encode + quote the attribute value |
| JavaScript string | JavaScript-encode (`\x3c`, `\x3e`) |
| URL parameter | URL-encode (`%3C`, `%3E`) |

Use framework auto-escaping (React JSX, Go `html/template`, Django templates,
Rails ERB `<%= %>`). Avoid `dangerouslySetInnerHTML`, `Html.Raw()`, `| safe`,
`raw()`, `{!! !!}`.

---

## 7. JWT -- Restrict Algorithms

Never decode JWTs without specifying the expected algorithm. Never accept
`alg:none`.

| Language | Dangerous | Safe |
|----------|-----------|------|
| Python | `jwt.decode(token, secret)` | `jwt.decode(token, secret, algorithms=["HS256"])` |
| Ruby | `JWT.decode(token, key, false)` | `JWT.decode(token, key, true, algorithms: ["HS256"])` |
| Swift | Return true for `alg:none` | Throw error for `alg:none` |
| Go | `jwt.Parse(token)` without `WithValidMethods` | `jwt.Parse(token, keyFunc, jwt.WithValidMethods(["RS256"]))` |
| Java | Accept `PlainJWT` | Reject `PlainJWT`, validate algorithm |

Real CVEs: PyJWT CVE-2022-29217, jose-swift GHSA-88q6, pac4j CVE-2026-29000.

---

## 8. TLS -- Use TLS 1.2+

Never configure TLS with deprecated protocol versions (SSLv3, TLS 1.0, TLS 1.1).

| Language | Dangerous | Safe |
|----------|-----------|------|
| Go | `tls.Config{MinVersion: tls.VersionTLS10}` | `tls.Config{MinVersion: tls.VersionTLS12}` |
| Java | `SSLContext.getInstance("TLSv1")` | `SSLContext.getInstance("TLSv1.2")` |
| JavaScript | `{ minVersion: 'TLSv1' }` | `{ minVersion: 'TLSv1.2' }` |
| C# | `SecurityProtocolType.Tls` | `SecurityProtocolType.Tls12` |
| Ruby | `SSLContext.new('TLSv1')` | `SSLContext.new` with `min_version = TLS1_2_VERSION` |

---

## 9. Certificate Validation -- Never Disable

Never disable TLS certificate verification in production code.

| Language | Dangerous | Safe |
|----------|-----------|------|
| Go | `InsecureSkipVerify: true` | Remove or set `false` |
| Python | `requests.get(url, verify=False)` | `requests.get(url)` (verify=True is default) |
| JavaScript | `rejectUnauthorized: false` | Remove (true is default) |
| C# | `ServerCertificateValidationCallback = (...) => true` | Implement proper validation |
| Ruby | `OpenSSL::SSL::VERIFY_NONE` | `OpenSSL::SSL::VERIFY_PEER` |
| Swift | `completionHandler(.useCredential, ...)` | `completionHandler(.performDefaultHandling, nil)` |

---

## 10. Deserialization -- Use Safe Loaders

Never deserialize untrusted data with unrestricted type instantiation.

| Language | Dangerous | Safe |
|----------|-----------|------|
| Python | `pickle.load(data)` | `json.loads(data)` |
| Python | `yaml.load(data)` | `yaml.safe_load(data)` |
| Ruby | `YAML.load(data)` | `YAML.safe_load(data, permitted_classes: [...])` |
| Java | `ObjectInputStream.readObject()` | Use `ObjectInputFilter` or JSON |
| Go | `yaml.Unmarshal(data, &interface{})` | `yaml.Unmarshal(data, &ConcreteStruct{})` |
| Swift | `NSKeyedUnarchiver.unarchiveObject(with:)` | `NSKeyedUnarchiver.unarchivedObject(ofClass:from:)` |
| C# | `BinaryFormatter.Deserialize()` | `System.Text.Json.JsonSerializer.Deserialize<T>()` |

Real CVEs: ms-swift CVE-2025-50460, OpenSearch Ruby GHSA-977c, go-yaml CVE-2022-28948.

---

## 11. HTTP Headers -- Reject CRLF in Values

Never put user input directly into HTTP response headers without stripping
`\r` and `\n` characters.

| Language | Dangerous | Safe |
|----------|-----------|------|
| Python | `response.headers["Location"] = user_input` | Strip or reject `\r\n` |
| Ruby | `fast_write "#{k}: #{v}\r\n"` | Check `v` for `\r` / `\n` first |
| JavaScript | `res.setHeader('Location', user_input)` | Validate no CRLF |

Real CVEs: CPython bpo-39603, Puma CVE-2020-5249, Node CVE-2018-12116.

---

## 12. CORS -- Restrict Origins

Never use `Access-Control-Allow-Origin: *` with credentials.

| Language | Dangerous | Safe |
|----------|-----------|------|
| Java/Spring | `@CrossOrigin(origins = "*")` | `@CrossOrigin(origins = "https://app.example.com")` |
| C#/ASP.NET | `builder.AllowAnyOrigin()` | `builder.WithOrigins("https://app.example.com")` |
| Python/Flask | `CORS(app, origins="*")` | `CORS(app, origins=["https://app.example.com"])` |
| Go | `w.Header().Set("Access-Control-Allow-Origin", "*")` | Validate Origin against allowlist |

---

## 13. Sensitive Data -- Don't Log Secrets

Never log passwords, API keys, tokens, or other secrets.

| Language | Dangerous | Safe |
|----------|-----------|------|
| Any | `log("password: " + password)` | `log("auth attempt for user: " + username)` |
| Any | `log("token: " + token)` | `log("token validated: " + tokenId)` |

Mask or redact sensitive fields before logging. Log identifiers (user ID,
request ID), not credentials.

---

## 14. Random Numbers -- Use Crypto RNG for Security

Never use `math/rand`, `Math.random()`, or similar PRNGs for security-sensitive
values (tokens, keys, session IDs, salts).

| Language | Dangerous | Safe |
|----------|-----------|------|
| Go | `math/rand.Int()` | `crypto/rand.Read()` |
| Python | `random.randint()` | `secrets.token_hex()` |
| JavaScript | `Math.random()` | `crypto.randomBytes()` / `crypto.getRandomValues()` |
| Java | `new Random()` | `new SecureRandom()` |
| C# | `new Random()` | `RandomNumberGenerator.GetBytes()` |

Real CVEs: Cloudreve CVE-2026-25726 (math/rand -> JWT forgery), YApi CVE-2021-27884.

---

## 15. Race Conditions -- Atomic File Operations

Don't create a file then chmod it -- use atomic creation with the right mode.

| Language | Dangerous | Safe |
|----------|-----------|------|
| Python | `open(f, "w")` then `chmod(f, 0o600)` | `os.fdopen(os.open(f, O_CREAT\|O_WRONLY, 0o600), "w")` |
| Go | `os.Create(f)` then `os.Chmod(f, 0600)` | `os.OpenFile(f, os.O_CREATE\|os.O_WRONLY, 0600)` |

Real CVE: Paramiko CVE-2022-24302.
