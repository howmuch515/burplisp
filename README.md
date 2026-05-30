# BurpLisp - Modify Burp Suite Request Headers with Clojure

`BurpLisp` is a powerful Burp Suite extension that allows you to dynamically inspect and modify outgoing HTTP requests using Clojure (Lisp) expressions.

With BurpLisp, you can write expressive Lisp code directly inside a dedicated tab in Burp Suite to alter headers, body payload, URLs, and target services on the fly. The extension packages the Clojure runtime inside, making it fully self-contained.

---

## 🛠️ Build Instructions

To compile the project and build the self-contained fat JAR, run the following command in the project root:

```bash
gradle jar
```

This will generate a self-contained JAR file at:
`build/libs/burplisp-1.0-SNAPSHOT.jar`

---

## 🚀 Installation

1. Open **Burp Suite**.
2. Go to the **Extensions** tab (formerly *Extender*).
3. Under **Installed**, click **Add**.
4. Choose Extension type: **Java**.
5. Select the path to the compiled JAR: `build/libs/burplisp-1.0-SNAPSHOT.jar` (within the project folder).
6. Click **Next** to load the extension. You should see "BurpLisp extension initialized successfully" in the output tab.

---

## 📖 Features & Architecture

### 1. Ring-Like Request Map (Flexible Request Manipulation)
The Clojure function takes two arguments: `request` (a Map representing the HTTP Request) and `state` (an Atom holding dynamic shared state). It must return a modified version of the `request` Map.

#### Request Map Structure:
```clojure
{:method "POST"
 :url "https://api.example.com/v1/users?id=123"
 :path "/v1/users"
 :query "id=123"
 :body "{\"username\": \"test\"}"
 :headers {"Host" "api.example.com"
           "Content-Type" "application/json"
           "User-Agent" "ClojureClient"}
 :service {:host "api.example.com"
           :port 443
           :secure true}}
```

#### Modifiable Map Attributes:
- `:method` (String) - Changes the request method (e.g. `GET`, `POST`, `PUT`).
- `:path` (String) - Changes the URL path.
- `:query` (String) - Changes the URL query string parameters.
- `:body` (String or byte[]) - Changes the request body. Supports JSON/XML strings or raw binaries.
- `:headers` (Map) - Completely replaces the HTTP headers list.
- `:service` (Map: `:host`, `:port`, `:secure`) - Modifies destination host, port, and SSL/TLS secure setting.

---

### 2. Thread-Safe Global State (`state` Atom)
The `state` parameter is a standard Clojure `atom` (which starts as an empty map `{}`). It allows you to persist data across multiple HTTP requests safely (e.g. tracking session states, auto-incrementing serial indices, or propagating CSRF tokens dynamically).

```clojure
(fn [request state]
  ;; Update counter in state atom
  (swap! state update :counter (fnil inc 0))
  (let [count (:counter @state)]
    (assoc-in request [:headers "X-Request-Index"] (str count))))
```

---

### 3. Comprehensive Target Scope & Tool Filtering
To prevent unwanted browser noise, you can filter which requests pass through the Clojure runtime:
- **Target Scope Only**: When enabled, BurpLisp ignores requests whose URL does not match Burp's target scope (`api.scope().isInScope(...)`).
- **Applicable Tools**: Filter interception using checkboxes for **Proxy**, **Repeater**, **Intruder**, and **Scanner**.

---

### 4. Enterprise-Grade Stability & Robustness
- **Automatic Preferences Storage**: Configurations (Clojure code, main toggle, scope toggles, and tool checkboxes) are saved automatically to Burp Suite's preferences, ensuring they persist between Burp Suite reboots or extension reloads.
- **Asynchronous Non-Blocking Compilation**: Compiling Lisp code is offloaded from Swing's Event Dispatch Thread (EDT) into a `SwingWorker` background thread. The Burp Suite UI remains responsive during compilation.
- **Interception Timeout Protection**: Modified requests run inside a cached daemon thread pool. If a user script crashes or hangs (e.g., infinite loop `(while true ...)`), the request times out after **500 milliseconds** and is safely forwarded unmodified, preventing Burp Suite from freezing.

---

## 💡 Practical S-Expression Presets

Use the **Preset Snippets** dropdown inside the UI to instantly load common configurations:

### 1. Add Custom Header (Default)
```clojure
(fn [request state]
  (assoc-in request [:headers "X-Burp-Lisp"] "Active"))
```

### 2. Host-based Conditional Modification
Inject custom Authorization headers strictly when matching target domains:
```clojure
(fn [request state]
  (let [host (get-in request [:service :host])]
    (if (= host "api.example.com")
      (-> request
          (assoc-in [:headers "Authorization"] "Bearer SECRET-LISP-TOKEN")
          (assoc-in [:headers "X-Lisp-Applied"] "true"))
      request)))
```

### 3. URL Query Parameter Injection
Add extra debugging parameters to the URL query string dynamically:
```clojure
(fn [request state]
  (let [current-query (:query request)
        new-query (if (empty? current-query)
                    "debug=true&test=1"
                    (str current-query "&debug=true&test=1"))]
    (assoc request :query new-query)))
```

### 4. Search & Replace JSON Request Body
Directly inspect and patch string values inside the JSON body payload:
```clojure
(fn [request state]
  (let [body (:body request)]
    (if (and (string? body) (.contains body "\"role\""))
      (assoc request :body (.replace body "\"role\":\"user\"" "\"role\":\"admin\""))
      request)))
```

---

## 🧑‍💻 Architecture Summary

- [BurpLispExtension.java](file:///Users/appbana/workspace/github.com/howmuch515/burplisp/src/main/java/burplisp/BurpLispExtension.java): Extension initialization and registering Montoya scope APIs.
- [BurpLispTab.java](file:///Users/appbana/workspace/github.com/howmuch515/burplisp/src/main/java/burplisp/BurpLispTab.java): Preferences storage, Swing-based layout, and SwingWorker compilation.
- [LispHttpHandler.java](file:///Users/appbana/workspace/github.com/howmuch515/burplisp/src/main/java/burplisp/LispHttpHandler.java): Intercepts HTTP requests, handles thread pool futures with 500ms timeouts, maps Ring-like variables, and registers filters.
