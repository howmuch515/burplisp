# BurpLisp - Modify Burp Suite Request Headers with Clojure

`BurpLisp` is a Burp Suite extension that allows you to dynamically modify outgoing HTTP request headers using Clojure (Lisp) expressions.

With BurpLisp, you can write powerful Lisp code directly inside a dedicated tab in Burp Suite to alter headers on the fly. The extension packages the Clojure runtime inside, making it fully self-contained with no external dependencies required.

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

## 📖 Usage Guide

Once loaded, a new tab named **BurpLisp** will appear in the Burp Suite interface.

### 1. The Interface
- **Enable BurpLisp (Checkbox)**: Toggles the request interception and modification on and off.
- **Clojure Lisp Expression (Text Area)**: Write your Lisp code here. The code must evaluate to a function (`IFn`) that takes a single map of headers and returns the modified map of headers.
- **Compile & Apply (Button)**: Compiles the Lisp code. If successful, it automatically applies the function to subsequent HTTP requests and auto-enables the extension.
- **Execution Logs / Compiler Errors (Console)**: Displays real-time status, compiler syntax errors, and runtime execution errors.

---

## 💡 Clojure S-Expression Examples

Your code must be a Clojure function that takes `headers` (represented as a Clojure map where keys and values are HTTP header names and values) and returns a new map of headers.

Here are practical examples you can paste into the BurpLisp editor:

### Example 1: Add or Update Headers (Default Example)
Simply add `X-Burp-Lisp` and modify the `User-Agent`.
```clojure
(fn [headers]
  (-> headers
      (assoc "X-Burp-Lisp" "Active")
      (assoc "User-Agent" "BurpLispAgent/1.0")))
```

### Example 2: Remove a Header
Remove headers like `DNT` or `Sec-Ch-Ua`.
```clojure
(fn [headers]
  (-> headers
      (dissoc "DNT")
      (dissoc "Sec-Ch-Ua")))
```

### Example 3: Conditional Header Modification (Based on Host)
Add a custom Authorization token *only* when the destination host is `api.example.com`.
```clojure
(fn [headers]
  (let [host (get headers "Host")]
    (if (= host "api.example.com")
      (assoc headers "Authorization" "Bearer LISP-SECRET-TOKEN-12345")
      headers)))
```

### Example 4: Dynamically Appending values
Append extra tracing data to an existing header.
```clojure
(fn [headers]
  (let [existing-cookie (get headers "Cookie" "")]
    (assoc headers "Cookie" (str existing-cookie "; lisp_session=active"))))
```

---

## 🛠️ How It Works Under the Hood

1. **Self-contained Clojure Environment**: The extension wraps the Clojure runtime (`org.clojure:clojure`). Inside `BurpLispTab.java`, we invoke `clojure.java.api.Clojure.var("clojure.core", "load-string")` to evaluate user input dynamically.
2. **Clojure Map Conversion**: In `LispHttpHandler.java`, when Burp intercepts an outgoing HTTP request, it converts the Java HTTP headers list to a standard `java.util.LinkedHashMap`, then converts it to a native Clojure map using `clojure.lang.PersistentHashMap.create(headersMap)`.
3. **Functional Application**: The Clojure function is invoked with this map, returns a new Clojure map, and the Java code uses it to rebuild the request headers.
