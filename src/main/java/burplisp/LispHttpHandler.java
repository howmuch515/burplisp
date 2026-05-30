package burplisp;

import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.scope.Scope;
import clojure.lang.IFn;
import clojure.java.api.Clojure;

import java.util.*;
import java.util.concurrent.*;

public class LispHttpHandler implements HttpHandler {
    private final Logging logging;
    private final Scope scope;
    
    private volatile IFn clojureFunction;
    private volatile Object clojureStateAtom; // clojure.lang.Atom
    private volatile boolean enabled = false;
    
    // Filters
    private volatile boolean targetScopeOnly = false;
    private volatile boolean proxyEnabled = true;
    private volatile boolean repeaterEnabled = true;
    private volatile boolean intruderEnabled = true;
    private volatile boolean scannerEnabled = false;

    // Cached thread pool for timeout management (uses daemon threads to allow Burp shutdown)
    private final ExecutorService executorService;

    public LispHttpHandler(Logging logging, Scope scope) {
        this.logging = logging;
        this.scope = scope;
        this.executorService = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r);
            t.setDaemon(true);
            t.setName("BurpLisp-Interception-Executor");
            return t;
        });
        
        resetStateAtom();
    }

    public void resetStateAtom() {
        ClassLoader originalClassLoader = Thread.currentThread().getContextClassLoader();
        try {
            // Safe ClassLoader swap during bootstrap
            ClassLoader extensionClassLoader = this.getClass().getClassLoader();
            Thread.currentThread().setContextClassLoader(extensionClassLoader);
            
            IFn atomFn = Clojure.var("clojure.core", "atom");
            IFn hashMapFn = Clojure.var("clojure.core", "hash-map");
            this.clojureStateAtom = atomFn.invoke(hashMapFn.invoke());
        } catch (Exception e) {
            logging.logToError("Failed to initialize Clojure state atom: " + e.getMessage());
        } finally {
            Thread.currentThread().setContextClassLoader(originalClassLoader);
        }
    }

    public void setClojureFunction(IFn clojureFunction) {
        this.clojureFunction = clojureFunction;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public void setFilters(boolean targetScopeOnly, boolean proxyEnabled, boolean repeaterEnabled, boolean intruderEnabled, boolean scannerEnabled) {
        this.targetScopeOnly = targetScopeOnly;
        this.proxyEnabled = proxyEnabled;
        this.repeaterEnabled = repeaterEnabled;
        this.intruderEnabled = intruderEnabled;
        this.scannerEnabled = scannerEnabled;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        if (!enabled || clojureFunction == null) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        // 1. Tool Filter Check
        ToolType toolType = requestToBeSent.toolSource().toolType();
        if (toolType == ToolType.PROXY && !proxyEnabled) return RequestToBeSentAction.continueWith(requestToBeSent);
        if (toolType == ToolType.REPEATER && !repeaterEnabled) return RequestToBeSentAction.continueWith(requestToBeSent);
        if (toolType == ToolType.INTRUDER && !intruderEnabled) return RequestToBeSentAction.continueWith(requestToBeSent);
        if (toolType == ToolType.SCANNER && !scannerEnabled) return RequestToBeSentAction.continueWith(requestToBeSent);

        // 2. Target Scope Filter Check
        if (targetScopeOnly && !scope.isInScope(requestToBeSent.url())) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        // 3. Threaded Clojure Execution with 500ms timeout protection against infinite loops
        Callable<HttpRequest> task = () -> executeClojureModification(requestToBeSent);
        Future<HttpRequest> future = executorService.submit(task);

        try {
            HttpRequest modifiedRequest = future.get(500, TimeUnit.MILLISECONDS);
            if (modifiedRequest != null) {
                return RequestToBeSentAction.continueWith(modifiedRequest);
            }
        } catch (TimeoutException e) {
            future.cancel(true);
            logging.logToError("BurpLisp dynamic execution timed out (>500ms) for: " + requestToBeSent.url() + ". Skipping modification.");
        } catch (Exception e) {
            logging.logToError("Error during BurpLisp interception: " + e.getMessage());
            java.io.StringWriter sw = new java.io.StringWriter();
            java.io.PrintWriter pw = new java.io.PrintWriter(sw);
            e.printStackTrace(pw);
            logging.logToError(sw.toString());
        }

        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    private HttpRequest executeClojureModification(HttpRequestToBeSent requestToBeSent) throws Exception {
        ClassLoader originalClassLoader = Thread.currentThread().getContextClassLoader();
        try {
            ClassLoader extensionClassLoader = this.getClass().getClassLoader();
            Thread.currentThread().setContextClassLoader(extensionClassLoader);

            // Construct Ring-like Request Map
            Map<String, Object> reqMap = new HashMap<>();
            reqMap.put("method", requestToBeSent.method());
            reqMap.put("url", requestToBeSent.url());
            reqMap.put("path", requestToBeSent.path());
            reqMap.put("query", requestToBeSent.query());
            reqMap.put("body", requestToBeSent.bodyToString());
            
            // Extract headers into key-value map
            Map<String, String> headersMap = new LinkedHashMap<>();
            for (HttpHeader h : requestToBeSent.headers()) {
                headersMap.put(h.name(), h.value());
            }
            reqMap.put("headers", headersMap);
            
            // Extract service details
            Map<String, Object> serviceMap = new HashMap<>();
            serviceMap.put("host", requestToBeSent.httpService().host());
            serviceMap.put("port", requestToBeSent.httpService().port());
            serviceMap.put("secure", requestToBeSent.httpService().secure());
            reqMap.put("service", serviceMap);

            // Cast Java map to native Clojure persistent structure
            clojure.lang.IPersistentMap clojureReq = clojure.lang.PersistentHashMap.create(reqMap);

            // Invoke Clojure function with the request map and global atom state
            Object result = clojureFunction.invoke(clojureReq, clojureStateAtom);

            if (result instanceof Map) {
                Map<?, ?> resMap = (Map<?, ?>) result;
                HttpRequest updatedRequest = requestToBeSent;

                // 1. Method
                if (resMap.containsKey("method")) {
                    updatedRequest = updatedRequest.withMethod(String.valueOf(resMap.get("method")));
                }

                // 2. Service (host, port, secure)
                if (resMap.containsKey("service")) {
                    Map<?, ?> sMap = (Map<?, ?>) resMap.get("service");
                    if (sMap != null) {
                        String host = String.valueOf(sMap.get("host"));
                        int port = ((Number) sMap.get("port")).intValue();
                        boolean secure = (Boolean) sMap.get("secure");
                        updatedRequest = updatedRequest.withService(burp.api.montoya.http.HttpService.httpService(host, port, secure));
                    }
                }

                // 3. Path / Query
                String path = resMap.containsKey("path") ? String.valueOf(resMap.get("path")) : requestToBeSent.path();
                String query = resMap.containsKey("query") ? (resMap.get("query") != null ? String.valueOf(resMap.get("query")) : null) : requestToBeSent.query();
                if (query != null && !query.trim().isEmpty()) {
                    updatedRequest = updatedRequest.withPath(path + "?" + query);
                } else {
                    updatedRequest = updatedRequest.withPath(path);
                }

                // 4. Headers (Safely clear and rebuild)
                if (resMap.containsKey("headers")) {
                    Map<?, ?> newHeadersMap = (Map<?, ?>) resMap.get("headers");
                    if (newHeadersMap != null) {
                        for (HttpHeader h : requestToBeSent.headers()) {
                            updatedRequest = updatedRequest.withRemovedHeader(h.name());
                        }
                        for (Map.Entry<?, ?> entry : newHeadersMap.entrySet()) {
                            String name = String.valueOf(entry.getKey());
                            String value = String.valueOf(entry.getValue());
                            updatedRequest = updatedRequest.withAddedHeader(name, value);
                        }
                    }
                }

                // 5. Body
                if (resMap.containsKey("body")) {
                    Object bodyObj = resMap.get("body");
                    if (bodyObj != null) {
                        if (bodyObj instanceof byte[]) {
                            updatedRequest = updatedRequest.withBody(burp.api.montoya.core.ByteArray.byteArray((byte[]) bodyObj));
                        } else {
                            updatedRequest = updatedRequest.withBody(String.valueOf(bodyObj));
                        }
                    }
                }

                return updatedRequest;
            } else {
                logging.logToError("BurpLisp error: Clojure function did not return a valid map structure.");
            }
        } finally {
            Thread.currentThread().setContextClassLoader(originalClassLoader);
        }
        return null;
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        return ResponseReceivedAction.continueWith(responseReceived);
    }
}
