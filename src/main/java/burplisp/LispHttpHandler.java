package burplisp;

import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
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
    private volatile IFn clojureResponseFunction;
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

    public void setClojureFunctions(Object result) {
        if (result instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) result;
            
            // Resolve Clojure Keyword keys
            Object reqKeyword = clojure.lang.Keyword.intern("request");
            Object resKeyword = clojure.lang.Keyword.intern("response");
            
            Object reqFn = map.get(reqKeyword);
            if (reqFn == null) reqFn = map.get("request"); // String key fallback
            
            Object resFn = map.get(resKeyword);
            if (resFn == null) resFn = map.get("response"); // String key fallback
            
            this.clojureFunction = (reqFn instanceof IFn) ? (IFn) reqFn : null;
            this.clojureResponseFunction = (resFn instanceof IFn) ? (IFn) resFn : null;
            
            logging.logToOutput("Successfully loaded dynamic script map. Request hook: " + (clojureFunction != null) + ", Response hook: " + (clojureResponseFunction != null));
        } else if (result instanceof IFn) {
            this.clojureFunction = (IFn) result;
            this.clojureResponseFunction = null;
            logging.logToOutput("Successfully loaded legacy Clojure function (Request hook only).");
        } else {
            this.clojureFunction = null;
            this.clojureResponseFunction = null;
            logging.logToError("Attempted to set invalid script result: neither map nor function.");
        }
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
        Callable<HttpRequest> task = () -> executeClojureRequestModification(requestToBeSent);
        Future<HttpRequest> future = executorService.submit(task);

        try {
            HttpRequest modifiedRequest = future.get(500, TimeUnit.MILLISECONDS);
            if (modifiedRequest != null) {
                return RequestToBeSentAction.continueWith(modifiedRequest);
            }
        } catch (TimeoutException e) {
            future.cancel(true);
            logging.logToError("BurpLisp request execution timed out (>500ms) for: " + requestToBeSent.url() + ". Skipping modification.");
        } catch (Exception e) {
            logging.logToError("Error during BurpLisp request interception: " + e.getMessage());
        }

        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (!enabled || clojureResponseFunction == null) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        // 1. Tool Filter Check
        ToolType toolType = responseReceived.toolSource().toolType();
        if (toolType == ToolType.PROXY && !proxyEnabled) return ResponseReceivedAction.continueWith(responseReceived);
        if (toolType == ToolType.REPEATER && !repeaterEnabled) return ResponseReceivedAction.continueWith(responseReceived);
        if (toolType == ToolType.INTRUDER && !intruderEnabled) return ResponseReceivedAction.continueWith(responseReceived);
        if (toolType == ToolType.SCANNER && !scannerEnabled) return ResponseReceivedAction.continueWith(responseReceived);

        // 2. Target Scope Filter Check
        if (targetScopeOnly && responseReceived.initiatingRequest() != null) {
            if (!scope.isInScope(responseReceived.initiatingRequest().url())) {
                return ResponseReceivedAction.continueWith(responseReceived);
            }
        }

        // 3. Threaded Clojure Execution with 500ms timeout protection
        Callable<HttpResponse> task = () -> executeClojureResponseModification(responseReceived);
        Future<HttpResponse> future = executorService.submit(task);

        try {
            HttpResponse modifiedResponse = future.get(500, TimeUnit.MILLISECONDS);
            if (modifiedResponse != null) {
                return ResponseReceivedAction.continueWith(modifiedResponse);
            }
        } catch (TimeoutException e) {
            future.cancel(true);
            logging.logToError("BurpLisp response execution timed out (>500ms). Skipping response modification.");
        } catch (Exception e) {
            logging.logToError("Error during BurpLisp response interception: " + e.getMessage());
        }

        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private HttpRequest executeClojureRequestModification(HttpRequestToBeSent requestToBeSent) throws Exception {
        ClassLoader originalClassLoader = Thread.currentThread().getContextClassLoader();
        try {
            ClassLoader extensionClassLoader = this.getClass().getClassLoader();
            Thread.currentThread().setContextClassLoader(extensionClassLoader);

            // Construct Ring-like Request Map
            Map<clojure.lang.Keyword , Object> reqMap = new HashMap<>();

            // すべてClojureのKeywordオブジェクトに変換してキーにする
            clojure.lang.Keyword kMethod = clojure.lang.Keyword.intern("method");
            clojure.lang.Keyword kUrl = clojure.lang.Keyword.intern("url");
            clojure.lang.Keyword kPath = clojure.lang.Keyword.intern("path");
            clojure.lang.Keyword kQuery = clojure.lang.Keyword.intern("query");
            clojure.lang.Keyword kHeaders = clojure.lang.Keyword.intern("headers");
            clojure.lang.Keyword kService = clojure.lang.Keyword.intern("service");
            clojure.lang.Keyword kBody = clojure.lang.Keyword.intern("body");

            reqMap.put(kMethod, requestToBeSent.method());
            reqMap.put(kUrl, requestToBeSent.url());
            reqMap.put(kPath, requestToBeSent.path());
            reqMap.put(kQuery, requestToBeSent.query());
            reqMap.put(kBody, requestToBeSent.bodyToString());
            
            // Extract headers into key-value map
            Map<String, String> headersMap = new HashMap<>();
            for (HttpHeader h : requestToBeSent.headers()) {
                headersMap.put(h.name(), h.value());
            }
            clojure.lang.IPersistentMap clojureHeadersMap = clojure.lang.PersistentHashMap.create(headersMap);
            reqMap.put(kHeaders, clojureHeadersMap);
            
            // Extract service details
            Map<String, Object> serviceMap = new HashMap<>();
            serviceMap.put("host", requestToBeSent.httpService().host());
            serviceMap.put("port", requestToBeSent.httpService().port());
            serviceMap.put("secure", requestToBeSent.httpService().secure());
            clojure.lang.IPersistentMap clojureServiceMap = clojure.lang.PersistentHashMap.create(headersMap);
            reqMap.put(kService, clojureServiceMap);

            // Cast Java map to native Clojure persistent structure
            clojure.lang.IPersistentMap clojureReq = clojure.lang.PersistentHashMap.create(reqMap);

            Object result = clojureFunction.invoke(clojureReq, clojureStateAtom);

            if (result instanceof Map) {
                Map<?, ?> resMap = (Map<?, ?>) result;
                HttpRequest updatedRequest = requestToBeSent;

                // 1. Method
                if (resMap.containsKey(kMethod)) {
                    updatedRequest = updatedRequest.withMethod(String.valueOf(resMap.get(kMethod)));
                }

                // 2. Service (host, port, secure)
                if (resMap.containsKey(kService)) {
                    Map<?, ?> sMap = (Map<?, ?>) resMap.get(kService);
                    if (sMap != null) {
                        String host = requestToBeSent.httpService().host();
                        int port = requestToBeSent.httpService().port();
                        boolean secure = requestToBeSent.httpService().secure();
                        updatedRequest = updatedRequest.withService(burp.api.montoya.http.HttpService.httpService(host, port, secure));
                    }
                }

                // 3. Path / Query
                String path = resMap.containsKey(kPath) ? String.valueOf(resMap.get(kPath)) : requestToBeSent.path();
                String query = resMap.containsKey(kQuery) ? (resMap.get(kQuery) != null ? String.valueOf(resMap.get(kQuery)) : null) : requestToBeSent.query();
                if (query != null && !query.trim().isEmpty()) {
                    updatedRequest = updatedRequest.withPath(path + "?" + query);
                } else {
                    updatedRequest = updatedRequest.withPath(path);
                }

                // 4. Headers (Safely clear and rebuild)
                if (resMap.containsKey(kHeaders)) {
                    Map<?, ?> newHeadersMap = (Map<?, ?>) resMap.get(kHeaders);
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
                if (resMap.containsKey(kBody)) {
                    Object bodyObj = resMap.get(kBody);
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

    private HttpResponse executeClojureResponseModification(HttpResponseReceived responseReceived) throws Exception {
        ClassLoader originalClassLoader = Thread.currentThread().getContextClassLoader();
        try {
            ClassLoader extensionClassLoader = this.getClass().getClassLoader();
            Thread.currentThread().setContextClassLoader(extensionClassLoader);

            // Construct Ring-like Response Map
            Map<String, Object> resMap = new HashMap<>();
            resMap.put("status", (int) responseReceived.statusCode());
            resMap.put("body", responseReceived.bodyToString());
            
            // Map headers
            Map<String, String> headersMap = new LinkedHashMap<>();
            for (HttpHeader h : responseReceived.headers()) {
                headersMap.put(h.name(), h.value());
            }
            resMap.put("headers", headersMap);

            // Include initiating request details in the response map for rich analytical context
            if (responseReceived.initiatingRequest() != null) {
                resMap.put("request", constructRequestMap(responseReceived.initiatingRequest()));
            }

            clojure.lang.IPersistentMap clojureRes = clojure.lang.PersistentHashMap.create(resMap);

            // Invoke Clojure response function
            Object result = clojureResponseFunction.invoke(clojureRes, clojureStateAtom);

            if (result instanceof Map) {
                Map<?, ?> resultMap = (Map<?, ?>) result;
                HttpResponse updatedResponse = responseReceived;

                // 1. Status Code
                if (resultMap.containsKey("status")) {
                    int sc = ((Number) resultMap.get("status")).intValue();
                    updatedResponse = updatedResponse.withStatusCode((short) sc);
                }

                // 2. Headers (Safely clear and rebuild)
                if (resultMap.containsKey("headers")) {
                    Map<?, ?> newHeadersMap = (Map<?, ?>) resultMap.get("headers");
                    if (newHeadersMap != null) {
                        for (HttpHeader h : responseReceived.headers()) {
                            updatedResponse = updatedResponse.withRemovedHeader(h.name());
                        }
                        for (Map.Entry<?, ?> entry : newHeadersMap.entrySet()) {
                            String name = String.valueOf(entry.getKey());
                            String value = String.valueOf(entry.getValue());
                            updatedResponse = updatedResponse.withAddedHeader(name, value);
                        }
                    }
                }

                // 3. Body
                if (resultMap.containsKey("body")) {
                    Object bodyObj = resultMap.get("body");
                    if (bodyObj != null) {
                        if (bodyObj instanceof byte[]) {
                            updatedResponse = updatedResponse.withBody(burp.api.montoya.core.ByteArray.byteArray((byte[]) bodyObj));
                        } else {
                            updatedResponse = updatedResponse.withBody(String.valueOf(bodyObj));
                        }
                    }
                }

                return updatedResponse;
            }
        } finally {
            Thread.currentThread().setContextClassLoader(originalClassLoader);
        }
        return null;
    }

    private Map<String, Object> constructRequestMap(HttpRequest request) {
        Map<String, Object> reqMap = new HashMap<>();
        reqMap.put("method", request.method());
        reqMap.put("url", request.url());
        reqMap.put("path", request.path());
        reqMap.put("query", request.query());
        reqMap.put("body", request.bodyToString());
        
        Map<String, String> headersMap = new LinkedHashMap<>();
        for (HttpHeader h : request.headers()) {
            headersMap.put(h.name(), h.value());
        }
        reqMap.put("headers", headersMap);
        
        Map<String, Object> serviceMap = new HashMap<>();
        serviceMap.put("host", request.httpService().host());
        serviceMap.put("port", request.httpService().port());
        serviceMap.put("secure", request.httpService().secure());
        reqMap.put("service", serviceMap);

        return reqMap;
    }

    private HttpRequest applyRequestModifications(HttpRequestToBeSent requestToBeSent, Map<?, ?> resMap) {
        HttpRequest updatedRequest = requestToBeSent;

        // 1. Method
        if (resMap.containsKey("method")) {
            updatedRequest = updatedRequest.withMethod(String.valueOf(resMap.get("method")));
        }

        // 2. Service
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

        // 4. Headers
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
    }
}
