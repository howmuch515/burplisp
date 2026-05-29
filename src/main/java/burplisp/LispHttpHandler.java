package burplisp;

import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.logging.Logging;
import clojure.lang.IFn;

import java.util.*;

public class LispHttpHandler implements HttpHandler {
    private final Logging logging;
    private volatile IFn clojureFunction;
    private volatile boolean enabled = false;

    public LispHttpHandler(Logging logging) {
        this.logging = logging;
    }

    public void setClojureFunction(IFn clojureFunction) {
        this.clojureFunction = clojureFunction;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        if (!enabled || clojureFunction == null) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        ClassLoader originalClassLoader = Thread.currentThread().getContextClassLoader();
        try {
            // Swap to the extension's classloader to resolve Burp Suite classpath encapsulation issues.
            ClassLoader extensionClassLoader = this.getClass().getClassLoader();
            Thread.currentThread().setContextClassLoader(extensionClassLoader);

            // Get original request headers
            List<HttpHeader> originalHeaders = requestToBeSent.headers();
            
            // Map headers for easy usage in Clojure.
            // Using LinkedHashMap to preserve order of headers and deal with duplicates nicely.
            Map<String, String> headersMap = new LinkedHashMap<>();
            for (HttpHeader h : originalHeaders) {
                headersMap.put(h.name(), h.value());
            }

            // Convert to a native Clojure Map so that assoc/dissoc works natively.
            clojure.lang.IPersistentMap clojureHeaders = clojure.lang.PersistentHashMap.create(headersMap);

            // Invoke Clojure function. e.g., (fn [headers] (assoc headers "X-Clojure" "Value"))
            Object result = clojureFunction.invoke(clojureHeaders);

            if (result instanceof Map) {
                Map<?, ?> newHeadersMap = (Map<?, ?>) result;
                
                // 1. Remove all existing headers
                HttpRequest updatedRequest = requestToBeSent;
                for (HttpHeader h : originalHeaders) {
                    updatedRequest = updatedRequest.withRemovedHeader(h.name());
                }

                // 2. Add all new headers
                for (Map.Entry<?, ?> entry : newHeadersMap.entrySet()) {
                    String name = String.valueOf(entry.getKey());
                    String value = String.valueOf(entry.getValue());
                    updatedRequest = updatedRequest.withAddedHeader(name, value);
                }

                return RequestToBeSentAction.continueWith(updatedRequest);
            } else {
                logging.logToError("Clojure function did not return a Map. Returned type: " + (result != null ? result.getClass().getName() : "null"));
            }
        } catch (Exception e) {
            logging.logToError("Error executing Clojure function: " + e.getMessage());
            java.io.StringWriter sw = new java.io.StringWriter();
            java.io.PrintWriter pw = new java.io.PrintWriter(sw);
            e.printStackTrace(pw);
            logging.logToError(sw.toString());
        } finally {
            // Restore original classloader
            Thread.currentThread().setContextClassLoader(originalClassLoader);
        }

        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        return ResponseReceivedAction.continueWith(responseReceived);
    }
}
