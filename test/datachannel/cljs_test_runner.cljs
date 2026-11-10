(ns datachannel.cljs-test-runner
  "Node.js ClojureScript test runner for clj-datachannel portable Sans-IO namespaces."
  (:require [cljs.test :as test :refer-macros [run-tests]]
            [datachannel.cljc-sans-io-test]))

(def ^{:doc "Atom holding aggregate test run summary."} summary-atom
  (atom {:fail 0 :error 0 :pass 0 :test 0}))

(defmethod test/report [::test/default :summary] [m]
  (reset! summary-atom m)
  (println "\nRan" (:test m) "tests containing"
           (+ (:pass m) (:fail m) (:error m)) "assertions.")
  (println (:fail m) "failures," (:error m) "errors."))

(defmethod test/report [::test/default :end-run-tests] [_m]
  (let [{:keys [fail error]} @summary-atom]
    (if (and (zero? fail) (zero? error))
      (.exit js/process 0)
      (.exit js/process 1))))

(defn -main
  "Main entry point for Node.js ClojureScript test runner."
  [& _args]
  (println "Running clj-datachannel ClojureScript tests on Node.js...")
  (run-tests 'datachannel.cljc-sans-io-test))

(set! *main-cli-fn* -main)
