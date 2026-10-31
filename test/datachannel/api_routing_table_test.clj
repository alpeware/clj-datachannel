(ns datachannel.api-routing-table-test
  (:require [clojure.test :refer [deftest is testing]]
            [datachannel.api :as api]))

(deftest test-routing-table-ttl-reaper
  (testing "The routing table background reaper drops stale, closed, disconnected, and idle peers"
    (let [opts {:port 5005}
          listener-node (api/listen! opts {})
          routing-table (:routing-table listener-node)
          now (System/currentTimeMillis)]
      (try
        ;; 1. Unverified stale connection (>30s)
        (swap! routing-table assoc "mock-unverified"
               {:state-atom (atom {:state :connected
                                   :ice-connection-state :new
                                   :last-stun-received (- now 31000)})})
        ;; 2. Closed connection even if ice-connection-state is :connected
        (swap! routing-table assoc "mock-closed"
               {:state-atom (atom {:state :closed
                                   :ice-connection-state :connected
                                   :last-stun-received now})})
        ;; 3. Disconnected / failed connection
        (swap! routing-table assoc "mock-disconnected"
               {:state-atom (atom {:state :connected
                                   :ice-connection-state :disconnected
                                   :last-stun-received now})})
        (swap! routing-table assoc "mock-failed"
               {:state-atom (atom {:state :connected
                                   :ice-connection-state :failed
                                   :last-stun-received now})})
        ;; 4. Idle connection (>60s) even if :ice-connection-state is :connected
        (swap! routing-table assoc "mock-idle-60s"
               {:state-atom (atom {:state :connected
                                   :ice-connection-state :connected
                                   :last-stun-received (- now 61000)})})
        ;; 5. Healthy active connection (should NOT be reaped)
        (swap! routing-table assoc "mock-healthy"
               {:state-atom (atom {:state :connected
                                   :ice-connection-state :connected
                                   :last-stun-received now})})

        ;; Wait a little over 10 seconds for the background reaper to run its 10s cycle
        (Thread/sleep 11000)

        (is (= #{"mock-healthy"} (set (keys @routing-table)))
            "Only the healthy active connection should remain in the routing table")
        (finally
          (api/close! listener-node))))))
