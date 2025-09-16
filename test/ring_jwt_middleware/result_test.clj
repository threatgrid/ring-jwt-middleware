(ns ring-jwt-middleware.result-test
  (:require [ring-jwt-middleware.result :as sut]
            [clojure.test :as t :refer [deftest is]]))

(deftest let-either-test
  (let [state (atom nil)]
    (is (= {:jwt-error {:error :err-code, :error_description "ERROR!"}}
           (sut/let-either [x (sut/->err :err-code "ERROR!" {})
                            y (do (reset! state :I_WAS_HERE)
                                  (inc x))]
             y)))
    (is (nil? @state) "let either fail on first error as expected"))

  (let [state (atom nil)]
    (is (= 1
           (sut/let-either [x (sut/->pure 0)
                            y (do (reset! state x)
                                  (sut/->pure (inc x)))]
             y)))
    (is (= 0 @state) "in case of success should pass")))
