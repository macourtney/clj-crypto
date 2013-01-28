(ns clj-crypto.test.symmetric-algorithm
  (:use [clj-crypto.symmetric-algorithm]
        [clojure.test])
  (:import [java.security KeyPair]))

(deftest password-encrypt-decrypt
  (let [password "password"
        data "secret text"
        algorithm des-algorithm
        encrypted-data (password-encrypt password data algorithm)]
    (is (not (= data encrypted-data)) "Text not encrypted.")
    (is (= data (password-decrypt password encrypted-data algorithm)) "Text not decrypted."))
  (let [password "password blah blah blah blah blah blah blah blah"
        data "secret text"
        algorithm triple-des-algorithm
        encrypted-data (password-encrypt password data algorithm)]
    (is (not (= data encrypted-data)) "Text not encrypted.")
    (is (= data (password-decrypt password encrypted-data algorithm)) "Text not decrypted.")))
