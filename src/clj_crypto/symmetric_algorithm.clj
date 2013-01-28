(ns clj-crypto.symmetric-algorithm
  (:require [clj-crypto.core :as core])
  (:import [java.security MessageDigest]
           [javax.crypto SecretKeyFactory]
           [javax.crypto.spec DESedeKeySpec DESKeySpec]))

;http://stackoverflow.com/questions/339004/java-encrypt-decrypt-user-name-and-password-from-a-configuration-file

(def des-algorithm "DES")
(def triple-des-algorithm "DESede") ; Triple DES algorithm

(def default-symmetrical-algorithm triple-des-algorithm)

(defn prepare-password
  ([password] (prepare-password password 24))
  ([password byte-length]
    (let [message-digest (MessageDigest/getInstance core/default-encrypt-password-algorithm)]
      (.reset message-digest)
      (into-array Byte/TYPE (take byte-length (.digest message-digest (core/get-data-bytes password)))))))

(defn des-key-spec
  "Generates a des key spec from the given password."
  [password]
  (DESKeySpec. (prepare-password password 8)))

(defn triple-des-key-spec
  "Generates a triple des key spec from the given password."
  [password]
  (DESedeKeySpec. (prepare-password password 24)))

(defn des-key
  "Creates a des key from the given password."
  [password]
  (.generateSecret (SecretKeyFactory/getInstance des-algorithm) (des-key-spec password)))

(defn triple-des-key
  "Creates a des key from the given password."
  [password]
  (.generateSecret (SecretKeyFactory/getInstance triple-des-algorithm) (triple-des-key-spec password)))

(defprotocol SymmetricAlgorithm
  "A protocol for symmetric encryption algorithms."
  (algorithm [this] "Returns the algorithm string for this algorithm.")
  (encrypt [this password data] "Encrypts the given data with the given password.")
  (decrypt [this password data] "Decrypts the given data with the given password."))

(deftype DES []
  SymmetricAlgorithm
  (algorithm [_] des-algorithm)
  (encrypt [_ password data] (core/encrypt (des-key password) data (core/create-cipher des-algorithm)))
  (decrypt [_ password data] (core/decrypt (des-key password) data (core/create-cipher des-algorithm))))

(deftype TripleDES []
  SymmetricAlgorithm
  (algorithm [_] triple-des-algorithm)
  (encrypt [_ password data] (core/encrypt (triple-des-key password) data (core/create-cipher triple-des-algorithm)))
  (decrypt [_ password data] (core/decrypt (triple-des-key password) data (core/create-cipher triple-des-algorithm))))

(def des-algorithm-type (new DES))
(def triple-des-algorithm-type (new TripleDES))

(def symetric-algorithms
  { des-algorithm des-algorithm-type
    triple-des-algorithm triple-des-algorithm-type })

(defn find-symetric-algorithm [algorithm]
  (cond
    (string? algorithm) (get symetric-algorithms algorithm)
    (instance? SymmetricAlgorithm algorithm) algorithm
    :else (throw (RuntimeException. (str "Unknown algorithm type: " algorithm)))))

(defn password-encrypt
  ([password data] (password-encrypt password data default-symmetrical-algorithm))
  ([password data algorithm]
    (encrypt (find-symetric-algorithm algorithm) password data)))

(defn password-decrypt
  ([password data] (password-decrypt password data default-symmetrical-algorithm))
  ([password data algorithm]
    (decrypt (find-symetric-algorithm algorithm) password data)))