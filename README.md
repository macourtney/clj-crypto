# clj-crypto

The clj-crypto library is a Clojure wrapper for the Java Bouncy Castle encryption library.


## Installation
`clj-crypto` is available is available as a Maven artifact from 
![Clojars Project](https://img.shields.io/clojars/v/clj-crypto.svg)

To use, simply add
`[clj-crypto "1.0.2"]`
to your `project.clj`

## Usage

```clojure
(:require [clj-crypto.core :as crypto])
```

To read your pkcs12 certificate store:

```clojure
(def keypair (crypto/get-key-pair-pkcs12 pkcs12-store passwd alias))
```
This will use the 'Bouncy Castle' as your crypto-provider.
If you want to use another, you can supply that as well like so:

```clojure
(def keypair (crypto/get-key-pair-pkcs12 pkcs12-store passwd alias crypto/sun-provider)) ; use SunJSSE
```
To obtain your private-key from a key-pair, drop in to java, like so:

```clojure
(def private-key (.getPrivate keypair)
```

To sign a message with your private key:

```clojure
(crypto/sign private-key msg
             crypto/sha256-signature-algorithm
             crypto/default-provider)
```

Of course, you also have your standard functions for base64 encoding
```clojure
(crypto/decode-base64 (crypto/encode-base64-as-str (.getBytes "sikrit")))
```


## License

Copyright (C) 2012 Matt Courtney

Distributed under the Eclipse Public License, the same as Clojure.
