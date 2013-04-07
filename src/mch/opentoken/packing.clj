;; Binary structure packing and unpacking
(ns mch.opentoken.packing
  (:require [gloss core io]))

(def opentoken-version 1)
(def opentoken-literal "OTK")
(def opentoken-standard-pairs {"subject" ""
                               "not-before" ""
                               "not-on-or-after" ""
                               "renew-until" ""})

(def opentoken-frame-keys [:otk :version :cipher-suite :hmac :iv :key-info :payload])

(def opentoken-frame [(gloss.core/string :utf-8 :length 3)
                      :byte
                      :byte
                      (gloss.core/finite-block 20)
                      (gloss.core/finite-block :byte)
                      (gloss.core/finite-block :byte)
                      (gloss.core/finite-block :int16)])

;; I wonder if gloss is not able to extract the payload properly because the length is in network order
;; It looks like it is, bytes [0 -64] are interpreted as a int16 of 192. But there may be problems
;; at the limits. 

(gloss.core/defcodec opentoken opentoken-frame)

(def payload-len-frame {:payload-len :int16})
(gloss.core/defcodec payload-len-codec payload-len-frame)

(defn create-frame [version cipher-suite hmac iv key-info payload]
  (.array (gloss.io/contiguous (gloss.io/encode opentoken
                                                [opentoken-literal
                                                 version
                                                 cipher-suite
                                                 hmac
                                                 iv
                                                 key-info
                                                 payload]))))

(defn decode-frame [token]
  (gloss.io/decode opentoken token))

(defn buffer-to-array [b]
  (if (nil? b)
    b
    (let [in (first b)
          l (.limit in)
          out (byte-array l)]
      (.get in out 0 l)
      out)))

