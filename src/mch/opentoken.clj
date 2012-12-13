(ns mch.opentoken)

(defn encode [payload & {:keys [cipher iv] :or {cipher :aes-256 iv nil}}]
  nil)

(defn decode [payload & {:keys [cipher iv] :or {cipher :aes-256 iv nil}}]
  nil)
