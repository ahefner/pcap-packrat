
(asdf:defsystem :packrat
  :depends-on (:plokami)
  :serial t
  :components ((:file "package")
               (:file "constants")
               (:file "binary")
               (:file "packrat")
               (:file "app")))
