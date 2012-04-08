(in-package :packrat)

;;;; This is a simple framework for defining bitfield accessors,
;;;; useful in parsing compact binary protocols like the TCP/IP
;;;; family.

(declaim (inline vector-ldb vector-ldb* simple-byte-vector-ldb*))

;;; TODO: These could go much faster still if we can guarantee some
;;; alignment modulo elt-bits (though I don't expect SBCL will figure
;;; this out, nor unroll the loop accordingly).

(defun vector-ldb (byte vector elt-bits)
  (vector-ldb* (byte-size byte) (byte-position byte) vector elt-bits))

(defun vector-ldb* (size position vector elt-bits &optional elt-mod)
  (declare (type (integer 0) size position)
           (type (integer 0 128) elt-bits)
           (ignore elt-mod)
           #+NIL (optimize (speed 3)))
  (loop for index upfrom (truncate position elt-bits)
        for top = (- elt-bits (mod position elt-bits)) then elt-bits
        for remaining-size of-type fixnum = size then (- remaining-size sub-width)
        as sub-width = (min top remaining-size)
        until (zerop remaining-size)
#|        collect (list :index index :boff boff :sub-width sub-width
                      :deposit-offset output-offset
                      :shift (- remaining-size sub-width)) |#
        summing (ash (ldb (byte sub-width (- top sub-width)) (aref vector index))
                     (- remaining-size sub-width))))

(define-compiler-macro vector-ldb* (&whole form size position vector elt-bits &optional elt-mod)
  (declare (ignorable vector))
  (cond
    ((and (constantp size) (constantp elt-bits) elt-mod (constantp elt-mod))
     (let ((size     (eval size))
           (elt-bits (eval elt-bits))
           (elt-mod  (eval elt-mod)))
       `(let* ((vector ,vector)
               (position ,position)
               (base (truncate position ,elt-bits))
               #+bitnanny (modpos (logand position ,(1- elt-bits))))
          #+bitnanny
          (unless (= ,elt-mod modpos)
            (error "Assertion failed: runtime modulus ~X != ~X (asserted modulus) (position=~X) (elt-bits=~D)" 
                   modpos ,elt-mod position ,elt-bits))
          (logior
           ,@(loop for index upfrom 0   ; awesome cut and paste!
                   for top = (- elt-bits elt-mod) then elt-bits
                   for remaining-size = size then (- remaining-size sub-width)
                   as sub-width = (min top remaining-size)
                   until (zerop remaining-size)
                   collect `(ash (ldb (byte ,sub-width ,(- top sub-width)) (aref vector (+ base ,index)))
                                 ,(- remaining-size sub-width)) 
                   into forms
                   finally (print forms) (return forms))))))
    (t form)))

(defun simple-byte-vector-ldb* (size position vector)
  (declare (type (simple-array (unsigned-byte 8) 1) vector)
           (type (integer 0 128) size)
           (type fixnum position))
  (vector-ldb* size position vector 8))

;;; Can we craft an interface (e.g. WITH-TCP-ACCESSORS) that defines
;;; them lexically and allows you to customize things like
;;; element-size, instead of having it baked into the accessors as at
;;; present?

(defmacro define-binary-accessors 
    ((prefix &key debug alignment (element-size 8) (inline t) safety) 
     &rest field-specs)
  (let ((prefix (string prefix))
        (package (symbol-package prefix))
        (position 0)
        (names nil)
        (definitions nil))
    (dolist (spec field-specs)
      (destructuring-bind (type &rest args) spec
        (case type
          (:skip 
           (assert (typep (first args) 'integer))
           (incf position (first args)))
          (:assert-position 
           (unless (= position (first args))
             (error "Position assertion failed while defining ~A: Asserted position=~A, really at ~A"
                    prefix (first args) position)))
          (:align
           (let ((modulus (first args)))
             (assert (typep modulus 'integer))
             (incf position (mod (- modulus position) modulus))))
          (otherwise
           (destructuring-bind (num-bits) args
             (let ((name (intern (format  nil "~A-~A" prefix (string type))
                                 package)))
               (push name names)
               (push `(defun ,name (vector bit-offset #|&optional (bit-offset 0)|#)
                        (declare (optimize (speed 3) ,@(and safety `((safety ,safety))))
                                 (type (simple-array (unsigned-byte ,element-size) 1) vector)
                                 (type fixnum bit-offset))
                        (vector-ldb* ,num-bits (+ bit-offset ,position) vector ,element-size
                                     ,(and alignment (mod (+ alignment position) element-size))))
                     definitions)
               (when debug
                 (format t "~&~A..~A  ~A (~A bit reader)~%" position (+ position num-bits) name num-bits))
               (incf position num-bits)))))))
    (when debug (format t "~&Total size of ~A: ~A bits~%" prefix position))
    (push `(defun ,(intern (format  nil "~A-~A" prefix "SIZE-BITS") package) ()
             ,position)
          definitions)
    `(progn 
       ,(and inline `(declaim (inline ,@names)))
       ,@definitions)))

;;;; Test of accessor definitions:

(define-binary-accessors (test-struct)
  (a 4)
  (b 3)
  (c 11)
  (d 29)
  (e 37)
  (f 1)
  (g 1))

(let (;;(raw-data #b11010001010110010101001001110001011111000011000011100001010110000110000010000100100001)
      (data-bytes (make-array 11 :element-type '(unsigned-byte 8)
                              :fill-pointer nil :adjustable nil
                              :initial-contents 
                              '(#b11010001 #b01011001 #b01010010 #b01110001
                                #b01111100 #b00110000 #b11100001 #b01011000
                                #b01100000 #b10000100 #b10000100)))
      (fields '(#b1101 #b000 #b10101100101 #b01001001110001011111000011000 #b0111000010101100001100000100001001000 #b0 #b1))
      (parsers (list #'test-struct-a #'test-struct-b #'test-struct-c #'test-struct-d #'test-struct-e #'test-struct-f #'test-struct-g)))
  (loop with failures = 0
        for parser in parsers
        for field in fields
        unless (= (funcall parser data-bytes 0) field)
        do 
        (incf failures) 
        (format t "~&Fail: ~B != ~B~%" (funcall parser data-bytes) field)
        finally (unless (zerop failures) (error "~D test failures" failures))))
