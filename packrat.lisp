;;;; Packrat packet capture file filter

(in-package :packrat)

;;; Compile with high safety, to ensure that type and array bounds
;;; checking is performed.
(declaim (optimize (speed 1) (safety 3) (debug 2) (space 0)))

;;; Various information and statistics gathered at runtime. They're
;;; preserved between runs in these global tables so that I can
;;; examine them at my leisure.
(defvar *packet-type-counts* (make-array (expt 2 16)))
(defvar *ip-type-counts* (make-array (expt 2 8)))
(defvar *total-read* 0)
(defvar *total-packets* 0)
(defvar *max-size* 0)
(defvar *src-address-bytes*)
(defvar *dst-address-bytes*)
(defvar *src-address-count*)
(defvar *dst-address-count*)
(defvar *source-port-bytes*)
(defvar *flow-table*)

(define-binary-accessors (ethernet :alignment 0)
  (dest 48)
  (src 48)
  (type 16))

(defun find-ip-header (vector &optional (offset 0))
  (case (ethernet-type vector offset)
    ;; Somewhat arbitrary, just hardcoded some protocols I expect to see on my network and
    ;; warn on anything else (even though, strictly speaking, there's plenty of protocols
    ;; in that list we should just ignore silently).
    (#.+IPV4+ (+ offset (ethernet-size-bits)))
    (#.+ARP+  nil)
    (#.+IPV6+ nil)
    (#.+IPX+  nil)
    (#.+EAP-802.1+ nil)
    ((#x60 #x61 #x62 #x63) nil)         ; Funky loopback packets (??)
    (6 nil)                             ; Mystery ethernet broadcasts on my LAN..
    (t #+NIL (break "Unhandled ethernet type: ~X" (ethernet-type vector offset))
       nil)))

(define-binary-accessors (ipv4 :alignment 0 :safety 0)
  (version 4)
  (ihl 4)
  (tos 8)
  (len 16)
  (id 16)
  (flags 3)                             ; Check these.
  (frag 13)
  (ttl 8)
  (proto 8)
  (checksum 16)
  (src 32)
  (dst 32)
  (:assert-position 160))

(define-binary-accessors (tcp :alignment 0)
  (src-port 16)
  (dst-port 16)
  (seq-number 32)
  (ack-number 32)
  (data-offset 4)
  (:skip 6)                             ; Skipped ECN..
  (urg 1)
  (ack 1)
  (psh 1)
  (rst 1)
  (syn 1)
  (fin 1)
  (window-size 16)
  (checksum 16)
  (urgent-seq 16)
  (:assert-position 160))

(defun find-tcp-header (buffer iphdr)
  (and iphdr
       (= 6 (ipv4-proto buffer iphdr))
       ;;(prog1 t (break "~A ~A" (ipv4-ihl buffer iphdr) (+ iphdr (* 32 (ipv4-ihl buffer iphdr)))))
       (+ iphdr (* 32 (ipv4-ihl buffer iphdr)))))
 
;; On lappy, only the first 1414338 packets of the huge log are readable.. stupid failing disk.
 
(defun collect-stats (&optional (filename "/root/huge-eth1log") (max-packets -1))
  (setf *total-read* 0
        *max-size* 0
        *src-address-count* (make-hash-table :test 'equal)
        *dst-address-count* (make-hash-table :test 'equal)
        *src-address-bytes* (make-hash-table :test 'equal)
        *dst-address-bytes* (make-hash-table :test 'equal)
        *source-port-bytes* (make-array (expt 2 16) :initial-element 0)
        *packet-type-counts* (make-array (expt 2 16) :initial-element 0)
        *ip-type-counts* (make-array (expt 2 8) :initial-element 0))
  (plokami:with-pcap-reader (reader filename)
    (plokami:set-filter reader "")
    (plokami:capture reader max-packets
      (lambda (sec usec caplen len buffer)
        (declare (ignorable sec usec caplen))
        (incf *total-read* len)
        (incf (aref *packet-type-counts* (ethernet-type buffer 0)))
        (setf *max-size* (max *max-size* len))
        (let* ((iphdr (find-ip-header buffer))
               (tcphdr (and iphdr (find-tcp-header buffer iphdr)))
               (src (and iphdr (ipv4-src buffer iphdr)))
               (dst (and iphdr (ipv4-dst buffer iphdr))))
          (when iphdr
            (incf (aref *ip-type-counts* (ipv4-proto buffer iphdr)))
            (incf (gethash src *src-address-count* 0))
            (incf (gethash dst *dst-address-count* 0))
            (incf (gethash src *src-address-bytes* 0) len)
            (incf (gethash dst *dst-address-bytes* 0) len)
            (when tcphdr
              ;;(break "sp ~A dp ~A" (tcp-src-port buffer tcphdr) (tcp-dst-port buffer tcphdr))
              (incf (aref *source-port-bytes* (tcp-src-port buffer tcphdr)) len))))))))

(defun print-stats-report ()
  (fresh-line)
  (format t "Total data: ~:D bytes~%" *total-read*)
  ;;(format t "Total packets: ~:D~%" *total-packets*)
  (format t "~%Ethernet protocols observed:~%")
  (loop for protocol upfrom 0 for count across *packet-type-counts*
        unless (zerop count)
        do (format t "~& ~4X: ~9:D packets -- ~A~%"
                   protocol count (or (etherproto-name protocol) "?")))
  (format t "~%IP protocols observed:~%")
  (loop for protocol upfrom 0 for count across *ip-type-counts*
        unless (zerop count)
        do (format t "~& ~4X: ~9:D packets -- ~A~%"
                   protocol count (or (ipproto-name protocol) "?"))))

(defun tcp-stats-report ()
  (format t "~&Traffic per TCP source port:~%")
  (loop for port upfrom 0 for bytes across *source-port-bytes*
        unless (zerop bytes)
        do (format t "~& ~5D: ~13:D bytes~%" port bytes)))


(defun tcp-flags-test (&optional (filename "/root/huge-eth1log") (max-packets 1000))
  (plokami:with-pcap-reader (reader filename)
    (plokami:set-filter reader "")
    (plokami:capture reader max-packets
      (lambda (sec usec caplen len buffer)
        (declare (ignorable sec usec caplen))
        (let* ((iphdr (find-ip-header buffer))
               (tcphdr (and iphdr (find-tcp-header buffer iphdr)))
               (src (and iphdr (ipv4-src buffer iphdr)))
               (dst (and iphdr (ipv4-dst buffer iphdr))))
          (when iphdr
            (when tcphdr
              (format t "~& ~15@A:~D~23T->~15@A:~D~50T~4D ~A ~A ~A ~A ~A ~A~%"
                      (ip->string src) (tcp-src-port buffer tcphdr)
                      (ip->string dst) (tcp-dst-port buffer tcphdr)
                      len
                      (if (zerop (tcp-syn buffer tcphdr)) "   " "SYN")
                      (if (zerop (tcp-psh buffer tcphdr)) "   " "PSH")
                      (if (zerop (tcp-ack buffer tcphdr)) "   " "ACK")
                      (if (zerop (tcp-fin buffer tcphdr)) "   " "FIN")
                      (if (zerop (tcp-rst buffer tcphdr)) "   " "RST")
                      (if (zerop (tcp-urg buffer tcphdr)) "   " "URG")))))))))

(defun hash-to-list (hash)
  (let ((accum nil))
    (maphash (lambda (key value)
               (push (list key value) accum))
             hash)
    accum))

(defun profile-packet-capture (filename)
  (plokami:with-pcap-reader (reader filename)
    (plokami:set-filter reader "")
    (handler-case
       (plokami:capture reader  -1
         (lambda (sec usec caplen len buffer)
           (declare (ignorable sec usec caplen))
           (incf *total-read* len)
           (incf *total-packets*)
           (incf (aref *packet-type-counts* (ethernet-type buffer 0)))
           (setf *max-size* (max *max-size* len))
           (let* ((iphdr (find-ip-header buffer))
                  (tcphdr (and iphdr (find-tcp-header buffer iphdr)))
                  (src (and iphdr (ipv4-src buffer iphdr)))
                  (dst (and iphdr (ipv4-dst buffer iphdr))))
             (when iphdr
               (when tcphdr
                 (incf (gethash (list src (tcp-src-port buffer tcphdr)
                                      dst (tcp-dst-port buffer tcphdr))
                                *flow-table*
                                0)
                       len))))))
      (plokami:capture-file-error (err)
        (format t "~&~A~%" err)))))

(defun filter-pcap-flows (infile outfile killed-flows)
  "Filter a PCAP file by eliminating the identified traffic flows"
  (let ((dropped-packets 0))
    (plokami:with-pcap-reader (reader infile)
      (plokami:set-filter reader "")
      (handler-case
        (plokami:with-pcap-writer (writer outfile)
          (plokami:capture reader  -1
            (lambda (sec usec caplen len buffer)
              (declare (ignorable sec usec caplen))
              (incf *total-read* len)
              (incf (aref *packet-type-counts* (ethernet-type buffer 0)))
              (setf *max-size* (max *max-size* len))
              (let* ((iphdr (find-ip-header buffer))
                     (tcphdr (and iphdr (find-tcp-header buffer iphdr)))
                     (src (and iphdr (ipv4-src buffer iphdr)))
                     (dst (and iphdr (ipv4-dst buffer iphdr))))
                (cond
                  ((and iphdr tcphdr)
                   (if (gethash (list src (tcp-src-port buffer tcphdr)
                                      dst (tcp-dst-port buffer tcphdr))
                                killed-flows)
                       (incf dropped-packets)
                       (plokami:dump writer buffer :length len :origlength len :sec sec :usec usec)))
                  (t (plokami:dump writer buffer :length len :origlength len :sec sec :usec usec)))))))
        (plokami:capture-file-error (err)
          (format t "~&~A~%" err))))
    dropped-packets))

(defun ip->string (ip)
  (format nil "~D.~D.~D.~D"
          (ldb (byte 8 24) ip)
          (ldb (byte 8 16) ip)
          (ldb (byte 8 8) ip)
          (ldb (byte 8 0) ip)))

(defun print-flow-table (table &optional (stream *standard-output*))
  (maphash 
   (lambda (flow length)
     (destructuring-bind (src-ip src-port dst-ip dst-port) flow
       (format stream "~& ~15@A:~D~23T->~15@A:~D ~48T~10:D bytes~%"
               (ip->string src-ip) src-port (ip->string dst-ip) dst-port length)))
   table))

(defun filter-pcap (infile outfile &key (factor 0.5) (report-only nil))
  ;;; Initialize
  (setf *total-read* 0
        *flow-table* (make-hash-table :test 'equal))
  ;;; Profiling pass
  (profile-packet-capture infile)
  ;;; Decide what to eliminate
  (let* ((flows (sort (hash-to-list *flow-table*) #'> :key #'second))
         (killed-flows (make-hash-table :test 'equal))
         (total (reduce #'+ flows :key #'second))
         (current total)
         dropped-packets
         (target (round (* total factor))))
    (format t "~&Total packets: ~:D~%Total data: ~:D bytes~%" *total-packets* total)
    (unless report-only
      (format t "~&Factor: ~D~%Target: ~:D bytes~%" factor target))
    (format t "~&~:D observed traffic flows~%" (length flows))

    (loop while (> current target)
          for flow in flows do
          (setf (gethash (first flow) killed-flows) (second flow))
          (decf current (second flow)))

    (format t (if report-only "~&Identified ~:D flows (~:R percentile):~%" "~&Dropping ~:D flows (~:R percentile)~%")
            (hash-table-count killed-flows)
            (truncate (* 100 (- 1.0 factor))))
    (print-flow-table killed-flows)
    
    ;;; Compression/rewrite pass
    (unless report-only
      (format t "~&Writing filtered output to ~A..~%" outfile)
      (setf dropped-packets (filter-pcap-flows infile outfile killed-flows))
      (format t "Done. Dropped ~A packets." dropped-packets))))

(defun minimize-pcap (infile outfile)
  "Minimize packet capture by stripping all non-SYN/FIN/RST TCP packets"
  (let ((dropped-packets 0))
    (plokami:with-pcap-reader (reader infile)
      (plokami:set-filter reader "")
      (handler-case
        (plokami:with-pcap-writer (writer outfile)
          (plokami:capture reader  -1
            (lambda (sec usec caplen len buffer)
              (declare (ignorable sec usec caplen))
              (let* ((iphdr (find-ip-header buffer))
                     (tcphdr (and iphdr (find-tcp-header buffer iphdr))))
                (cond
                  ((and iphdr tcphdr                        
                        (zerop (tcp-syn buffer tcphdr))
                        (zerop (tcp-rst buffer tcphdr))
                        (zerop (tcp-fin buffer tcphdr)))
                   ;; Drop these packets
                   (values))
                   (t (plokami:dump writer buffer :length len :origlength len :sec sec :usec usec)))))))
        (plokami:capture-file-error (err)
          (format t "~&~A~%" err))))
    dropped-packets))
  

(defun file-size (filename)
  (with-open-file (in filename :element-type '(unsigned-byte 8))
    (file-length in)))

;;; Allocate 1/3 of storage to raw captures.
;;; Allocate 1/3 of storage to stripped captures.
;;; Allocate 1/3 of storage to minimal captures.
;;; This isn't very well thought out.

(defun compress-logs (sorted-files size-bound unit-size &key verbose report-only)
  (let* ((total (reduce #'+ sorted-files :key #'file-size)))
    (cond 
     (t ;;(> total size-bound)
      (loop with accum-size = 0
            with stripped-partition = (truncate size-bound 3)
            with minimal-partition = (truncate (* 2 size-bound) 3)
            with stripped-size = (round (* 0.15 unit-size))
            for file in sorted-files
            for filename = (pathname-name file)
            as file-size = (file-size file)
            do
            (cond
              ;; Raw files
              ((< (+ file-size accum-size) stripped-partition)
               (when verbose (format t "~&~7A ~13:D bytes ~30T Raw~%" filename file-size))
               (incf accum-size file-size))
              ;; Stripped files
              ((< (+ accum-size file-size) minimal-partition)
               (cond
                 ((<= file-size stripped-size)
                  (when verbose
                    (format t "~&~7A ~13:D bytes ~30T Already stripped.~%" filename file-size)))
                 (report-only
                  ;; TODO: We could run the filter process in report-only mode here and
                  ;; get a better estimate of the resulting size. Oh well.
                  (when verbose
                    (format t "~&~7A ~13:D bytes ~30T Stripped (estimate ~:D)~%" 
                            filename file-size stripped-size))
                  (incf file-size stripped-size))
                 (t (rename-file file "tmplog")
                    (filter-pcap "tmplog" (sb-ext:native-namestring file) :factor 0.15)
                    (delete-file "tmplog")
                    (incf accum-size (file-size file))
                    (when verbose (format t "~&~7A ~13:D bytes ~30T Stripped to ~:D~%"
                                          filename file-size (file-size file))))))
              ((< (+ accum-size file-size) size-bound)
               (cond
                 ((and verbose report-only)
                  (format t "~&~7A ~13:D bytes ~30T Minimal~%" filename file-size))
                 ((not report-only)
                  (rename-file file "tmplog")
                  (minimize-pcap "tmplog" (sb-ext:native-namestring file))
                  (delete-file "tmplog")
                  (format t "~&~7A ~13:D bytes ~30T Minimized to ~:D~%"
                          filename file-size (file-size file)))))
              (t (when verbose 
                   (format t "~&~7A ~13:D bytes ~30T Scheduled for deletion.~%" filename file-size))
                 (unless report-only
                   (delete-file file))))))
     (verbose (format t "~&Total storage ~:D is less than size bound of ~:D. Doing nothing.~%" 
                      total size-bound)))))

(defun unsorted-log-listing (dir)
  (remove-if-not (lambda (name)
                   (or (string= name "log")
                       (eql 3 (mismatch name "log"))))
                 (directory dir)
                 :key #'pathname-name))

(defun name-key (name)
  (if (= 3 (length name))
      0
      (or (parse-integer name :start 3 :junk-allowed t)
          (error "~&Log file \"~A\" has unparsable name. Aborting.~%" name))))

(defun sorted-log-listing (dir)
  (sort (copy-list (unsorted-log-listing dir))
        #'> :key (lambda (pn) (name-key (pathname-name pn)))))
