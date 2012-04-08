;;;; Load/dump application. Implement command-line interface.

(in-package :packrat)

(defun dump-executable ()
  (sb-ext:save-lisp-and-die 
   "packrat" 
   :executable t
   :save-runtime-options t
   :toplevel 
   (lambda ()
     (setf *print-length* 200
           *print-circle* t)
     (sb-sys:ignore-interrupt sb-unix:sigpipe)
     (execute-command (rest sb-ext:*posix-argv*))
     (sb-ext:quit))))

(defun execute-command (args &aux (*read-eval* nil))
  (cond
    ((null args)
     (format t "Usage:
  packrat strip INFILE OUTFILE [FACTOR=0.5]
  packrat minimize INFILE OUTFILE
  packrat flows FILENAME
  packrat tcp-flags-test FILENAME
  packrat tcp-port-traffic FILENAME
  packrat protocols FILENAME
  packrat compress-logs [--verbose] [--report-only] 
                        [--unit-size MEGABYTES=100] 
                        [--size-bound MEGABYTES=4000]
"))
    ((and (string= (first args) "strip")
          (<= 3 (length args) 4))
     (destructuring-bind (infile outfile &optional (factor "0.5")) (rest args)
       (filter-pcap infile outfile :factor (read-from-string factor))))
    ((and (string= (first args) "minimize")
          (= 3 (length args)))
     (destructuring-bind (infile outfile) (rest args)
       (minimize-pcap infile outfile)))
    ((and (string= (first args) "flows")
          (= 2 (length args)))
     (filter-pcap (second args) nil :report-only t))
    ((and (string= (first args) "tcp-flags-test")
          (= 2 (length args)))
     (tcp-flags-test (second args) -1))
    ((and (string= (first args) "protocols")
          (= 2 (length args)))
     (collect-stats (second args))
     (print-stats-report))
    ((and (string= (first args) "tcp-port-traffic")
          (= 2 (length args)))
     (collect-stats (second args))
     (tcp-stats-report))
    ((string= (first args) "compress-logs")
     (pop args)
     (let (report-only 
           verbose 
           (unit-size (* 100 (expt 2 20)))
           (size-bound (* 4 (expt 2 30)))
           (logs (sorted-log-listing "*")))
       (loop while args
             as switch = (pop args) do
             (cond
               ((equal switch "--verbose") (setf verbose t))
               ((equal switch "--report-only") (setf report-only t))
               ((and args (equal switch "--unit-size"))
                (let* ((arg (pop args))
                       (x (parse-integer arg :junk-allowed t)))
                  (unless x
                    (format t "Not an integer: ~A~%" arg)
                    (sb-ext:quit))
                  (setf unit-size (* x (expt 2 20)))))
               ((and args (equal switch "--size-bound"))
                (let* ((arg (pop args))
                       (x (parse-integer arg :junk-allowed t)))
                  (unless x
                    (format t "Not an integer: ~A~%" arg)
                    (sb-ext:quit))
                  (setf size-bound (* x (expt 2 20)))))
               (t (format t "Invalid argument: ~A~%" switch)
                  (sb-ext:quit))))
       #+NIL
       (when verbose 
         (format t "~&Log files:~%~{  ~A~%~}~%" logs))
       (compress-logs logs size-bound unit-size
                      :verbose verbose
                      :report-only report-only)))
    (t (format t "~&Invalid arguments.~%"))))
