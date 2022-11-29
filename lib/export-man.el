;;; export-man.el -- Export man page and filter result

;;; Commentary:
;;;
;;; Exports a man page and filters the result so we can exclude parts of the man
;;; page based on features enabled in the build system.
;;;
;;; The export-man-page function is called from common.mk with --eval

;;; Code:

(require 'ox-man)
(require 'parse-time)

(defvar feature-exclude-tags
  '(("LIBBPF_PERF_BUFFER__CONSUME" . "feat_perfbuf"))
  "Mapping of feature strings to exclude tags for man page export.")

(defvar feature-exclude-regexes
  '(("LIBBPF_PERF_BUFFER__CONSUME" . "--perf-wakeup"))
  "Mapping of feature strings to regexes to filter form export man page.")

(defun get-feature-values (enabled-feats exclude-list)
  "Get feature-tag values for ENABLED-FEATS based on EXCLUDE-LIST."
  (delq nil (mapcar #'(lambda (f)
                      (unless (member (car f) enabled-feats)
                        (cdr f)))
                    exclude-list)))

(defun replace-regexp-in-buffer (regexp replace)
  "Replace REGEXP with REPLACE in buffer."
  (let ((case-fold-search nil))
    (goto-char 0)
    (when (re-search-forward regexp nil t)
      (replace-match replace))))

(defun open-file (filename)
  "Find file FILENAME but complain if it doesn't exist."
  (if (file-exists-p filename)
      (find-file filename)
    (error "File not found: %s" filename)))

(defun get-file-mod-time (filename)
  (let* ((file-modtime (file-attribute-modification-time (file-attributes filename)))
         (git-logtime (ignore-errors (shell-command-to-string
                                      (format "git log -1 --pretty='format:%%cI' -- %s" filename))))
         (git-modtime (ignore-errors (parse-iso8601-time-string git-logtime))))
    (or git-modtime file-modtime)))

(defun filter-post-export (file feat-list version modtime)
  "Post-process exported FILE based on features in FEAT-LIST and VERSION."
  (let ((exclude-regexes (get-feature-values feat-list feature-exclude-regexes))
        (date (format-time-string "%B %_d, %Y" modtime))
        (make-backup-files nil))
    (with-current-buffer (open-file file)
      (mapc #'(lambda (r) (delete-matching-lines r)) exclude-regexes)
      (replace-regexp-in-buffer "DATE" date)
      (replace-regexp-in-buffer "VERSION" version)
      (replace-regexp-in-buffer "^.SH \"\\([^\"]+\\) - \\([^\"]+\\)\""
                                ".SH \"NAME\"\n\\1 \\\\- \\2\n.SH \"SYNOPSIS\"")
      (save-buffer))))

(defun export-man-page (outfile infile enabled-features version)
  "Export man page from INFILE into OUTFILE with ENABLED-FEATURES and VERSION."
  (let* ((feat-list (split-string enabled-features))
         (org-export-exclude-tags (get-feature-values feat-list feature-exclude-tags))
         (modtime (get-file-mod-time infile)))
    (with-current-buffer (open-file infile)
      (org-export-to-file 'man outfile)
      (filter-post-export outfile feat-list version modtime))))

(provide 'export-man)
;;; export-man.el ends here
