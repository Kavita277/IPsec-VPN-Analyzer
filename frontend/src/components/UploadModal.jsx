import React, { useState } from "react";
import { UploadIcon, XIcon, FileTextIcon, CheckCircleIcon, AlertTriangleIcon } from "./Icons.jsx";

export default function UploadModal({ isOpen, onClose, onUpload, policy, health }) {
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadError, setUploadError] = useState("");
  const [uploadSuccess, setUploadSuccess] = useState(false);

  if (!isOpen) return null;

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const validateFile = (file) => {
    if (!file) return false;
    const name = file.name.toLowerCase();
    const validExts = [".pcap", ".pcapng", ".cap", ".json"];
    const hasValidExt = validExts.some((ext) => name.endsWith(ext));
    if (!hasValidExt) {
      setUploadError("Unsupported file type. Please upload a .pcap, .pcapng, .cap, or .json file.");
      return false;
    }
    if (name.endsWith(".pcap") || name.endsWith(".pcapng") || name.endsWith(".cap")) {
      if (health && !health.pcap_upload) {
        setUploadError("PCAP upload is disabled on the server because tshark is not installed. You can still upload analysis .json files.");
        return false;
      }
    }
    setUploadError("");
    return true;
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      if (validateFile(file)) {
        setSelectedFile(file);
      }
    }
  };

  const handleChange = (e) => {
    e.preventDefault();
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      if (validateFile(file)) {
        setSelectedFile(file);
      }
    }
  };

  const handleProceed = async () => {
    if (!selectedFile) return;
    setIsUploading(true);
    setUploadError("");
    try {
      await onUpload(selectedFile);
      setUploadSuccess(true);
      setTimeout(() => {
        setIsUploading(false);
        setUploadSuccess(false);
        setSelectedFile(null);
        onClose();
      }, 700);
    } catch (err) {
      setUploadError(err.message || "Failed to process upload.");
      setIsUploading(false);
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose} role="dialog" aria-modal="true" aria-labelledby="modal-title">
      <div className="modal-card" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title-wrap">
            <div className="modal-icon-badge">
              <UploadIcon size={20} />
            </div>
            <div>
              <h3 id="modal-title" className="modal-title">Upload Session</h3>
              <p className="modal-subtitle">Upload packet capture or analysis JSON</p>
            </div>
          </div>
          <button type="button" className="btn-icon" onClick={onClose} aria-label="Close modal">
            <XIcon size={18} />
          </button>
        </div>

        <div className="modal-body">
          {health && !health.pcap_upload && (
            <div className="alert-banner warning">
              <AlertTriangleIcon size={16} />
              <span>Note: tshark is not detected on server. Only analysis <code>.json</code> files can be analyzed.</span>
            </div>
          )}

          {uploadError && (
            <div className="alert-banner error" role="alert">
              <AlertTriangleIcon size={16} />
              <span>{uploadError}</span>
            </div>
          )}

          {uploadSuccess && (
            <div className="alert-banner success">
              <CheckCircleIcon size={16} />
              <span>File processed successfully! Loading session...</span>
            </div>
          )}

          <div
            className={`dropzone ${dragActive ? "drag-active" : ""} ${selectedFile ? "has-file" : ""}`}
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
          >
            <input
              type="file"
              id="modal-file-input"
              accept=".pcap,.pcapng,.cap,.json"
              onChange={handleChange}
              className="dropzone-input"
            />
            <label htmlFor="modal-file-input" className="dropzone-content">
              {selectedFile ? (
                <div className="dropzone-selected">
                  <div className="dropzone-file-icon">
                    <FileTextIcon size={32} />
                  </div>
                  <div className="dropzone-file-info">
                    <span className="dropzone-file-name">{selectedFile.name}</span>
                    <span className="dropzone-file-size">{(selectedFile.size / 1024).toFixed(1)} KB</span>
                  </div>
                </div>
              ) : (
                <>
                  <div className="dropzone-icon">
                    <UploadIcon size={28} />
                  </div>
                  <p className="dropzone-prompt">
                    <strong>Click to browse</strong> or drag and drop capture file
                  </p>
                  <p className="dropzone-formats">Supports .pcap, .pcapng, .cap, .json (max 25 MB)</p>
                </>
              )}
            </label>
          </div>

          <div className="modal-policy-notice">
            <span>Evaluating under current policy: <strong>{policy}</strong></span>
          </div>
        </div>

        <div className="modal-footer">
          <button type="button" className="btn btn-secondary" onClick={onClose} disabled={isUploading}>
            Cancel
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={handleProceed}
            disabled={!selectedFile || isUploading}
          >
            {isUploading ? "Analyzing..." : "Analyze File"}
          </button>
        </div>
      </div>
    </div>
  );
}
