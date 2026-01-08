import React, { useState, useEffect } from "react";
import { useAuth } from "react-oidc-context";
import api, { setAuthToken } from "./api";

import SecretChat from "./SecretChat";

/**
 * Main Application Component.
 * 
 * Orchestrates the Zero Trust Document Exchange UI.
 * 
 * Responsibilities:
 * - OIDC Authentication (Login/Logout/Token Management)
 * - Navigation (Files / Chat / Admin Logs)
 * - File Operations (Upload, Decrypt, Delete)
 * - Admin Auditing
 */
function App() {
  const auth = useAuth();

  // --- STATE MANAGEMENT ---
  const [file, setFile] = useState(null);
  const [documents, setDocuments] = useState([]);
  const [uploadKey, setUploadKey] = useState("");

  // View State: 'documents' or 'chat'
  const [view, setView] = useState('documents');
  const [isUploading, setIsUploading] = useState(false);

  // UX State
  const [notification, setNotification] = useState(null); // { message, type: 'info' | 'error' }
  const [keyTimer, setKeyTimer] = useState(0); // Countdown for key visibility

  // Admin State
  const [auditLogs, setAuditLogs] = useState([]);

  // Modal State
  const [decryptModal, setDecryptModal] = useState({ show: false, docId: null, filename: '' });
  const [deleteModal, setDeleteModal] = useState({ show: false, docId: null });
  const [decryptKeyInput, setDecryptKeyInput] = useState('');

  /**
   * Helper to show temporary notifications.
   * @param {string} msg - The message to display.
   * @param {'info' | 'error' | 'success'} type - Notification style.
   */
  const showNotify = (msg, type = 'info') => {
    setNotification({ message: msg, type });
    // Auto-hide notification after 5s
    setTimeout(() => setNotification(null), 5000);
  };

  // Effect: Ephemeral Key Timer
  // Counts down and destroys the encryption key from memory after 20 seconds.
  useEffect(() => {
    let interval = null;
    if (uploadKey && keyTimer > 0) {
      interval = setInterval(() => {
        setKeyTimer((prev) => prev - 1);
      }, 1000);
    } else if (keyTimer === 0) {
      setUploadKey(""); // Burn the key
    }
    return () => clearInterval(interval);
  }, [uploadKey, keyTimer]);

  /**
   * Admin Action: Fetch System Audit Logs.
   * Protected by Backend RBAC (Only 'Admin' role can succeed).
   */
  const fetchAuditLogs = async () => {
    try {
      const res = await api.get("/audit-logs");
      setAuditLogs(res.data);
    } catch (err) {
      showNotify("ACCESS DENIED: ADMIN ONLY", 'error');
      setView('documents');
    }
  };

  // Effect: Initial Auth & Data Fetch
  useEffect(() => {
    if (auth.isAuthenticated) {
      setAuthToken(auth.user?.access_token);
      fetchDocuments();
    }
  }, [auth.isAuthenticated, auth.user]);

  // Effect: Fetch Logs when switching to Admin View
  useEffect(() => {
    if (view === 'admin') {
      fetchAuditLogs();
    }
  }, [view]);

  /**
   * Fetch documents visible to the current user.
   * Note: The backend enforces Departmental Segregation (BOLA).
   */
  const fetchDocuments = async () => {
    try {
      // Add timestamp to prevent caching
      const res = await api.get(`/documents?t=${new Date().getTime()}`);
      setDocuments(res.data);
    } catch (err) {
      console.error("Error fetching docs", err);
    }
  };

  /**
   * Handle Secure File Upload.
   * 
   * Steps:
   * 1. Send file to backend
   * 2. Backend Scans & Encrypts
   * 3. Backend returns the One-Time Key
   * 4. Display Key to User
   */
  const handleUpload = async () => {
    if (!file) return showNotify("PLEASE_SELECT_FILE", 'error');

    setIsUploading(true); // Start Loading

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await api.post("/documents", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      // CRITICAL: Show the key to the user
      setUploadKey(res.data.decryptionKey);
      setKeyTimer(20); // 20 Seconds Countdown
      showNotify("UPLOAD SUCCESSFUL. SECURE KEY GENERATED.", 'info');

      // Wait a moment for DB consistency then fetch
      setTimeout(() => fetchDocuments(), 500);
    } catch (err) {
      showNotify("UPLOAD FAILED: " + (err.response?.data?.message || err.message), 'error');
    } finally {
      setIsUploading(false); // Stop Loading
    }
  };

  // Toggle Decryption Modal
  const handleDecryptClick = (id, filename) => {
    setDecryptModal({ show: true, docId: id, filename });
    setDecryptKeyInput('');
  };

  /**
   * Execute Decryption logic.
   * Sends the user-provided key to the backend.
   * Logic: The backend attempts AES-GCM decryption. If Auth Tag validates, file is returned.
   */
  const executeDecryption = async () => {
    if (!decryptKeyInput) return showNotify("ENTER DECRYPTION KEY", 'error');

    const cleanKey = decryptKeyInput.trim();

    try {
      const res = await api.post(`/documents/${decryptModal.docId}/download`, { key: cleanKey }, {
        responseType: "blob", // Important for binary files
      });

      // Create a download link programmatically
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", "decrypted_" + decryptModal.filename);
      document.body.appendChild(link);
      link.click();
      link.remove();

      // Close Modal & Success
      setDecryptModal({ show: false, docId: null, filename: '' });
      showNotify("DECRYPTION SUCCESSFUL. FILE DOWNLOADED.", 'info');
    } catch (err) {
      showNotify("DECRYPTION FAILED. ACCESS DENIED OR WRONG KEY.", 'error');
    }
  };

  // Toggle Delete Modal
  const requestDelete = (id) => {
    setDeleteModal({ show: true, docId: id });
  };

  /**
   * Execute Document Deletion.
   * Only success if User is Admin AND belongs to the Department.
   */
  const executeDelete = async () => {
    try {
      await api.delete(`/documents/${deleteModal.docId}`);
      showNotify("FILE DELETED.", 'success');
      setDeleteModal({ show: false, docId: null });
      fetchDocuments();
    } catch (err) {
      showNotify("DELETE FAILED: " + (err.response?.status === 403 ? "ACCESS DENIED" : err.message), 'error');
    }
  };

  if (auth.isLoading) return <div>Loading...</div>;

  if (!auth.isAuthenticated) {
    return (
      <div style={{ padding: "50px", textAlign: "center", color: "#00ff00" }}>
        <h1>&gt; SECURE ZERO TRUST EXCHANGE</h1>
        <p>AUTHENTICATION REQUIRED</p>
        <button onClick={() => auth.signinRedirect()}>[ ACCESS GATEWAY ]</button>
      </div>
    );
  }

  // Helper to decode Access Token (Client-Side)
  // Used for UI adaptation (e.g., showing Admin buttons)
  // Security Note: Real enforcement is done on the Backend.
  const parseJwt = (token) => {
    try {
      return JSON.parse(atob(token.split('.')[1]));
    } catch (e) {
      return null;
    }
  };

  const isChat = view === 'chat';
  const isAdmin = view === 'admin';

  // Check Access Token for 'realm_access.roles'
  let hasAdminRole = false;
  if (auth.user?.access_token) {
    const decoded = parseJwt(auth.user.access_token);
    hasAdminRole = decoded?.realm_access?.roles?.includes('admin');
  }

  return (
    <div className="container">
      {/* HEADER */}
      <header className="header-nav">
        <div style={{ fontSize: '1.2rem', fontWeight: 'bold', border: 'none', padding: 0 }}>
           SECURE_DOC_EXCHANGE :: User > {auth.user?.profile.preferred_username}
        </div>
        <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
          <button onClick={() => setView('documents')} className={view === 'documents' ? 'active-nav' : ''}> FILES </button>
          <button onClick={() => setView('chat')} className={isChat ? 'active-nav' : ''}> SECRET_CHAT </button>

          {hasAdminRole && (
            <button onClick={() => setView('admin')} className={isAdmin ? 'active-nav' : ''} style={{ color: 'orange', borderColor: 'orange' }}> ADMIN_LOGS </button>
          )}

          <button onClick={() => auth.signoutRedirect({ post_logout_redirect_uri: window.location.origin })} style={{ borderColor: 'red', color: 'red', marginLeft: '20px' }}> LOGOUT </button>
        </div>
      </header>

      {/* VIEW: ADMIN LOGS */}
      {isAdmin ? (
        <div className="encryption-zone">
          <h3>&gt; SYSTEM_AUDIT_LOGS_ACCESS</h3>
          <div style={{ maxHeight: '600px', overflowY: 'auto' }}>
            <table className="terminal-table" style={{ tableLayout: 'fixed', fontSize: '0.9rem' }}>
              <thead>
                <tr>
                  <th style={{ width: '50px' }}>ID</th>
                  <th style={{ width: '160px' }}>TIME</th>
                  <th style={{ width: '100px' }}>USER_ID</th>
                  <th style={{ width: '120px' }}>ACTION</th>
                  <th>FILE / RESOURCE</th>
                  <th style={{ width: '80px' }}>STATUS</th>
                  <th style={{ width: '120px' }}>IP</th>
                </tr>
              </thead>
              <tbody>
                {auditLogs.map(log => (
                  <tr key={log.id} style={{ color: log.status === 'FAILURE' ? 'red' : 'inherit' }}>
                    <td>{log.id}</td>
                    <td>{new Date(log.timestamp).toLocaleString()}</td>
                    <td title={log.principal} style={{ cursor: 'help' }}>
                      {log.principal.substring(0, 8)}...
                    </td>
                    <td>{log.action}</td>
                    <td style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }} title={log.resource}>
                      {log.resource}
                    </td>
                    <td>{log.status === 'SUCCESS' ? 'OK' : 'FAIL'}</td>
                    <td>{log.ipAddress}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : isChat ? (
        <SecretChat />
      ) : (
        <>
          {/* SECTION 1: UPLOAD */}
          <div className="container">
            <h3>&gt; UPLOAD DOCUMENT</h3>

            <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
              <input
                id="file-upload"
                type="file"
                onChange={(e) => setFile(e.target.files[0])}
                style={{ display: 'none' }}
              />
              <label htmlFor="file-upload" className="custom-file-upload">
                 BROWSE 
              </label>
              <span style={{ marginRight: '20px' }}>{file ? file.name : 'NO_FILE_SELECTED'}</span>

              <button onClick={handleUpload} disabled={isUploading}>
                {isUploading ? "UPLOADING..." : "UPLOAD_FILE"}
              </button>
            </div>

            {uploadKey && (
              <div className="alert">
                <h4>⚠️ CRITICAL: SAVE ENCRYPTION KEY</h4>
                <p>KEY WILL SELF-DESTRUCT IN: {keyTimer}s</p>
                <div className="code-block">{uploadKey}</div>
                <button onClick={() => { navigator.clipboard.writeText(uploadKey); showNotify("COPIED_TO_CLIPBOARD"); }}>
                  COPY_KEY
                </button>
              </div>
            )}
          </div>

          {/* SECTION 2: LIST */}
          <div className="container">
            {/* NOTIFICATION AREA */}
            {notification && (
              <div className={`alert ${notification.type === 'error' ? 'error' : 'success'}`} style={{ marginBottom: '20px' }}>
                <strong>&gt; SYSTEM_MESSAGE:</strong> {notification.message}
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3>&gt; DEPARTMENT DOCUMENTS</h3>
              <button onClick={fetchDocuments} style={{ fontSize: '0.8rem', padding: '2px 8px' }}> REFRESH_LIST </button>
            </div>
            <table>
              <thead>
                <tr>
                  <th>FILENAME</th>
                  <th>DEPARTMENT</th>
                  <th>TIMESTAMP</th>
                  <th>ACTION</th>
                </tr>
              </thead>
              <tbody>
                {documents.map((doc) => (
                  <tr key={doc.id}>
                    <td>{doc.filename}</td>
                    <td>{doc.departmentGroup}</td>
                    <td>{new Date(doc.uploadedAt).toLocaleString()}</td>
                    <td>
                      <button onClick={() => handleDecryptClick(doc.id, doc.filename)}>
                        DECRYPT
                      </button>
                      {hasAdminRole && (
                        <button
                          onClick={() => requestDelete(doc.id)}
                          style={{ marginLeft: '10px', borderColor: 'red', color: 'red' }}>
                          DELETE
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* DECRYPTION MODAL */}
          {decryptModal.show && (
            <div className="modal-overlay">
              <div className="modal-content">
                <h3>&gt; DECRYPT_FILE</h3>
                <p>TARGET: {decryptModal.filename}</p>
                <input
                  type="text"
                  placeholder="ENTER_SECURE_KEY"
                  value={decryptKeyInput}
                  onChange={(e) => setDecryptKeyInput(e.target.value)}
                  autoFocus
                />
                <div style={{ marginTop: '20px' }}>
                  <button onClick={executeDecryption}>[ EXECUTE ]</button>
                  <button onClick={() => setDecryptModal({ show: false, docId: null, filename: '' })} style={{ borderColor: 'red', color: 'red' }}>
                    [ ABORT ]
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* DELETE CONFIRMATION MODAL */}
          {deleteModal.show && (
            <div className="modal-overlay">
              <div className="modal-content" style={{ borderColor: 'red', boxShadow: '0 0 15px red' }}>
                <h3 style={{ color: 'red' }}>&gt; WARNING: IRREVERSIBLE ACTION</h3>
                <p className="error">CONFIRM DELETION? THIS EVENT WILL BE LOGGED AS A SECURITY AUDIT.</p>
                <div style={{ marginTop: '20px', display: 'flex', gap: '10px', justifyContent: 'center' }}>
                  <button onClick={executeDelete} style={{ borderColor: 'red', color: 'red' }}>[ CONFIRM_DELETE ]</button>
                  <button onClick={() => setDeleteModal({ show: false, docId: null })}>[ CANCEL ]</button>
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

export default App;
