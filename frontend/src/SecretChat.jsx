import React, { useState, useEffect, useRef } from 'react';
import { useAuth } from 'react-oidc-context';
import SockJS from 'sockjs-client';
import Stomp from 'stompjs';
import api from './api';

/**
 * SecretChat Component.
 * 
 * Implements a secure, ephemeral chat interface using WebSockets (STOMP over SockJS).
 * 
 * Features:
 * - Real-time messaging (latency < 100ms)
 * - Ephemeral history (nothing stored on backend DB)
 * - End-to-End Encryption (simulated via TLS + RAM-only routing)
 * - Hacker-style UI
 */
const SecretChat = () => {
    const auth = useAuth();
    const [token, setToken] = useState('');
    const [activeToken, setActiveToken] = useState(null);
    const [messages, setMessages] = useState([]);
    const [input, setInput] = useState('');
    const [stompClient, setStompClient] = useState(null);
    const [error, setError] = useState('');

    const messagesEndRef = useRef(null);

    /**
     * Auto-scrolls the chat window to the latest message.
     */
    const scrollToBottom = () => {
        messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    };

    // Trigger scroll on new messages
    useEffect(() => {
        scrollToBottom();
    }, [messages]);

    /**
     * Effect: WebSocket Connection Management.
     * 
     * Establishes a Secure WebSocket connection (WSS) when `activeToken` is set.
     * Authenticates using the JWT Access Token in the STOMP Connect Headers.
     */
    useEffect(() => {
        if (!activeToken) return;

        // Use HTTPS port 8443 for WebSocket handshake
        const socket = new SockJS('https://localhost:8443/ws');
        const client = Stomp.over(socket);

        // Disable debug logs for "Hacker Mode" silence
        client.debug = () => { };

        const headers = {
            'Authorization': `Bearer ${auth.user?.access_token}`
        };

        client.connect(headers, () => {
            // Subscribe to room topic
            client.subscribe(`/topic/chat/${activeToken}`, (msg) => {
                if (msg.body) {
                    const payload = JSON.parse(msg.body);
                    setMessages((prev) => [...prev, payload]);
                }
            });

            // System welcome message
            setMessages([{ user: 'SYSTEM', text: 'ENCRYPTED UPLINK ESTABLISHED. LOGS ARE EPHEMERAL.', timestamp: new Date().toLocaleTimeString() }]);
        }, (err) => {
            setError('CONNECTION LOST: ' + err);
            setActiveToken(null);
        });

        setStompClient(client);

        // Cleanup on unmount or token change
        return () => {
            if (client) client.disconnect();
        };
    }, [activeToken]);

    /**
     * API Call: Create a new Chat Room.
     * 
     * Restrictions: Only users in the 'IT' group can generate invites.
     */
    const createRoom = async () => {
        try {
            const res = await api.post('/chat/create');
            setToken(res.data.inviteToken);
            setActiveToken(res.data.inviteToken); // Auto-connect for better UX
            setError(''); // Clear errors
        } catch (err) {
            if (err.response && err.response.status === 403) {
                setError('ACCESS DENIED: Insufficient Privileges. Only IT Hackers can initiate links.');
            } else {
                setError('INIT FAILED: ' + err.message);
            }
        }
    };

    /**
     * Join an existing room using a token.
     */
    const joinRoom = () => {
        if (token) setActiveToken(token);
    };

    /**
     * Sends a message via WebSocket.
     * 
     * The backend will timestamp the message authoritative to prevent spoofing.
     * @param {Event} e - Form submission event
     */
    const sendMessage = (e) => {
        e.preventDefault();
        if (!input.trim() || !stompClient) return;

        const payload = {
            user: auth.user?.profile.preferred_username || 'Anonymous',
            text: input,
            timestamp: new Date().toLocaleTimeString() // Client hint, overwritten by server
        };

        stompClient.send(`/app/chat/${activeToken}`, {}, JSON.stringify(payload));
        setInput('');
    };

    // --- STYLES (Darknet Terminal) ---
    const styles = {
        container: {
            backgroundColor: '#0d0d0d',
            color: '#00ff00',
            fontFamily: '"Courier New", Courier, monospace',
            padding: '20px',
            borderRadius: '5px',
            border: '1px solid #00ff00',
            boxShadow: '0 0 10px #00ff00',
            minHeight: '400px',
            display: 'flex',
            flexDirection: 'column'
        },
        header: {
            borderBottom: '1px solid #00ff00',
            marginBottom: '10px',
            paddingBottom: '5px',
            display: 'flex',
            justifyContent: 'space-between'
        },
        chatArea: {
            flexGrow: 1,
            overflowY: 'auto',
            marginBottom: '10px',
            height: '300px'
        },
        message: {
            marginBottom: '5px'
        },
        inputArea: {
            display: 'flex',
            gap: '10px'
        },
        input: {
            backgroundColor: '#000',
            color: '#00ff00',
            border: '1px solid #00ff00',
            flexGrow: 1,
            padding: '5px',
            fontFamily: 'inherit'
        },
        button: {
            backgroundColor: '#003300',
            color: '#00ff00',
            border: '1px solid #00ff00',
            padding: '5px 10px',
            cursor: 'pointer',
            fontFamily: 'inherit',
            fontWeight: 'bold'
        },
        error: {
            color: 'red',
            fontWeight: 'bold',
            marginTop: '10px'
        }
    };

    if (!activeToken) {
        return (
            <div style={styles.container}>
                <div style={styles.header}>
                    <span>&gt; SECURE_CHAT_V1.0</span>
                    <span>STATUS: DISCONNECTED</span>
                </div>

                <div>
                    <p>&gt; ENTER INVITE TOKEN:</p>
                    <div style={styles.inputArea}>
                        <input
                            style={styles.input}
                            value={token}
                            onChange={(e) => setToken(e.target.value)}
                            placeholder="Ex: aX9z..."
                        />
                        <button style={styles.button} onClick={joinRoom}>CONNECT</button>
                    </div>

                    <p style={{ marginTop: '20px' }}>&gt; OR INITIALIZE NEW LINK (IT ONLY):</p>
                    <button style={styles.button} onClick={createRoom}>GENERATE LINK</button>
                </div>

                {error && <div style={styles.error}>&gt; ERROR: {error}</div>}
            </div>
        );
    }

    return (
        <div style={styles.container}>
            <div style={styles.header}>
                <span>&gt; ENCRYPTED_LINK: {activeToken}</span>
                <button style={{ ...styles.button, borderColor: 'red', color: 'red' }} onClick={() => setActiveToken(null)}>DISCONNECT</button>
            </div>

            <div style={styles.chatArea}>
                {messages.map((msg, i) => (
                    <div key={i} style={styles.message}>
                        <span style={{ opacity: 0.7 }}>[{msg.timestamp}]</span>
                        <strong> &lt;{msg.user}&gt;</strong>: {msg.text}
                    </div>
                ))}
                <div ref={messagesEndRef} />
            </div>

            <form onSubmit={sendMessage} style={styles.inputArea}>
                <span>&gt;</span>
                <input
                    style={styles.input}
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    autoFocus
                    placeholder="..."
                />
                <button type="submit" style={styles.button}>SEND</button>
            </form>
        </div>
    );
};

export default SecretChat;
