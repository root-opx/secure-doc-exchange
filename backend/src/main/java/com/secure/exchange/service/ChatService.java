package com.secure.exchange.service;

import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service for managing secure, ephemeral chat sessions.
 * <p>
 * This service implements the "Darknet" concept:
 * <ul>
 * <li>Chat Rooms exist only in RAM.</li>
 * <li>No history is ever persisted to database or disk.</li>
 * <li>When the server restarts, all conversations are obliterated.</li>
 * </ul>
 * </p>
 */
@Service
public class ChatService {

    /**
     * In-Memory Ephemeral Storage.
     * <p>
     * Key: RoomID (Invite Token)<br>
     * Value: Creation Timestamp (Long)
     * </p>
     */
    private final Map<String, Long> activeRooms = new ConcurrentHashMap<>();

    /**
     * Cryptographically secure random number generator for invite tokens.
     */
    private final SecureRandom random = new SecureRandom();

    /**
     * Creates a new ephemeral chat room.
     *
     * @return A secure, randomly generated Invite Token (Room ID).
     */
    public String createRoom() {
        // Generate a random 128-bit Invite Token (acts as Room ID)
        byte[] bytes = new byte[16];
        random.nextBytes(bytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

        activeRooms.put(token, System.currentTimeMillis());

        System.out.println("DEBUG: ChatService created room: " + token + ". Active rooms: " + activeRooms.size());
        return token;
    }

    /**
     * Checks if a chat room exists and is active.
     *
     * @param token The Invite Token of the room.
     * @return true if room exists, false otherwise.
     */
    public boolean roomExists(String token) {
        return activeRooms.containsKey(token);
    }

    /**
     * Destroys a chat room.
     *
     * @param token The Invite Token to destroy.
     */
    public void closeRoom(String token) {
        activeRooms.remove(token);
    }
}
