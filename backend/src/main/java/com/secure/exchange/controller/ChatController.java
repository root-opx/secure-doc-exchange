package com.secure.exchange.controller;

import com.secure.exchange.service.ChatService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.handler.annotation.DestinationVariable;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.access.prepost.PreAuthorize;
import com.secure.exchange.service.AuditService;

import java.util.List;
import java.util.Map;

/**
 * Controller for the Secure "Darknet" Chat.
 * <p>
 * Combines:
 * <ul>
 * <li><b>REST API</b> for Room Creation (Invitation Logic).</li>
 * <li><b>WebSocket/STOMP</b> for Real-Time Messaging.</li>
 * </ul>
 * </p>
 */
@RestController
@RequestMapping("/api/chat")
public class ChatController {

    private final ChatService chatService;
    private final AuditService auditService;

    public ChatController(ChatService chatService, AuditService auditService) {
        this.chatService = chatService;
        this.auditService = auditService;
    }

    /**
     * Initializes a new Secure Chat Room.
     * <p>
     * Restriction: Only members of the 'IT' department (Hackers) can initiate new
     * rooms.
     * </p>
     *
     * @param auth    The JWT Authentication.
     * @param request The HttpServletRequest.
     * @return Map containing the 'inviteToken' if successful.
     */
    @PostMapping("/create")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, String>> createRoom(Authentication auth, HttpServletRequest request) {
        System.out.println("DEBUG: createRoom called. Auth: " + auth);
        String group = extractGroup(auth);
        String ipAddress = request.getRemoteAddr();
        System.out.println("DEBUG: Extracted Group: " + group);

        if (!"IT".equals(group)) {
            // AUDIT LOG: ACCESS DENIED
            auditService.logEvent(auth.getName(), "CREATE_CHAT_DENIED", "Group: " + group, ipAddress, false);

            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "Access Denied: Only IT hackers can initialize darknet links."));
        }

        String token = chatService.createRoom();

        // AUDIT LOG: SUCCESS
        auditService.logEvent(auth.getName(), "CREATE_CHAT_ROOM", token, ipAddress, true);

        return ResponseEntity.ok(Map.of("inviteToken", token));
    }

    /**
     * WebSocket Endpoint for handling chat messages.
     * <p>
     * Mapped to: /app/chat/{roomId}<br>
     * Broadcasts to: /topic/chat/{roomId}
     * </p>
     * <p>
     * <b>Security Note:</b> Detailed AuthZ checks happen in WebSocketConfig
     * ChannelInterceptor.
     * This controller performs logic validation (Room Existence) and Timestamp
     * Authority.
     * </p>
     *
     * @param roomId  The RoomInviteToken extracted from the destination path.
     * @param message The JSON payload sent by the client (expects 'text').
     * @return The same message, enriched with authoritative server timestamp.
     */
    @MessageMapping("/chat/{roomId}")
    @SendTo("/topic/chat/{roomId}")
    public Map<String, String> sendMessage(@DestinationVariable String roomId, Map<String, String> message) {
        System.out.println("DEBUG: sendMessage called. RoomID: " + roomId + ", Msg: " + message);

        // Validate room exists
        boolean exists = chatService.roomExists(roomId);
        if (!exists) {
            throw new SecurityException("Chat Room does not exist or has been burned.");
        }

        // ENFORCE Server-Side Timestamp (Don't trust client)
        message.put("timestamp", new java.util.Date().toString());

        // Return message payload to subscribers
        return message;
    }

    /**
     * Helper to extract the Department Group from the JWT Claims.
     * TODO: Refactor this into a shared Utility in the next sprint.
     *
     * @param auth The Spring Authentication object.
     * @return The group string (e.g. "IT", "HR").
     */
    private String extractGroup(Authentication auth) {
        if (auth.getPrincipal() instanceof Jwt jwt) {
            if (jwt.hasClaim("groups")) {
                Object groups = jwt.getClaims().get("groups");
                if (groups instanceof List<?> list && !list.isEmpty()) {
                    String group = list.get(0).toString();
                    return group.startsWith("/") ? group.substring(1) : group;
                }
            }
        }
        return "UNKNOWN";
    }
}
