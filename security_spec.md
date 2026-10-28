# Sentinel AC — Zero-Trust Firestore Security Specification (`security_spec.md`)

## 1. Data Invariants

1. **Default-Deny Catch-All**: No read or write is permitted on any path unless explicitly matched and validated.
2. **Verified Identity**: Every write operation requires an authenticated user with `request.auth != null && request.auth.token.email_verified == true`.
3. **Path Variable Hardening**: Every single-document target path ID (`adminId`, `userId`, `deviceId`, `eventId`, `incidentId`, `ruleId`, `logId`) must match `^[a-zA-Z0-9_\-]+$` and have `.size() >= 1 && .size() <= 128`.
4. **PII Isolation (`users/{userId}`)**: User profiles contain `email` and `displayName`. Reading `users/{userId}` is strictly restricted to the document owner (`request.auth.uid == userId`) or a verified administrator (`isAdmin()`). Self-assigned `Administrator` roles by non-admins are blocked on creation and update.
5. **Strict Key & Type Blueprints (`hasAll` / `hasOnly`)**: Every entity creation validates exact key presence (`hasAll` and `hasOnly`), string bounds, numeric bounds, and enum membership. No shadow fields are permitted.
6. **Action-Based Updates (`affectedKeys().hasOnly(...)`)**: Every update begins with `isValid[Entity](incoming())`, verifies immutable fields (`ownerId`, `createdAt`, primary ID), enforces `incoming().updatedAt == request.time`, and restricts modified fields to explicit action allowlists.
7. **Immutable Telemetry & Audit Trails**: `events/{eventId}` and `auditLogs/{logId}` are append-only (`allow update, delete: if false;`).
8. **Secure List Queries (`allow list`)**: No blanket `allow list: if isSignedIn()`. Every `allow list` enforces `resource.data.ownerId == request.auth.uid || isAdmin()`.

---

## 2. The "Dirty Dozen" Adversarial Payloads

### Payload 1: Shadow Field Injection on Incident Creation
```json
{
  "collection": "/incidents/inc_001",
  "operation": "create",
  "payload": {
    "incidentId": "inc_001",
    "ownerId": "user_1",
    "isVerified": true
  },
  "expected": "PERMISSION_DENIED (Blocked by keys().hasOnly())"
}
```

### Payload 2: Unverified Email Spoof of Bootstrapped Admin
```json
{
  "collection": "/admins/user_spoof",
  "operation": "get",
  "auth": { "uid": "user_spoof", "email": "shubhamdas6789@gmail.com", "email_verified": false },
  "expected": "PERMISSION_DENIED (Blocked by email_verified == true check)"
}
```

### Payload 3: Cross-User PII Scraping on `/users/{userId}`
```json
{
  "collection": "/users/victim_uid",
  "operation": "get",
  "auth": { "uid": "attacker_uid", "email": "attacker@example.com", "email_verified": true },
  "expected": "PERMISSION_DENIED (Blocked by isOwner(userId) || isAdmin())"
}
```

### Payload 4: Self-Privilege Escalation in `/users/{userId}`
```json
{
  "collection": "/users/attacker_uid",
  "operation": "update",
  "payload": { "role": "Administrator" },
  "expected": "PERMISSION_DENIED (Blocked by affectedKeys().hasOnly(['displayName', 'updatedAt']) for non-admins)"
}
```

### Payload 5: Identity Spoofing (`ownerId` Mismatch on Device Registration)
```json
{
  "collection": "/devices/dev_01",
  "operation": "create",
  "auth": { "uid": "attacker_uid" },
  "payload": { "deviceId": "dev_01", "ownerId": "other_user_uid" },
  "expected": "PERMISSION_DENIED (Blocked by data.ownerId == request.auth.uid)"
}
```

### Payload 6: Value Poisoning on Incident Update (`analystNotes` > 2000 chars)
```json
{
  "collection": "/incidents/inc_001",
  "operation": "update",
  "payload": { "analystNotes": "<3000-byte string>" },
  "expected": "PERMISSION_DENIED (Blocked by isValidIncident(incoming()) size check)"
}
```

### Payload 7: Tampering with Immutable `createdAt` Timestamp on Incident Update
```json
{
  "collection": "/incidents/inc_001",
  "operation": "update",
  "payload": { "createdAt": "2020-01-01T00:00:00Z" },
  "expected": "PERMISSION_DENIED (Blocked by incoming().createdAt == existing().createdAt)"
}
```

### Payload 8: Forged Client Timestamp on Creation (`createdAt != request.time`)
```json
{
  "collection": "/events/evt_001",
  "operation": "create",
  "payload": { "createdAt": "2099-01-01T00:00:00Z" },
  "expected": "PERMISSION_DENIED (Blocked by data.createdAt == request.time)"
}
```

### Payload 9: Modifying or Deleting an Immutable Audit Log Record
```json
{
  "collection": "/auditLogs/log_001",
  "operation": "update",
  "payload": { "details": "Cleared log" },
  "expected": "PERMISSION_DENIED (allow update, delete: if false)"
}
```

### Payload 10: ID Poisoning Attack (`{deviceId}` with Path Traversal / Special Chars)
```json
{
  "collection": "/devices/dev$bad!id",
  "operation": "create",
  "expected": "PERMISSION_DENIED (Blocked by isValidId(deviceId))"
}
```

### Payload 11: Unauthorized Blanket List Query on `/devices`
```json
{
  "collection": "/devices",
  "operation": "list",
  "auth": { "uid": "attacker_uid" },
  "query": "collection('devices') without ownerId filter",
  "expected": "PERMISSION_DENIED (Blocked by resource.data.ownerId == request.auth.uid || isAdmin())"
}
```

### Payload 12: Rule Update with Missing Cryptographic Signature Hash
```json
{
  "collection": "/rules/PROC-001",
  "operation": "update",
  "payload": { "signatureHash": "short" },
  "expected": "PERMISSION_DENIED (Blocked by data.signatureHash.size() >= 16)"
}
```
