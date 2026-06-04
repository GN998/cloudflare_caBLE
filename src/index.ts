import { DurableObject } from "cloudflare:workers";

// ========== [ Types & Interfaces ] ==========
export interface Env {
    TUNNEL_ROOM: DurableObjectNamespace;
}

interface SocketAttachment {
    id: string;
    role: "client" | "authenticator";
    replaced?: boolean;
}

interface MsgBufferRow {
    id: number;
    senderId: string;
    data: ArrayBuffer;
}

// ========== [ Durable Object Class ] ==========
export class TunnelRoom extends DurableObject {
    private flushPromise: Promise<void> | null = null;
    declare ctx: DurableObjectState;
    declare env: Env;

    constructor(ctx: DurableObjectState, env: Env) {
        super(ctx, env);
    }

    async fetch(request: Request): Promise<Response> {
        const corsHeaders = { "Access-Control-Allow-Origin": "*" };

        const upgradeHeader = request.headers.get("Upgrade") || "";
        if (upgradeHeader.toLowerCase() !== "websocket") {
            return new Response("Expected Upgrade: websocket", { status: 426, headers: corsHeaders });
        }

        const url = new URL(request.url);
        const path = url.pathname;
        const isContact = path.startsWith("/cable/contact/");
        const isNew = path.startsWith("/cable/custom/");
        const isConnect = path.startsWith("/cable/connect/");

        const isClient = request.headers.has("X-caBLE-Client-Payload") || isConnect;
        const role: "client" | "authenticator" = isClient ? "client" : "authenticator";

        const storedData = await this.ctx.storage.get(["tombstoned", "isContact", "hasPaired"]);

        if (storedData.get("tombstoned")) {
            return new Response("Gone: Tunnel is exhausted and permanently sealed", { status: 410, headers: corsHeaders });
        }

        if (isContact && !storedData.get("isContact")) {
            this.ctx.waitUntil(this.ctx.storage.put("isContact", true).catch(e => console.error("KV put error:", e))); 
            storedData.set("isContact", true); 
        }

        const sockets = this.ctx.getWebSockets();
        const existingSameRole = sockets.find(s => (s.deserializeAttachment() as SocketAttachment)?.role === role);

        if (existingSameRole) {
            const attachment = existingSameRole.deserializeAttachment() as SocketAttachment;
            existingSameRole.serializeAttachment({
                ...attachment,
                replaced: true
            });
            try { 
                existingSameRole.close(1000, "Replaced by new connection"); 
            } catch (e) {}
        } else if (sockets.length >= 2) {
            return new Response("Forbidden: Room is full", { status: 403, headers: corsHeaders });
        }

        const pair = new WebSocketPair();
        const [client, server] = Object.values(pair) as [WebSocket, WebSocket];
        const socketId = crypto.randomUUID();
        server.serializeAttachment({ id: socketId, role } as SocketAttachment);
        
        const activeSocketsBefore = this.ctx.getWebSockets().filter(s => !(s.deserializeAttachment() as SocketAttachment)?.replaced);
        let releaseLock: (() => void) | undefined;
        
        let currentFlushPromise: Promise<void> | null = null;
        if (activeSocketsBefore.length === 1) { 
            currentFlushPromise = new Promise<void>(resolve => { releaseLock = resolve; });
            this.flushPromise = currentFlushPromise;
        }

        try {
            this.ctx.acceptWebSocket(server);

            const activeSockets = this.ctx.getWebSockets().filter(
                s => !(s.deserializeAttachment() as SocketAttachment)?.replaced
            );

            if (activeSockets.length === 1) {
                const ttl = isContact ? (30 * 24 * 60 * 60 * 1000) : (3 * 60 * 1000);
                try {
                    await this.ctx.storage.setAlarm(Date.now() + ttl);
                } catch (e) {
                    console.error("Set alarm failed after accept", e);
                }
            }

            if (activeSockets.length === 2) {
                if (!storedData.get("hasPaired")) {
                    try {
                        await this.ctx.storage.put("hasPaired", true);
                    } catch (e) {
                        console.error("Set hasPaired failed after accept", e);
                    }
                }

                // [Fix 4] Prevent "dirty writes" caused by Zombie Yield.
                // After the `await` above (yielding DO control), this connection might have been instantly marked as `replaced` and discarded by a newly connected connection.
                // If it has been discarded, we absolutely must not continue to SELECT and DELETE handshake frames, otherwise the genuine connection will encounter a state black hole.
                const currentAttachment = server.deserializeAttachment() as SocketAttachment;
                if (!currentAttachment?.replaced) {
                    let bufferToFlush: MsgBufferRow[] = [];
                    try {
                        this.ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS msg_buffer (id INTEGER PRIMARY KEY, senderId TEXT, data BLOB)`);
                        bufferToFlush = this.ctx.storage.sql.exec(`SELECT senderId, data FROM msg_buffer ORDER BY id ASC`).toArray() as MsgBufferRow[];
                        
                        if (bufferToFlush.length > 0) {
                            this.ctx.storage.sql.exec(`DELETE FROM msg_buffer`);
                        }
                    } catch (e) {
                        console.error("Failed to read SQLite buffer", e);
                    }

                    for (const buffered of bufferToFlush) {
                        for (const socket of activeSockets) {
                            const socketAttachment = socket.deserializeAttachment() as SocketAttachment;
                            if (socketAttachment?.id !== buffered.senderId) {
                                try {
                                    socket.send(buffered.data);
                                } catch (e) {
                                    console.warn(`[Room ${this.ctx.id}] Buffered send failed`, e);
                                }
                            }
                        }
                    }
                }
            }
        } finally {
            if (releaseLock) releaseLock();
            if (this.flushPromise === currentFlushPromise && currentFlushPromise !== null) {
                this.flushPromise = null;
            }
        }

        const headers = new Headers();
        headers.set("Access-Control-Allow-Origin", "*");
        
        const requestedProtocols = request.headers.get("Sec-WebSocket-Protocol") || "";
        if (requestedProtocols.includes("fido.cable")) {
            headers.set("Sec-WebSocket-Protocol", "fido.cable"); 
        }

        if (isNew) {
            const bytes = new Uint8Array(3);
            crypto.getRandomValues(bytes);
            const routingId = Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
            headers.set("X-Cable-Routing-Id", routingId);
        }

        return new Response(null, { 
            status: 101, 
            webSocket: client,
            headers: headers 
        });
    }

    async webSocketMessage(ws: WebSocket, message: ArrayBuffer | string) {
        if (typeof message === "string") {
            ws.close(1003, "Unsupported Data: FIDO caBLE requires binary frames");
            return;
        }

        if (message.byteLength > 1048640) {
            ws.close(1009, "Message Too Big: Payload exceeds 1MiB cipher limit");
            return;
        }

        if (this.flushPromise) {
            await this.flushPromise;
        }

        const attachment = ws.deserializeAttachment() as SocketAttachment;
        
        // [Fix 5] Prevent phantom message broadcasting.
        // During the suspension period of `await this.flushPromise`, if this WebSocket has been replaced,
        // its old messages should no longer be broadcast to the currently surviving nodes, to prevent breaking the strict sequential decryption state machine of the Noise protocol.
        if (attachment?.replaced) {
            return;
        }

        const sockets = this.ctx.getWebSockets();
        const senderId = attachment?.id;
        const activeSockets = sockets.filter(s => !(s.deserializeAttachment() as SocketAttachment)?.replaced);

        if (activeSockets.length < 2) {
            try {
                this.ctx.storage.sql.exec(
                    `CREATE TABLE IF NOT EXISTS msg_buffer (id INTEGER PRIMARY KEY, senderId TEXT, data BLOB)`
                );
                
                const countRows = this.ctx.storage.sql.exec(`SELECT count(*) as count FROM msg_buffer`).toArray();
                if ((countRows[0] as any).count < 50) {
                    this.ctx.storage.sql.exec(
                        `INSERT INTO msg_buffer (senderId, data) VALUES (?, ?)`, 
                        senderId, message
                    );
                } else {
                    ws.close(1009, "Message Too Big: Buffer overflow before peer connected");
                }
            } catch (e) {
                console.error("SQLite buffer write error:", e);
                ws.close(1011, "Internal Server Error: Storage failed");
            }
            return;
        }

        for (const socket of activeSockets) {
            const peerAttachment = socket.deserializeAttachment() as SocketAttachment;
            if (peerAttachment?.id !== senderId) {
                try {
                    socket.send(message);
                } catch (err) {}
            }
        }
    }

    async webSocketClose(ws: WebSocket, code: number, reason: string, wasClean: boolean) {
        await this.handleDisconnect(ws);
    }

    async webSocketError(ws: WebSocket, error: any) {
        await this.handleDisconnect(ws);
    }

    async handleDisconnect(ws: WebSocket) {
        const attachment = ws.deserializeAttachment() as SocketAttachment;
        if (attachment?.replaced) {
            return;
        }

        ws.serializeAttachment({
            ...attachment,
            replaced: true
        });

        const sockets = this.ctx.getWebSockets();
        const disconnectedId = attachment?.id;

        for (const sock of sockets) {
            const peerAttachment = sock.deserializeAttachment() as SocketAttachment;
            if (peerAttachment?.id !== disconnectedId) {
                sock.serializeAttachment({
                    ...peerAttachment,
                    replaced: true
                });
                try { 
                    sock.close(1001, "Peer disconnected"); 
                } catch (e) {
                    console.error("Socket close error:", e);
                }
            }
        }

        try {
            this.ctx.storage.sql.exec(`DELETE FROM msg_buffer`);
        } catch (e) {
            // Ignore if table does not exist yet
        }

        const storedData = await this.ctx.storage.get(["isContact", "hasPaired", "tombstoned"]);
        const isContact = storedData.get("isContact");
        const hasPaired = storedData.get("hasPaired");
        const isTombstoned = storedData.get("tombstoned");

        if (!isContact && hasPaired && !isTombstoned) {
            await this.ctx.storage.put("tombstoned", true);
            const CLEANUP_DELAY_MS = 1 * 60 * 1000;
            await this.ctx.storage.setAlarm(Date.now() + CLEANUP_DELAY_MS);
        } else if (isContact) {
            await this.ctx.storage.setAlarm(Date.now() + 30 * 24 * 60 * 60 * 1000);
        }
    }

    async alarm() {
        const sockets = this.ctx.getWebSockets();
        
        for (const sock of sockets) {
            const attachment = sock.deserializeAttachment() as SocketAttachment | null;
            if (attachment) {
                sock.serializeAttachment({
                    ...attachment,
                    replaced: true
                });
            }
            try { 
                sock.close(1000, "Tunnel absolute TTL expired"); 
            } catch (e) {}
        }
        
        try {
            this.ctx.storage.sql.exec(`DROP TABLE IF EXISTS msg_buffer`);
        } catch (e) {
            console.error("Failed to drop msg_buffer table on TTL expire", e);
        }

        await this.ctx.storage.deleteAll();
    }
}

// ========== [ Main Routing Layer ] ==========
export default {
    async fetch(request: Request, env: Env): Promise<Response> {
        // ... (Keep completely unchanged)
        const url = new URL(request.url);
        
        const corsHeaders = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, OPTIONS",
            "Access-Control-Allow-Headers": "Upgrade, Sec-WebSocket-Protocol, X-caBLE-Client-Payload"
        };

        if (request.method === "OPTIONS") {
            return new Response(null, { 
                status: 204, 
                headers: corsHeaders 
            });
        }

        if (request.method !== "GET") {
            return new Response("Method Not Allowed", { status: 405, headers: corsHeaders });
        }

        const upgradeHeader = request.headers.get("Upgrade") || "";
        if (upgradeHeader.toLowerCase() !== "websocket") {
            return new Response("Expected Upgrade: websocket", { status: 426, headers: corsHeaders });
        }

        const protocols = request.headers.get("Sec-WebSocket-Protocol") || "";
        if (!protocols.includes("fido.cable")) {
            return new Response("Forbidden: Invalid WebSocket Protocol", { status: 403, headers: corsHeaders });
        }

        const path = url.pathname;
        const isNew = path.startsWith("/cable/custom/");
        const isConnect = path.startsWith("/cable/connect/");
        const isContact = path.startsWith("/cable/contact/"); 

        if (!isNew && !isConnect && !isContact) {
            return new Response("Not Found: Invalid FIDO endpoint", { status: 404, headers: corsHeaders });
        }

        const parts = path.split("/").filter(Boolean);
        if (parts.length < 3) {
            return new Response("Missing parameters", { status: 400, headers: corsHeaders });
        }

        let identifier;
        if (isConnect) {
            if (parts.length !== 4) return new Response("Bad Request", { status: 400, headers: corsHeaders });
            identifier = parts[3]; 
        } else {
            identifier = parts[parts.length - 1];
        }

        if (isNew || isConnect) {
            if (!/^[a-fA-F0-9]{32}$/.test(identifier)) {
                return new Response("Bad Request: Invalid Tunnel ID format", { status: 400, headers: corsHeaders });
            }
        } else if (isContact) {
            if (!/^[A-Za-z0-9_-]{1,256}$/.test(identifier)) {
                return new Response("Bad Request: Invalid Contact ID format", { status: 400, headers: corsHeaders });
            }
        }

        const namespaceKey = isContact ? "contact:" + identifier : "tunnel:" + identifier;
        const id = env.TUNNEL_ROOM.idFromName(namespaceKey);
        return env.TUNNEL_ROOM.get(id).fetch(request);
    },
};