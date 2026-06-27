// src/utils/response.ts

const CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Upgrade, Sec-WebSocket-Protocol, X-caBLE-Client-Payload"
};

/**
 * Constructs a Response with universal CORS headers.
 */
export function createResponse(body: BodyInit | null, status: number, extraHeaders?: HeadersInit): Response {
    const headers = new Headers(CORS_HEADERS);
    
    if (extraHeaders) {
        const extra = new Headers(extraHeaders);
        extra.forEach((value, key) => headers.set(key, value));
    }
    
    return new Response(body, { status, headers });
}

/**
 * Constructs a standard error response.
 */
export function createError(message: string, status: number): Response {
    return createResponse(message, status);
}

/**
 * Constructs a standard OPTIONS preflight response.
 */
export function createOptionsResponse(): Response {
    return createResponse(null, 204);
}