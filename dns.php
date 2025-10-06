<?php
/**
 * A production-ready PHP DNS-over-HTTPS (DoH) proxy.
 *
 * This script forwards DoH requests to upstream DNS servers, with support for
 * authentication, caching, rate limiting, and TCP fallback for truncated responses.
 *
 * @version 1.2.0
 * @license MIT
 */

// ===================================================================
//  CONFIGURATION
// ===================================================================

// An array of upstream servers for load balancing/failover.
const UPSTREAM_DNS_SERVERS = ['1.1.1.1', '1.0.0.1'];
const DNS_PORT = 53;
const DNS_TIMEOUT = 5; // In seconds.
const MAX_DNS_REQUEST_SIZE = 1024; // In bytes.
const DNS_RESPONSE_BUFFER = 4096; // In bytes.

// --- Authentication ---
// Set to 'true' to require an authentication token for all requests.
const ENABLE_AUTH = true;
// The secret token clients must provide. Use a strong, randomly generated string.
const AUTH_TOKEN = 'YourSuperSecretAndLongRandomTokenHere';

// --- Caching (requires APCu extension) ---
const ENABLE_CACHE = true;
const CACHE_TTL = 300; // Cache DNS responses for 5 minutes.

// --- Rate Limiting (requires APCu extension) ---
const ENABLE_RATE_LIMIT = true;
const RATE_LIMIT_REQUESTS = 100; // Max requests...
const RATE_LIMIT_TIMEFRAME = 60;  // ...per minute, per IP.


// ===================================================================
//  SECURITY MIDDLEWARE
// ===================================================================

// Authentication Check
if (ENABLE_AUTH) {
    // Token can be provided via 'X-API-Key' header (preferred) or 'auth' GET parameter.
    $providedToken = $_SERVER['HTTP_X_API_KEY'] ?? $_GET['auth'] ?? null;

    // Use hash_equals() for a timing-attack-safe comparison.
    if ($providedToken === null || !hash_equals(AUTH_TOKEN, $providedToken)) {
        sendErrorResponse(401, 'Unauthorized');
    }
}

// IP-based Rate Limiting
if (ENABLE_RATE_LIMIT && function_exists('apcu_inc')) {
    $rateLimitKey = 'doh_rl_' . $_SERVER['REMOTE_ADDR'];
    $requestCount = apcu_inc($rateLimitKey, 1, $success, RATE_LIMIT_TIMEFRAME);
    if ($requestCount > RATE_LIMIT_REQUESTS) {
        sendErrorResponse(429, 'Too Many Requests');
    }
}


// ===================================================================
//  CORE LOGIC
// ===================================================================

/**
 * Handles the entire request lifecycle.
 */
function handleRequest(): void
{
    $requestBinary = getDnsRequestFromInput();

    if ($requestBinary === null) {
        sendErrorResponse(400, 'Bad Request: Expecting a DoH GET or POST request.');
    }
    if (strlen($requestBinary) > MAX_DNS_REQUEST_SIZE || strlen($requestBinary) === 0) {
        sendErrorResponse(413, 'Payload Too Large or Empty.');
    }

    $cacheKey = ENABLE_CACHE ? 'doh_cache_' . hash('sha256', $requestBinary) : null;

    if (ENABLE_CACHE && function_exists('apcu_fetch')) {
        $cachedResponse = apcu_fetch($cacheKey);
        if ($cachedResponse !== false) {
            sendDnsResponse($cachedResponse);
            return;
        }
    }

    $upstreamServer = UPSTREAM_DNS_SERVERS[array_rand(UPSTREAM_DNS_SERVERS)];
    $response = resolveDnsWithFallback($requestBinary, $upstreamServer);

    if ($response) {
        if (ENABLE_CACHE && function_exists('apcu_store')) {
            apcu_store($cacheKey, $response, CACHE_TTL);
        }
        sendDnsResponse($response);
    } else {
        sendErrorResponse(502, 'Bad Gateway: Upstream DNS server failed to respond.');
    }
}

/**
 * Retrieves the raw DNS query from either a POST body or a GET parameter.
 */
function getDnsRequestFromInput(): ?string
{
    if (isset($_SERVER['CONTENT_TYPE']) && str_starts_with($_SERVER['CONTENT_TYPE'], 'application/dns-message')) {
        return file_get_contents("php://input");
    }

    if (isset($_GET['dns'])) {
        $base64Url = strtr($_GET['dns'], '-_', '+/');
        $decoded = base64_decode($base64Url, true);
        return $decoded === false ? null : $decoded;
    }

    return null;
}

/**
 * Resolves a DNS query, starting with UDP and falling back to TCP if the response is truncated.
 */
function resolveDnsWithFallback(string $requestBinary, string $upstreamHost): ?string
{
    $udpResponse = forwardDnsQuery($requestBinary, $upstreamHost, 'udp');

    // The 'Truncated' bit (TC) is the 2nd bit of the 3rd byte in the DNS header.
    $isTruncated = ($udpResponse && strlen($udpResponse) > 2 && (ord($udpResponse[2]) & 0x02) !== 0);

    if ($isTruncated) {
        // Retry the query over TCP if the UDP response was truncated.
        return forwardDnsQuery($requestBinary, $upstreamHost, 'tcp');
    }

    return $udpResponse;
}

/**
 * Forwards a raw DNS query to an upstream server using either UDP or TCP.
 */
function forwardDnsQuery(string $requestBinary, string $upstreamHost, string $protocol): ?string
{
    $target = "{$protocol}://{$upstreamHost}:" . DNS_PORT;

    $socket = @stream_socket_client($target, $errno, $errstr, DNS_TIMEOUT);
    if (!$socket) {
        error_log("DNS proxy socket error ({$protocol}): {$errno} - {$errstr}");
        return null;
    }

    stream_set_timeout($socket, DNS_TIMEOUT);

    // DNS over TCP requires the query to be prefixed with a 2-byte length field.
    if ($protocol === 'tcp') {
        $requestBinary = pack('n', strlen($requestBinary)) . $requestBinary;
    }

    if (fwrite($socket, $requestBinary) === false) {
        fclose($socket);
        return null;
    }

    $response = fread($socket, DNS_RESPONSE_BUFFER);
    fclose($socket);

    if ($response === false || $response === '') {
        return null;
    }

    // For TCP, the response is also prefixed with a 2-byte length which must be stripped.
    if ($protocol === 'tcp') {
        if (strlen($response) < 2) return null; // Invalid response
        $response = substr($response, 2);
    }

    return $response;
}


// ===================================================================
//  RESPONSE HELPERS
// ===================================================================

/**
 * Outputs a binary DNS response with appropriate headers.
 */
function sendDnsResponse(string $responseBinary): void
{
    header('Content-Type: application/dns-message');
    header('Content-Length: ' . strlen($responseBinary));
    echo $responseBinary;
}

/**
 * Outputs a plain text error response and terminates the script.
 */
function sendErrorResponse(int $statusCode, string $message): void
{
    http_response_code($statusCode);
    header('Content-Type: text/plain');
    echo $message;
    exit;
}


// ===================================================================
//  SCRIPT EXECUTION
// ===================================================================

handleRequest();