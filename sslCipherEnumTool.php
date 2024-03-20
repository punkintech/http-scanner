<?php
/**
 * SSL Cipher Enum Tool
 *
 * This script is designed to enumerate SSL/TLS ciphers for a given domain or IP and port.
 * It provides detailed information about DNS records, checks for HTTP to HTTPS redirects,
 * tests for HSTS (HTTP Strict Transport Security), SSL/TLS versions, server headers, and
 * cipher suites.
 *
 * PHP version 8.0+
 *
 * @package    SSLCipherEnumTool
 * @author     kaitoj
 * @license    MIT License
 * @version    0.0.0-alpha.1
 * @link       https://github.com/punkintech/ssl-cipher-enum-tool
 *
 * MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * DISCLAIMER: This tool is for educational and testing purposes only. The author
 * or contributors are not responsible for any misuse or damage caused by this tool.
 */

const SINGLE = PHP_EOL;
const DOUBLE = SINGLE.SINGLE;
const HTTP = "http://";
const HTTPS = "https://";
const TLS = "tls://";

/** Check dependencies before continuing */
checkDependencies();

/** Prompt for user input
 * $domain can be a host or IP, do not include HTTP(s)
 * $port must be an int or blank for default 443
 */
echo SINGLE;
$domain = trim(readline('Enter the hostname or IP address of the server: '));
$port = trim(readline('Enter the port number of the server (press Enter for default - 443): '));
$port = (empty($port)) ? 443 : $port;

/**
 * Validate the host / IP
 */
$ip = validateHostorIP($domain);

/**
 * Get DNS records
 */
$dnsRecords = getDnsRecords($domain);

echo SINGLE.getBgColour('blue')."Testing {$domain} ($ip) on port {$port}...".getBgColour().DOUBLE;

/**
 * Process DNS records
 */
echo getTitle('dns');
$validDomain = false;
foreach($dnsRecords as $key => $record) {
    if(!$record) {
        echo getResponse('info', "[{$key}] Couldn't obtain DNS record(s)");
    } else {
        $detectedType = strtoupper($record[0]['type']);
        $detectedValue = match ($detectedType) {
            'TXT' => $record[0]['txt'],
            'A' => $record[0]['ip'],
            'AAAA' => $record[0]['ipv6'],
            'MX', 'NS' => $record[0]['target'],
            'CNAME' => $record[0]['cname'],
            'SOA' => $record[0]['mname']."|".$record[0]['rname'],
            default => ''
        };

        $validDomain = strtoupper($record[0]['type']) == 'A' || strtoupper($record[0]['type']) == 'AAAA';

        echo getResponse('info', "[{$key}][{$detectedType}][{$record[0]['host']}][{$detectedValue}]");
    }
}

/**
 * Check for HTTP/S redirection and HSTS
 */
echo getTitle('redirection');

$curlDomain = (!$validDomain)? $ip : $domain;
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, HTTP.$curlDomain);
if($port != 443 && $port != 80) {
    curl_setopt($ch, CURLOPT_PORT, $port);
}
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HEADER, true);
curl_setopt($ch, CURLOPT_NOBODY, true);

$response = curl_exec($ch);
$statusCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

$headers = explode("\r\n", $response);
if (in_array($statusCode, [301, 302])) {
    foreach ($headers as $header) {
        if (!empty($header)) {
            if (stripos($header, 'Location:') !== false) {
                $location = $header;
                // Check if the Location header specifies an HTTPS URL
                if (stripos($location, HTTPS) !== false) {
                    echo getResponse('secure'," The server enforces HTTPS redirect");
                } else {
                    echo getResponse('insecure', " The server redirects, but does not enforce HTTPS");
                }
                break;
            }
        }
    }
} else {
    foreach ($headers as $header) {
        if (!empty($header)) {
            if (stripos($header, "Strict-Transport-Security") !== false) {
                echo getResponse('secure', " The server enforces HTTPS redirect");
            } else {
                echo getResponse('insecure', " No redirect from HTTP to HTTPS detected");
            }
            break;
        }
    }
    
}

curl_close($ch);

/**
 * Get headers
 */
echo getTitle('header');
$error = false;
$curlDomain = (!$validDomain)? $ip : $domain;
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, HTTP.$curlDomain);
if($port != 443 && $port != 80) {
    curl_setopt($ch, CURLOPT_PORT, $port);
}
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch, CURLOPT_HEADER, true);
curl_setopt($ch, CURLOPT_NOBODY, true);
// If we have an IP,lets not bother validating host
if (filter_var($ip, FILTER_VALIDATE_IP)) {
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
}
$response = curl_exec($ch);

if (curl_errno($ch)) {
    $error = true;
}

if (!$error) {
    $lines = [];
    $headers = explode("\r\n", $response);
    if (!empty($header)) {
        foreach ($headers as $header) {
            $lines[] = explode(":", $header);
        }
    }

    foreach ($lines as $line) {
        $resp = '';
        if (str_contains($line[0], "HTTP")) {
            $http = explode("/", $line[0]);
            $httpResponse = explode(" ", $http[1]);
            $resp = getResponse('info', "[{$http[0]}][{$httpResponse[0]}][{$httpResponse[1]}]");
        }

        if (str_contains($line[0], "Server")) {
            $resp = getResponse('info', "[{$line[0]}][{$line[1]}]".getStatus('unknown'));
        }

        if (str_contains($line[0], "Location")) {
            $locationUrl = trim($line[1].$line[2]);
            $resp = getResponse('info',"[{$line[0]}][{$locationUrl}]");
        }

        if (str_contains($line[0], "strict-transport-security")) {
            $resp = getResponse('secure',"[{$line[0]}][{$line[1]}]");
        }

        if (str_contains($line[0], "x-xss-protection")) {
            $resp = getResponse('secure', "[{$line[0]}][{$line[1]}]");
        }

        if (str_contains($line[0], "content-security-policy")) {
            $resp = getResponse('info', "[{$line[0]}][{$line[1]}]");
        }

        if (str_contains($line[0], "permissions-policy")) {
            $resp = getResponse('info',"[{$line[0]}][{$line[1]}]");
        }

        if (str_contains($line[0], "x-frame-options")) {
            $resp = getResponse('info', "[{$line[0]}][{$line[1]}]");
        }

        if (str_contains($line[0], "x-")) {
            $resp = getResponse('info', "[{$line[0]}][{$line[1]}]");
        }

        // Cloudflare
        if (str_contains($line[0], "report-to")) {
            $resp = getResponse('info', "[{$line[0]}][{$line[1]}]");
        }

        // Cloudflare
        if (str_contains($line[0], "cf-")) {
            $resp = getResponse('info', "[{$line[0]}][{$line[1]}]");
        }

        // Cloudflare
        if (str_contains($line[0], "nel")) {
            $resp = getResponse('info', "[{$line[0]}][{$line[1]}]");
        }

        // Cookies
        if (str_contains($line[0], "set-cookie")) {

            $cookie = getCookieMetadata($line[1]);
            $state = 'info';
            if ($cookie['type'] == "JWT") {
                $state = 'secure';
            } else {
                $state = 'insecure';
            }

            $resp = getResponse($state, "[{$line[0]}][{$cookie['key']}][{$cookie['type']}]");
        }
        echo $resp;
    }

} else {
    echo "skipping headers".SINGLE;
}
curl_close($ch);
/**
 * Get Certificate chain
 */
echo getTitle('sslChain');
$context = getSslStreamContext("TLSv1_2"); // should work most of the time
$socket = getSslSocket($ip, $port, $context);
$certificates = getSslCertificates($socket);

foreach ($certificates as $cert) {
    $certInfo = openssl_x509_parse($cert);

    echo "[{$certInfo['subject']['CN']}][{$certInfo['issuer']['O']}]".SINGLE;

    $validTo = new DateTime();
    $validTo->setTimestamp($certInfo['validTo_time_t']);
    $date = $validTo->format("Y-m-d");
    echo "      ".getResponse(sslValidityStatus($certInfo['validTo_time_t']), $date);
    echo "      ".getResponse(sslSignatureStatus($certInfo['signatureTypeSN']), $certInfo['signatureTypeSN']);
}

/**
 * Get supported ciphers
 */
echo getTitle('ssl');
$suites = getCipherSuites();
$sslVersions = getSslVersions();
foreach ($sslVersions as $sslVersion) {
    $context = getSslStreamContext($sslVersion);
    $socket = getSslSocket($ip, $port, $context);

    $security = 'secure';

    $reference = match($sslVersion) {
        "SSLv2", "SSLv3" => "https://www.tenable.com/plugins/nessus/20007",
        "TLSv1_0" => "https://www.tenable.com/plugins/nessus/104743",
        "TLSv1_1" => "https://www.tenable.com/plugins/nessus/157288",
        "TLSv1_2" => "https://www.tenable.com/plugins/nessus/136318",
        "TLSv1_3" => "https://www.tenable.com/plugins/nessus/138330"
    };
    if ($socket) {
        if (str_contains(verifyConnection($socket, $sslVersion), "not supported")) {
            // Remove from next stage
            unset($sslVersions[$sslVersion]);
        } else {
            $security = ($sslVersion == "SSLv2" || $sslVersion == "SSLv3" || $sslVersion == "TLSv1_0" || $sslVersion == "TLSv1_1") ? 'weak' : $security;
        }
        echo getResponse($security, "[{$sslVersion}][{$reference}] ".verifyConnection($socket, $sslVersion));

        fclose($socket);
    } else {
        echo getResponse($security, "[{$sslVersion}][{$reference}] Not Supported");
        // Remove from next stage
        unset($sslVersions[$sslVersion]);
    }
 }
 
// Check if we have protocols to test
if (empty($sslVersions)) {
    echo "No SSL / TLS is supported. Exiting".DOUBLE;
    exit;
}

/**
 * Test supported ciphers
 */
echo getTitle('ciphers');

foreach ($sslVersions as $sslVersion) {
    foreach ($suites as $cipherSuite) {
        $start = microtime(true);
        $security = "unknown";
        $url = "https://ciphersuite.info/api/cs/{$cipherSuite['search_name']}";
        $context = getSslStreamContext($sslVersion, $cipherSuite);
        $socket = getSslSocket($ip, $port, $context);
        
        // Make an API call to ciphersuite.info to get security rating
        $apiData = getCipherSuitesInfoApi($url);
        
        if ($socket) {
            
            if ($apiData && isset($apiData[$cipherSuite["search_name"]]['security'])) {
                $security = $apiData[$cipherSuite["search_name"]]['security'];
            }
            $security = strtoupper($security);
            $elapsedTime = microtime(true) - $start;

            $status = match($security) {
                'WEAK' => 'weak',
                'SECURE' => 'secure',
                "RECOMMENDED" => 'recommended',
                default => 'info'
            };

            echo getResponse($status,"[$sslVersion][{$cipherSuite["openssl_name"]}][{$url}] Connection established in $elapsedTime seconds");
            
            fclose($socket);
        }
    }
}

/**
 * @param $client
 * @param string $protocol
 * @return string
 */
function verifyConnection($client, string $protocol): string {
    $meta = stream_get_meta_data($client);
    
    if ($meta["crypto"]["protocol"] == trim(str_ireplace("_", ".", $protocol))) {
        return "supported";
    } else {
        return "not supported";
    }
}

/**
 * Simple validation of HOST / IP
 * @param string $domain
 * @return string
 */
function validateHostOrIP(string $domain): string
{
    if (!filter_var($domain, FILTER_VALIDATE_IP)) {
        $ip = gethostbyname($domain);
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            // Check if the domain is valid
            if (!checkdnsrr($domain, "ANY")) {
                die ("Error: Invalid Host or IP");
            }

        }
    } else {
        $ip = $domain;
    }

    return $ip;
}

/**
 * @param string $status
 * @param $response
 * @return string
 */
function getResponse(string $status, $response): string
{
    return getStatus($status).$response.SINGLE;
}

/**
 * @param string $status
 * @return string
 */
function getStatus(string $status):string
{
    $statuses = [
        'info' => "[".getTextColour('blue')."INFO".getTextColour()."]",
        'weak' => "[".getTextColour('yellow')."WEAK".getTextColour()."]",
        'recommended' => "[".getTextColour('blue')."RECOMMENDED".getTextColour()."]",
        'secure' => "[".getTextColour('green')."SECURE".getTextColour()."]",
        'insecure' => "[".getTextColour('red')."INSECURE".getTextColour()."]",
        'unknown' => "[UNKNOWN]",
    ];

    return (isset($statuses[$status])) ? $statuses[$status] : $statuses['unknown'];
}

/**
 * @param string|null $type
 * @return array|string
 */
function getDnsTypes(?string $type = null)
{
    $types = [
        'DNS_ALL' => DNS_ALL,
        'DNS_ANY' => DNS_ANY,
        'DNS_A' => DNS_A,
        'DNS_CNAME' => DNS_CNAME,
        'DNS_HINFO' => DNS_HINFO,
        'DNS_CAA' => DNS_CAA,
        'DNS_MX' => DNS_MX,
        'DNS_NS' => DNS_NS,
        'DNS_PTR' => DNS_PTR,
        'DNS_SOA' => DNS_SOA,
        'DNS_TXT' => DNS_TXT,
        'DNS_AAAA' => DNS_AAAA,
        'DNS_SRV' => DNS_SRV,
        'DNS_NAPTR' => DNS_NAPTR,
        'DNS_A6' => DNS_A6
    ];
    if(!is_null($type)) {
        return $types[$type];
    }
    return $types;
}

/**
 * @return array
 */
function getDnsRecords(string $domain): array
{
    $dnsRecords = [];
    $dnsTypes = getDnsTypes();
    foreach ($dnsTypes as $key => $dns) {
        $dnsRecords[$key] = @dns_get_record($domain, $dns);
    }
    return $dnsRecords;
}

function getTitle(string $title): string
{

    $titles = [
        'dns' => getBgColour('yellow')."Testing DNS Records ...".getBgColour().DOUBLE,
        'redirection' => SINGLE.getBgColour('yellow')."Testing For HTTP -> HTTPS redirection ...".getBgColour().DOUBLE,
        'header' => SINGLE.getBgColour('yellow')."Testing For HTTP(S) headers ...".getBgColour().DOUBLE,
        'ssl' => SINGLE.getBgColour('yellow')."Testing for SSL/TLS support...".getBgColour().DOUBLE,
        'ciphers' => SINGLE.getBgColour('yellow')."Testing Cipher Suites ...".getBgColour().DOUBLE,
        'sslChain' => SINGLE.getBgColour('yellow')."Testing SSL Certificate Chain ...".getBgColour().DOUBLE
    ];

    return $titles[$title];
}

/**
 * @param string|null $colour
 * @return string
 */
function getBgColour(?string $colour = null): string
{
    // Background Colours
    $bgColours = [
        'white' => '',
        'default' => "\033[0m",
        'red' => "\033[41m",
        'yellow' => "\033[43m",
        'cyan' => "\033[46m",
        'green' => "\033[42m",
        'blue' => "\033[44m"
    ];
    return (!is_null($colour)) ? $bgColours[$colour] : $bgColours['default'];
}

/**
 * @param string|null $colour
 * @return string
 */
function getTextColour(?string $colour = null): string
{
    // Text Colours
    $textColours = [
        'white' => '',
        'default' => "\033[0m",
        'red' => "\033[31m",
        'blue' => "\033[34m",
        'green' => "\033[32m",
        'yellow' => "\033[33m",
        'cyan' => "\033[36m"
    ];
    return (!is_null($colour)) ? $textColours[$colour] : $textColours['default'];
}

/**
 * @return array
 */
function getSslCipherSuites(): array
{
    return explode(":", shell_exec("openssl ciphers"));
}

/**
 * @param $socket
 * @return array
 */
function getSslCertificates($socket): array
{
    $contParams = stream_context_get_params($socket);

    if (!empty($contParams['options']['ssl']['peer_certificate_chain'])) {
        return $contParams['options']['ssl']['peer_certificate_chain'];
    } else {
        echo getResponse("info", "Certificate chain not found");
    }
    return [];
}

/**
 * @param string $url
 * @return array
 */
function getCipherSuitesInfoApi(string $url): array
{
    // This make sure we have the ciphersuite internal name for searching later
    $apiResponse = @file_get_contents($url);
    if (!$apiResponse) {
        die ("Error: Unable to get ciphers");
    }
    return json_decode($apiResponse, true);
}

/**
 * @return array
 */
function getCipherSuites(): array
{
    $suites = [];

    // Get a list of all supported cipher suites
    $sslCipherSuites = getSslCipherSuites();

    // Get list of openssl ciphers from ciphersuite.info
    $cipherSuiteInfoSearch = getCipherSuitesInfoApi("https://ciphersuite.info/api/cs/software/openssl");

    foreach ($cipherSuiteInfoSearch["ciphersuites"] as $cipher) {

        if (array_search($cipher[key($cipher)]["openssl_name"], $sslCipherSuites)) {
            $suites[] = [
                "openssl_name" => $cipher[key($cipher)]["openssl_name"],
                "search_name" => key($cipher)
            ];
        }
    }

    return $suites;
}

/**
 * @return string[]
 */
function getSslVersions(): array
{
    // List of SSL/TLS versions to test
    return [
        'SSLv2' => 'SSLv2',
        'SSLv3' => 'SSLv3',
        'TLSv1_0' => 'TLSv1_0',
        'TLSv1_1' => 'TLSv1_1',
        'TLSv1_2' => 'TLSv1_2',
        'TLSv1_3' => 'TLSv1_3',
    ];
}

/**
 * @return resource
 */
function getSslStreamContext(string $sslVersion, $cipherSuite = null)
{
    $context = [
        'ssl' => [
            'capture_peer_cert_chain' => true,
            'crypto_method' => constant("STREAM_CRYPTO_METHOD_{$sslVersion}_CLIENT"),
            'verify_peer' => false,
            'verify_peer_name' => false
        ],
    ];

    if (!is_null($cipherSuite)) {
        $context['ciphers'] = $cipherSuite;
    }

    return stream_context_create($context);
}

/**
 * @param $ip
 * @param $port
 * @param $context
 * @return false|resource
 */
function getSslSocket($ip, $port, $context = null)
{
    return @stream_socket_client(TLS."$ip:$port", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $context);
}

function getCookieMetadata(string $cookie): array
{
    $key = explode("=", trim($cookie));
    $value = explode(";", trim($key[1]));

    return [
        'key' => trim($key[0]),
        'value' => trim($value[0]),
        'type' => (isJwt($value[0])) ? "JWT" : "UNKNOWN STRING",
        'meta' => trim($value[1])
        ];
}

function isJwt(string $string): bool
{
    // first urldecode and base64 decode
    $parsed = base64_decode(urldecode($string));
    // test if is a json. if json, then probably a jwt
    return (is_object(json_decode($parsed)));
}

/**
 * @param int $timestamp
 * @return string
 */
function sslValidityStatus(int $timestamp = 0): string
{
    return ($timestamp > time()) ? 'secure' : 'weak';
}

/**
 * @param string $signature
 * @return string
 */
function sslSignatureStatus(string $signature): string
{
    return 'info';
}

/**
 * @return void
 */
function checkDependencies(): void
{
    if (!version_compare(PHP_VERSION, '8.0', '>=')) {
        die ('PHP version 8.0 or greater is required');
    }
    if (!function_exists('curl_init')) {
        die ("Curl not installed. Install php-curl to continue.");
    }
}