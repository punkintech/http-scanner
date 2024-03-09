<?php

// Prompt user for input
$domain = trim(readline('Enter the hostname or IP address of the server: '));
$port = trim(readline('Enter the port number of the server (press Enter for default - 443): '));

// Use default port (443) if user leaves it blank
$port = (empty($port)) ? 443 : $port;
$validDomain = false;

// List of SSL/TLS versions to test
$sslVersions = $sslVersions = [
    'SSLv2' => 'SSLv2',
    'SSLv3' => 'SSLv3',
    'TLSv1_0' => 'TLSv1_0',
    'TLSv1_1' => 'TLSv1_1',
    'TLSv1_2' => 'TLSv1_2',
    'TLSv1_3' => 'TLSv1_3',
];
// DNS options
$dnsTypes = [
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

// Simple validation of HOST / IP
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

// We will loop over the DNS record types because sometimes they don't work correctly
$dnsRecords = [];
foreach ($dnsTypes as $key => $dns) {
    $dnsRecords[$key] = @dns_get_record($domain, $dns); 
}

echo PHP_EOL."\033[44mTesting {$domain} ($ip) on port {$port}...\033[0m".PHP_EOL.PHP_EOL;

echo PHP_EOL."\033[43mTesting DNS Records ...\033[0m".PHP_EOL.PHP_EOL;
foreach($dnsRecords as $key => $record) {
    if(!$record) {
        echo "[{$key}] Couldn't obtain DNS record(s)".PHP_EOL;
    } else {
        
        $detectedType = strtoupper($record[0]['type']);
        $detectedValue = match ($detectedType) {
            'TXT' => $record[0]['txt'],
            'A' => $record[0]['ip'],
            'AAAA' => $record[0]['ipv6'],
            'MX' => $record[0]['target'],
            default => ''
        };

        $validDomain = (strtoupper($record[0]['type']) == 'A' || strtoupper($record[0]['type']) == 'AAAA') ? true : false;

        echo "[\033[32m{$key}\033[0m] TYPE: {$record[0]['type']} | HOST: {$record[0]['host']} | $detectedType: {$detectedValue}".PHP_EOL;
    }
}


// Lets check for HTTP -> HTTPS redirection
$curlDomain = (!$validDomain)? $ip : $domain;
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, "http://".$curlDomain);
if($port != 443 && $port != 80) {
    curl_setopt($ch, CURLOPT_PORT, $port);
}
curl_setopt($ch, CURLOPT_PORT, ".".$port);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HEADER, true);
curl_setopt($ch, CURLOPT_NOBODY, true);

$response = curl_exec($ch);
$statusCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

echo PHP_EOL."\033[43mTesting For HTTP -> HTTPS redirection ...\033[0m".PHP_EOL.PHP_EOL;

$headers = explode("\r\n", $response);
if (in_array($statusCode, [301, 302])) {
    foreach ($headers as $header) {
        if (!empty($header)) {
            if (stripos($header, 'Location:') !== false) {
                $location = $header;
                // Check if the Location header specifies an HTTPS URL
                if (stripos($location, 'https://') !== false) {
                    echo "[\033[32mSECURE\033[0m] The server enforces HTTPS redirect".PHP_EOL;
                } else {
                    echo "[\033[31mINSECURE\033[0m] The server redirects, but does not enforce HTTPS".PHP_EOL;
                }
                break;
            }
        }
    }
} else {
    foreach ($headers as $header) {
        if (!empty($header)) {
            if (stripos($header, "Strict-Transport-Security") !== false) {
                echo "[\033[32mSECURE\033[0m] The server enforces HTTPS redirect".PHP_EOL;
            } else {
                echo "[\033[31mINSECURE\033[0m] No redirect from HTTP to HTTPS detected".PHP_EOL;
            }
            break;
        }
    }
    
}

curl_close($ch);

// Lets get the headers
$error = false;
$curlDomain = (!$validDomain)? $ip : $domain;
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, "http://".$curlDomain);
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

echo PHP_EOL."\033[43mTesting For HTTP(S) headers ...\033[0m".PHP_EOL.PHP_EOL;
if (!$error) {
    $headers = explode("\r\n", $response);
    if (!empty($header)) {
        foreach ($headers as $header) {
            $lines[] = explode(":", $header);
            
            
        }
    }
    var_dump($headers);
    foreach ($lines as $line) {
        
        if (str_contains($line[0], "HTTP")) {
            $http = explode("/", $line[0]);
            $httpResponse = explode(" ", $http[1]);
            echo "[INFO][{$http[0]}][{$httpResponse[0]}][{$httpResponse[1]}]".PHP_EOL;
        }

        if (str_contains($line[0], "Server")) {
            echo "[INFO][{$line[0]}][{$line[1]}][UNKNOWN]".PHP_EOL;
        }
        //echo "[][{$line[0]}][{$line[1]}]".PHP_EOL;
    }

} else {
    echo "skipping headers".PHP_EOL;
}
curl_close($ch);

// Get a list of all supported cipher suites
$cipherSuites = explode(":", shell_exec("openssl ciphers"));

// Get list of openssl ciphers from ciphersuite.info
// This make ssure we have the ciphersuite internal name for searching later
$apiUrl = "https://ciphersuite.info/api/cs/software/openssl";
$apiResponse = @file_get_contents($apiUrl);
if (!$apiResponse) {
    die ("Error: Unable to get ciphers");
}

$cipherSearch = json_decode($apiResponse, true);
foreach ($cipherSearch["ciphersuites"] as $cipher) {
    
    if (array_search($cipher[key($cipher)]["openssl_name"], $cipherSuites)) {
        $suites[] = [
            "openssl_name" => $cipher[key($cipher)]["openssl_name"],
            "search_name" => key($cipher)
        ];
    }
}

echo PHP_EOL."\033[43mTesting for SSL/TLS support...\033[0m".PHP_EOL.PHP_EOL;
/**
 * First lets check if the server responds to each tls / ssl version without specifying a cipher
 */

foreach ($sslVersions as $sslVersion) {
    $context = stream_context_create([
        'ssl' => [
            //'ciphers' => $cipherSuite,
            'crypto_method' => constant("STREAM_CRYPTO_METHOD_{$sslVersion}_CLIENT"),
            'verify_peer' => false,
            'verify_peer_name' => false
        ],
    ]);

    $socket = @stream_socket_client("tls://$ip:$port", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $context);
    $security = "\033[32mSECURE\033[0m";
    $reference = match($sslVersion) {
        "SSLv2" => "https://www.tenable.com/plugins/nessus/20007",
        "SSLv3" => "https://www.tenable.com/plugins/nessus/20007",
        "TLSv1_0" => "https://www.tenable.com/plugins/nessus/104743",
        "TLSv1_1" => "https://www.tenable.com/plugins/nessus/157288",
        "TLSv1_2" => "https://www.tenable.com/plugins/nessus/136318",
        "TLSv1_3" => "https://www.tenable.com/plugins/nessus/138330"
    };
    if ($socket) {
        if (str_contains(verifyConnection($socket, $sslVersion), "not supported")) {
            // Remove from next strage
            unset($sslVersions[$sslVersion]);
        } else {
            $security = ($sslVersion == "SSLv2" || $sslVersion == "SSLv3" || $sslVersion == "TLSv1_0" || $sslVersion == "TLSv1_1") ? "\033[31mWEAK\033[0m" : $security;
        }
        echo "[$security][{$sslVersion}][{$reference}] ".verifyConnection($socket, $sslVersion).PHP_EOL;
        fclose($socket);
    } else {
        echo "[{$security}][{$sslVersion}][{$reference}] Not Supported".PHP_EOL;
        // Remove from next strage
        unset($sslVersions[$sslVersion]);
    }
 }
 
 // Check if we have protocols to test
 if (empty($sslVersions)) {
    echo "No SSL / TLS is supported. Exiting".PHP_EOL;
    exit;
 }

 echo PHP_EOL."\033[43mTesting Cipher Suites ...\033[0m".PHP_EOL.PHP_EOL;

foreach ($sslVersions as $sslVersion) {
    foreach ($suites as $cipherSuite) { 
        $context = stream_context_create([
            'ssl' => [
                'ciphers' => $cipherSuite["openssl_name"],
                'crypto_method' => constant("STREAM_CRYPTO_METHOD_{$sslVersion}_CLIENT"),
                'verify_peer' => false,
                'verify_peer_name' => false
            ],
        ]);

        $start = microtime(true);
        $socket = @stream_socket_client("tls://$ip:$port", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $context);
        
        
        // Make an API call to ciphersuite.info to get security rating
        $apiUrl = "https://ciphersuite.info/api/cs/{$cipherSuite["search_name"]}";
        $apiResponse = @file_get_contents($apiUrl);
        
        $apiData = json_decode($apiResponse, true);
        
        $security = "Unknown";
        
        if ($socket) {
            
            if ($apiData && isset($apiData[$cipherSuite["search_name"]]['security'])) {
                $security = $apiData[$cipherSuite["search_name"]]['security'];
            }
            $security = strtoupper($security);
            $elapsedTime = microtime(true) - $start;

            $colour = match($security) {
                'WEAK' => "\033[31m",
                'SECURE' => "\033[32m",
                "RECOMMENDED" => "\033[34m",
                default => "\033[0m"
            };

            echo "[".$colour."{$security}\033[0m][$sslVersion][{$cipherSuite["openssl_name"]}][{$apiUrl}] Connection established in $elapsedTime seconds.".PHP_EOL;
            
            fclose($socket);
        }
    }
}


function verifyConnection($client, $protocol) {
    $meta = stream_get_meta_data($client);
    
    if ($meta["crypto"]["protocol"] == trim(str_ireplace("_", ".", $protocol))) {
        return "supported";
    } else {
        return "not supported";
    }
}
?>
