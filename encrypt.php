<?php
class MultiEncryptor {
    private $key;
    private $iv;
    private $sodium_key;

    public function __construct($key) {
        $this->key = hash('sha256', $key); // Key for encryption
        $this->iv = substr(hash('sha256', 'encryption_iv'), 0, 16); // IV for algorithms like AES and 3DES
        $this->sodium_key = sodium_crypto_secretbox_keygen(); // Sodium key for ChaCha20
    }

    // AES-256-CBC Encryption
    public function aesEncrypt($data) {
        $encrypted = openssl_encrypt($data, 'AES-256-CBC', $this->key, 0, $this->iv);
        return base64_encode($encrypted);
    }

    // AES-256-CBC Decryption with Error Handling
    public function aesDecrypt($data) {
        $decoded_data = base64_decode($data);
        if ($decoded_data === false) {
            return "Base64 decode failed.";
        }

        $decrypted = openssl_decrypt($decoded_data, 'AES-256-CBC', $this->key, 0, $this->iv);
        if ($decrypted === false) {
            return "Decryption failed: " . openssl_error_string();
        }
        return $decrypted;
    }

    // Triple DES (3DES) Encryption
    public function tripleDesEncrypt($data) {
        $encrypted = openssl_encrypt($data, 'DES-EDE3', $this->key, 0, $this->iv);
        return base64_encode($encrypted);
    }

    // Triple DES (3DES) Decryption with Error Handling
    public function tripleDesDecrypt($data) {
        $decoded_data = base64_decode($data);
        if ($decoded_data === false) {
            return "Base64 decode failed.";
        }

        $decrypted = openssl_decrypt($decoded_data, 'DES-EDE3', $this->key, 0, $this->iv);
        if ($decrypted === false) {
            return "Decryption failed: " . openssl_error_string();
        }
        return $decrypted;
    }

    // Blowfish Encryption
    public function blowfishEncrypt($data) {
        $encrypted = openssl_encrypt($data, 'BF-CBC', $this->key, 0, $this->iv);
        return base64_encode($encrypted);
    }

    // Blowfish Decryption with Error Handling
    public function blowfishDecrypt($data) {
        $decoded_data = base64_decode($data);
        if ($decoded_data === false) {
            return "Base64 decode failed.";
        }

        $decrypted = openssl_decrypt($decoded_data, 'BF-CBC', $this->key, 0, $this->iv);
        if ($decrypted === false) {
            return "Decryption failed: " . openssl_error_string();
        }
        return $decrypted;
    }

    // ChaCha20 Encryption
    public function chacha20Encrypt($data) {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $encrypted = sodium_crypto_secretbox($data, $nonce, $this->sodium_key);
        return base64_encode($nonce . $encrypted);
    }

    // ChaCha20 Decryption with Error Handling
    public function chacha20Decrypt($data) {
        $decoded = base64_decode($data);
        if ($decoded === false) {
            return "Base64 decode failed.";
        }

        $nonce = substr($decoded, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = substr($decoded, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $decrypted = sodium_crypto_secretbox_open($ciphertext, $nonce, $this->sodium_key);
        if ($decrypted === false) {
            return "Decryption failed.";
        }
        return $decrypted;
    }

    // MD5 Hash
    public function md5Hash($data) {
        return md5($data);
    }

    // SHA-256 Hash
    public function sha256Hash($data) {
        return hash('sha256', $data);
    }

    // SHA-224 Hash
    public function sha224Hash($data) {
        return hash('sha224', $data);
    }

    // SHA-384 Hash
    public function sha384Hash($data) {
        return hash('sha384', $data);
    }

    // SHA-512 Hash
    public function sha512Hash($data) {
        return hash('sha512', $data);
    }

    // SHA-512/224 Hash
    public function sha512_224Hash($data) {
        return hash('sha512/224', $data);
    }

    // SHA-512/256 Hash
    public function sha512_256Hash($data) {
        return hash('sha512/256', $data);
    }
}

// Check if the form was submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $crypto = $_POST["crypto"];
    $action = $_POST["action"];
    $input_data = $_POST["input_data"];
    $encryptor = new MultiEncryptor("your_secret_key_here"); // Use a strong key

    $output = '';

    if ($action == "encrypt") {
        switch ($crypto) {
            case 'aes':
                $output = $encryptor->aesEncrypt($input_data);
                break;
            case '3des':
                $output = $encryptor->tripleDesEncrypt($input_data);
                break;
            case 'blowfish':
                $output = $encryptor->blowfishEncrypt($input_data);
                break;
            case 'chacha20':
                $output = $encryptor->chacha20Encrypt($input_data);
                break;
            case 'md5':
                $output = $encryptor->md5Hash($input_data);
                break;
            case 'sha256':
                $output = $encryptor->sha256Hash($input_data);
                break;
            case 'sha224':
                $output = $encryptor->sha224Hash($input_data);
                break;
            case 'sha384':
                $output = $encryptor->sha384Hash($input_data);
                break;
            case 'sha512':
                $output = $encryptor->sha512Hash($input_data);
                break;
            case 'sha512_224':
                $output = $encryptor->sha512_224Hash($input_data);
                break;
            case 'sha512_256':
                $output = $encryptor->sha512_256Hash($input_data);
                break;
        }
    } elseif ($action == "decrypt") {
        switch ($crypto) {
            case 'aes':
                $output = $encryptor->aesDecrypt($input_data);
                break;
            case '3des':
                $output = $encryptor->tripleDesDecrypt($input_data);
                break;
            case 'blowfish':
                $output = $encryptor->blowfishDecrypt($input_data);
                break;
            case 'chacha20':
                $output = $encryptor->chacha20Decrypt($input_data);
                break;
            case 'md5':
            case 'sha256':
            case 'sha224':
            case 'sha384':
            case 'sha512':
            case 'sha512_224':
            case 'sha512_256':
                $output = "Hashing algorithms are one-way and cannot be decrypted.";
                break;
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HeyFetch! - Encryptor Tool</title>
    <style>
        body {
            background-color: #f0f0f0;
            font-family: 'Courier New', monospace;
            color: #000;
            padding: 20px;
        }
        h1 {
            color: #ff00ff;
            text-shadow: 1px 1px 0px #000000;
            font-size: 24px;
            text-align: center;
        }
        form {
            background-color: #fff;
            padding: 10px;
            border: 3px solid #000;
            max-width: 600px;
            margin: 0 auto;
            display: block;
            box-shadow: 2px 2px 0px #000000;
        }
        label, select, input, button {
            display: block;
            margin: 10px 0;
            font-size: 16px;
        }
        input, select {
            padding: 5px;
            width: 100%;
            font-family: 'Courier New', monospace;
            border: 2px solid #000;
            box-sizing: border-box;
        }
        button {
            background-color: #00ffff;
            color: #000;
            font-family: 'Courier New', monospace;
            font-size: 16px;
            padding: 8px;
            cursor: pointer;
            border: 2px solid #000;
        }
        button:hover {
            background-color: #ff00ff;
            color: #fff;
        }
        textarea {
            width: 100%;
            height: 100px;
            font-family: 'Courier New', monospace;
            border: 2px solid #000;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <h1>HeyFetch! Encryptor Tool</h1>
    <form method="POST" action="">
        <label for="crypto">Select Algorithm:</label>
        <select name="crypto" id="crypto">
            <option value="aes">AES-256-CBC</option>
            <option value="3des">Triple DES</option>
            <option value="blowfish">Blowfish</option>
            <option value="chacha20">ChaCha20</option>
            <option value="md5">MD5 (Hash Only)</option>
            <option value="sha256">SHA-256</option>
            <option value="sha224">SHA-224</option>
            <option value="sha384">SHA-384</option>
            <option value="sha512">SHA-512</option>
            <option value="sha512_224">SHA-512/224</option>
            <option value="sha512_256">SHA-512/256</option>
        </select>

        <label for="input_data">Enter Data (link, username, email, password, or code):</label>
        <input type="text" id="input_data" name="input_data">

        <button type="submit" name="action" value="encrypt">Encrypt/Hash</button>
        <button type="submit" name="action" value="decrypt">Decrypt</button>
    </form>

    <?php if (isset($output)): ?>
        <h2>Output:</h2>
        <textarea readonly><?php echo htmlspecialchars($output); ?></textarea>
    <?php endif; ?>
</body>
</html>
