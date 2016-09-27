<?php

/**
 * Created by PhpStorm.
 * User: yu
 * Date: 2016/7/28
 * Time: 23:01
 */
class KingDee
{
    public $key_path;
    public $private_key;

    function __construct($key_path) {
        $this->key_path = $key_path;
    }

    // 将二进制的KEY文件转换为PEM格式的private key文件
    private function get_private_key() {
        $private_key_bin = file_get_contents($this->key_path);
        $private_key_base64 = base64_encode($private_key_bin);
        $private_key_pem = '';
        for ($i = 0; $i < strlen($private_key_base64); $i+=64) {
            $private_key_pem .= substr($private_key_base64, $i, 64);
            $private_key_pem .= "\n";
        }

        $private_key_pem = "-----BEGIN PRIVATE KEY-----\n" . $private_key_pem . "-----END PRIVATE KEY-----";
        return $private_key_pem;
    }

    // 对data加密
    public function encrypt($data, $needBase64 = true) {
        $result = '';

        // 生成随机KEY，16字节，用来对data进行加密
        $random_key = substr(uniqid('', true), 0, 16);

        // 用RSA私钥对上面生成的随机KEY进行加密，密文长度为128字节（1024 / 8)
        $private_key =  openssl_pkey_get_private($this->get_private_key());
        openssl_private_encrypt($random_key, $encrypted, $private_key);
        $result .= $encrypted;

        // 用AES对data进行加密，128位，ECB模式，PCK5 padding（JAVA的AES算法的默认值）
        $td = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_ECB, '');

        // PCK5 padding实现
        $block_size = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB);
        $pad = $block_size - (strlen($data) % $block_size);
        $data =  $data . str_repeat(chr($pad), $pad);

        $iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
        mcrypt_generic_init($td, $random_key, $iv);
        $encrypted = mcrypt_generic($td, $data);
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);
        $result .= $encrypted;

        return $needBase64 ? base64_encode($result) : $result;
    }
}