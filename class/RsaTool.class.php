<?php

/**
 * 加密
 * 一般来说，加密分为两个部分，一个是非对称加密，一个是对称加密。
 * 使用对称加密加密正文信息，使用非对称加密加密对称加密的密钥，然后发送加密数据(消息摘要和数字签名就不讨论了)，
 * 这是正规的数据加密策略，对称加密默认支持大数据分段加密策略，你只需要从接口中完成加密即可，
 * 而且对称加密速度比非对称加密快很多，如果你需要使用这个策略建议使用AES。
 * 如果你不愿意使用对称加密，只愿意使用AES加密，那你就必须丧失速度了，而且自己处理分段加密，因为RSA加密通常是117个字节就要分段(这个长度可能和密钥长度有关，我是用的接口是117)，你需要自己把数据变成N个117字节的数据段来完成加密，解密也需要自己完成字节拼装。
 */
class RsaTool
{
    private $priFile = './rsa_key/rsa_private_key.pem';
    private $pubFile = './rsa_key/rsa_public_key.pem';

    private $publicKey  = null;
    private $privateKey = null;

    public function __construct()
    {
        // 这个函数可用来判断私钥是否是可用的，可用返回资源id Resource id
        $this->publicKey  = openssl_pkey_get_public(file_get_contents($this->pubFile));
        $this->privateKey = openssl_pkey_get_private(file_get_contents($this->priFile));
    }

    /**
     * RSA公钥加密,输出base64
     */
    public function publicEncrypt($data)
    {
        openssl_public_encrypt($data, $encryptData, $this->publicKey);
        return base64_encode($encryptData);
    }

    /**
     * RSA私钥加密,输出base64
     */
    public function privateEncrypt($data)
    {
        openssl_private_encrypt($data, $encryptData, $this->privateKey);
        return base64_encode($encryptData);
    }

    /**
     * RSA公钥解密,base64
     */
    public function publicDecrypt($ciphertext)
    {
        $ciphertext = base64_decode($ciphertext);
        openssl_public_decrypt($ciphertext, $decrypted, $this->publicKey);
        return $decrypted;
    }

    /**
     * RSA私钥解密,base64
     */
    public function privateDecrypt($ciphertext)
    {
        $ciphertext = base64_decode($ciphertext);
        openssl_private_decrypt($ciphertext, $decrypted, $this->privateKey);
        return $decrypted;
    }

    /**
     * RSA私钥分片加密,100
     */
    public function privateSplitEncrypt($data)
    {
        $encrypted = '';
        // 生成密钥位数 1024 bit key,最大允许加密长度为117，得分段加密
        $plainData = str_split($data, 100);
        foreach ($plainData as $chunk) {
            $partialEncrypted = '';
            $encryptionOk     = openssl_private_encrypt($chunk, $partialEncrypted, $this->privateKey);//私钥加密
            if ($encryptionOk === false) return false;
            $encrypted .= $partialEncrypted;
        }
        // 加密后的内容通常含有特殊字符，需要编码转换下，
        // 在网络间通过url传输时要注意base64编码是否是url安全的
        $encrypted = base64_encode($encrypted);
        return $encrypted;
    }

    /**
     * RSA私钥分片解密,128
     */
    public function privateSplitDecrypt($ciphertext)
    {
        $decrypted = '';
        $plainData = str_split(base64_decode($ciphertext), 128);
        foreach ($plainData as $chunk) {
            $str          = '';
            $decryptionOk = openssl_private_decrypt($chunk, $str, $this->privateKey);//私钥解密
            if ($decryptionOk === false) return false;
            $decrypted .= $str;
        }
        return $decrypted;
    }

    /**
     * RSA公钥分片解密
     */
    public function publicSplitDecrypt($data)
    {
        $plainData = str_split(base64_decode($data), 128);//生成密钥位数 1024 bit key
        $decrypted = '';
        foreach ($plainData as $chunk) {
            $str          = '';
            $decryptionOk = openssl_public_decrypt($chunk, $str, $this->publicKey);//公钥解密
            if ($decryptionOk === false) {
                return false;
            }
            $decrypted .= $str;
        }
        return $decrypted;
    }

    /**
     * RSA公钥加密
     */
    public function publicSplitEncrypt($data)
    {
        $encrypted = '';
        $plainData = str_split($data, 100);
        foreach ($plainData as $chunk) {
            $partialEncrypted = '';
            $encryptionOk     = openssl_public_encrypt($chunk, $partialEncrypted, $this->publicKey);//公钥加密
            if ($encryptionOk === false) {
                return false;
            }
            $encrypted .= $partialEncrypted;
        }
        $encrypted = base64_encode($encrypted);
        return $encrypted;
    }
}

$res = new RsaTool();

echo $res->publicSplitDecrypt('XRglzBotsLHLZxEomri5HQt4cZFe0QIytLTIH7t97ISeyG4jjtcmGTtpJRx8g7LAIqRTZBOAnV3MG9p7XhJDf33ZdBYetLDrSOk872SExMYmDmpZGJ2FrpnF20g3PZrX2EzrsrjY10bK67wiqFEBOLbWS9wV6ecXPPiRsbnNiR0ggVYy4X7CPhAW7vHy35qyVj+ZPyQCpsK7ZVaKRD9W4gTQXEpuaL7vYMlOdk+P2BGREtalNpgr3HJrfDPjfaqLnso5a6kLdjEwzP7s7ri3NkTxq5LNm0r6yURJsdzItrq8i3fYXc6mYghNrCwdeVvMVIkmu0cOfMc3/3BAx9LDDF5mRh5ET/RyJIdq8KRuNcxF7iFu14NNG1GAycM5wOn1XKj8E9hEtjrLAbItCLy5oCjjKhghA642N5M13RNDg8yutDskcVKZ+d0I6SF/nP+xdldr4WsRzvWlMrZ/uSl3cK2qkegav2x6cmXwH4h3xeR47u1ovX6EXTKR1F2eZuIOQ36nedCF+mAfXlJqTQMbmlZUZGKzVc3D3LlYm/VW/HQd6N5AA6Q/Y1XivzvQqk5PBE3x6kURSX/9Axfc3du3SF8zgnZ5HgtjHwnXtSqPZHofBLWigUllAyri8mY26T1+1JiBri/XidDS8iWUBpkeng3uPKSpRdWoJVbM6lQMOvxVGgaEqlyz8Z44nOAHsq4FlZoBxqY63ckmHGtbXSRNMRAyIMH4VqwjIiCZh8bIisuALrx+kol5SuJ7TdcvwsZTFE8iUsMZgpmhsGAuXFKYW+pZ7G3N5ipZOsXHyEYBlNINkufiIrPxshodgKlBYRMFDWEukLPYw8hXT8+xMPTtIYVCymv4X2aAyxBTpnhaoGEiVt4n5rgz99RPqWJSo8ePMbfcF/sEMe6UPOVWKfj2MUWxc6GHvndMQeD6vP9tqdWjlkJBUNbpo72+5R//GX0Zd24VeLFjHBabxZR2l4/yqWexVugWbqtDj9kLQr1nEionvm+RGFz3Y2N99gxL1EXA');


echo json_encode(['aa我的', 'nid']);