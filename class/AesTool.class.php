<?php

class AesTool
{
    /**
     * 加密
     *
     * @param string $plaintext 明文
     * @param string $method    加密方法
     * @param string $key       密码
     * @param string $iv        iv
     *
     * @return string
     */
    public function opensslEncrypt(string $plaintext, string $method, string $key, string $iv = '')
    {
        if ($iv == '') {
            $ivLen = openssl_cipher_iv_length($method);   // 获得该加密方式的iv长度
            $iv    = openssl_random_pseudo_bytes($ivLen); // 生成相应长度的伪随机字节串作为初始化向量
        }
        $ciphertext = openssl_encrypt($plaintext, $method, $key, 0, $iv);
        return $iv . $ciphertext;;
    }

    /**
     * 解密
     *
     * @param string $ciphertext 密文
     * @param string $method     解密方法
     * @param string $key        密码
     * @param string $iv
     *
     * @return string ciphertext
     */
    public function opensslDecrypt(string $ciphertext, string $method, string $key, string $iv = '')
    {
        if ($iv == '') {
            $ivLen      = openssl_cipher_iv_length($method);
            $iv         = substr($ciphertext, 0, $ivLen);
            $ciphertext = substr($ciphertext, $ivLen);
        }
        return openssl_decrypt($ciphertext, $method, $key, 0, $iv);
    }

    /**
     * @param $data
     * @param $key
     * @param $method
     * @param $mode
     *
     * @return string
     * @throws Exception
     */
    public function mcryptEncrypt($data, $key, $method, $mode, $iv = '')
    {
        if ($iv == '') {
            $ivLen = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, $this->_mode);
            $iv    = mcrypt_create_iv($ivLen, MCRYPT_RAND);
        }

        $size       = mcrypt_get_block_size($method, $mode);
        $data       = $this->pkcs5Padding($data, $size);
        $ciphertext = mcrypt_encrypt($method, $key, $data, $mode, $iv);
        $ciphertext = $iv . $ciphertext;

        return base64_encode($ciphertext);
    }

    /**
     * @param string $ciphertext
     * @param string $key
     * @param        $method
     * @param        $mode
     * @param string $iv
     *
     * @return bool|string
     */
    public function mcryptDecrypt(string $ciphertext, string $key, $method, $mode, string $iv = '')
    {
        $ciphertext = base64_decode($ciphertext);
        if ($iv == '') {
            $ivLen      = mcrypt_get_iv_size($method, $this->_mode);
            $iv         = substr($ciphertext, 0, $ivLen);
            $ciphertext = substr($ciphertext, $ivLen);
        }

        $str = mcrypt_decrypt($method, $key, $ciphertext, $mode, $iv);
        $str = $this->pkcs5Unpad($str);
        return $str;
    }

    /**
     * 填充
     */
    private function pkcs5Padding($text, $blocksize)
    {
        $pad = $blocksize - (strlen($text) % $blocksize);
        return $text . str_repeat(chr($pad), $pad);
    }

    /**
     * 去除填充内容
     */
    private function pkcs5Unpad($text)
    {
        $pad = ord($text{strlen($text) - 1});
        if ($pad > strlen($text))
            return false;
        if (strspn($text, chr($pad), strlen($text) - $pad) != $pad)
            return false;
        return substr($text, 0, -1 * $pad);
    }
}


$originData = "独孤求败是香港武侠小说家金庸的作品里一位武林高手，是小说中唯一被提及过真正“无敌于天下”的高手，于小说中从未出场过，而其事迹只在极少数武林人士之间口耳相传。其名字曾于金庸的三部小说中出现，分别为《神雕侠侣》、《笑傲江湖》以及《鹿鼎记》。《神雕侠侣》主角杨过习得独孤求败使用重剑以及其修练内力的法门后，继以晋身当代绝顶高手之列。《笑傲江湖》主角令狐冲原本武功平平，因缘际会学得独孤九剑以后，一跃为当代剑术高手。《鹿鼎记》只有一句提及独孤求败，是澄观和尚想及“无招胜有招”的前人例子时念起。";

$aesTool = new AesTool();

$opensslCiphertext = $aesTool->opensslEncrypt($originData, 'aes-128-cbc', '1246');
echo '$opensslCiphertext:  ' . $opensslCiphertext . PHP_EOL;

$opensslPlaintext = $aesTool->opensslDecrypt($opensslCiphertext, 'aes-128-cbc', '1246');
echo '$opensslCiphertext:  ' . $opensslCiphertext . PHP_EOL;
