<?php

/**
 * Class McryptAesTool
 */
class McryptAesTool
{
    private $_mode = MCRYPT_MODE_CBC;

    public function encrypt($data, $key)
    {
        $size = mcrypt_get_block_size ( MCRYPT_RIJNDAEL_128, $this->_mode );
        $data = $this->pkcs5Padding($data, $size);
        $iv = $this->getIv();
        $ciphertext = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_CBC, $iv);

        $ciphertext = $iv . $ciphertext;

        return base64_encode($ciphertext);
    }

    /**
     * 填充
     */
    private function pkcs5Padding ($text, $blocksize)
    {
        $pad = $blocksize - (strlen($text) % $blocksize);
        return $text . str_repeat(chr($pad), $pad);
    }

    /**
     * 去除填充内容
     */
    private function pkcs5Unpad($text)
    {
        $pad = ord ( $text {strlen ( $text ) - 1} );
        if ($pad > strlen ( $text ))
            return false;
        if (strspn ( $text, chr ( $pad ), strlen ( $text ) - $pad ) != $pad)
            return false;
        return substr ( $text, 0, - 1 * $pad );
    }

    /**
     * 获取向量
     */
    private function getIv($data=false)
    {
        $ivSize = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
        if($data == false){
            $iv = mcrypt_create_iv($ivSize, MCRYPT_RAND);
        }else{
            $iv = substr($data, 0, $ivSize);
        }
        return $iv;
    }

    public function decrypt($data, $key)
    {
        $ciphertext_dec = base64_decode($data);

        $ivSize  = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);

        $iv = $this->getIv($ciphertext_dec);

        $ciphertext_dec = substr($ciphertext_dec, $ivSize);

        $str = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $ciphertext_dec, MCRYPT_MODE_CBC, $iv);
        $str = $this->pkcs5Unpad( $str );
        return $str;
    }
}

$aes = new McryptAesTool();
$data = "abcdefghizklmnopqrstuvwxyz";
$key = pack('H*', "bcb04b7e103a0cd8b54763051cef08bc55abe029fdebae5e1d417e2ffb2a00a3");

$mdata = $aes->encrypt($data, $key);
echo "MIWEN:".$mdata . PHP_EOL;
$data = $aes->decrypt($mdata, $key);
echo "YUANWEN:".$data . PHP_EOL;




