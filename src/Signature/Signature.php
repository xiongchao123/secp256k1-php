<?php
/**
 * This file is part of secp256k1 package.
 * 
 * (c) Kuan-Cheng,Lai <alk03073135@gmail.com>
 * 
 * @author Peter Lai <alk03073135@gmail.com>
 * @license MIT
 */

namespace Xiongchao\Secp256k1\Signature;

use GMP;
use Mdanter\Ecc\Crypto\Signature\Signature as SignatureBase;
use Xiongchao\Secp256k1\Serializer\HexSignatureSerializer;

class Signature extends SignatureBase
{
    /**
     * serializer
     * 
     * @var \Xiongchao\Secp256k1\Serializer\HexSignatureSerializer
     */
    protected $serializer;

    /**
     * construct
     *
     * @param \GMP $r
     * @param \GMP $s
     * @return void
     */
    public function __construct($r, $s)
    {
        parent::__construct($r, $s);

        $this->serializer = new HexSignatureSerializer;
    }

    /**
     * toHex
     * 
     * @return string
     */
    public function toHex(): string
    {
        return $this->serializer->serialize($this);
    }
}