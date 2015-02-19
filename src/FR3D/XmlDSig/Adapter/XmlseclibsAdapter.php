<?php

namespace FR3D\XmlDSig\Adapter;

use DOMDocument;
use DOMNode;
use XMLSecEnc;
use RuntimeException;
use XMLSecurityKey;
use XMLSecurityDSig;
use UnexpectedValueException;

/**
 * XmlDSig adapter based on "xmlseclibs" library
 *
 * http://code.google.com/p/xmlseclibs/
 */
class XmlseclibsAdapter implements AdapterInterface
{
    /**
     * Private key
     *
     * @var string
     */
    protected $privateKey;

    /**
     * Public key
     *
     * @var string
     */
    protected $publicKey;

    /**
     * Signature algorithm URI. By default RSA with SHA1
     *
     * @var string
     */
    protected $keyAlgorithm = self::RSA_SHA1;

    /**
     * Digest algorithm URI. By default SHA1
     *
     * @var string
     * @see AdapterInterface::SHA1
     */
    protected $digestAlgorithm = self::SHA1;

    /**
     * Canonical algorithm URI. By default C14N
     *
     * @var string
     * @see AdapterInterface::XML_C14N
     */
    protected $canonicalMethod = self::XML_C14N;

    /**
     * Transforms list
     *
     * @var array
     * @see AdapterInterface::ENVELOPED
     */
    protected $transforms = array();


    public function setPrivateKey($privateKey, $algorithmType = self::RSA_SHA1)
    {
        if( strlen($privateKey) < 1024 && is_file($privateKey) ){
            $privateKey = file_get_contents($privateKey);
        }

        $this->privateKey   = $privateKey;
        $this->keyAlgorithm = $algorithmType;

        return $this;
    }

    public function setPublicKey($publicKey)
    {
        if( strlen($publicKey) < 1024 && is_file($publicKey) ){
            $publicKey = file_get_contents($publicKey);
        }

        $this->publicKey = $publicKey;

        return $this;
    }

    public function getPublicKey(DOMNode $dom = null)
    {
        if ($dom) {
            $this->setPublicKeyFromNode($dom);
        }

        if (!$this->publicKey && $this->privateKey) {
            $this->setPublicKeyFromPrivateKey($this->privateKey);
        }

        return $this->publicKey;
    }

    public function getPrivateKey()
    {
        return $this->privateKey;
    }

    public function getKeyAlgorithm()
    {
        return $this->keyAlgorithm;
    }

    public function setDigestAlgorithm($algorithmType = self::SHA1)
    {
        $this->digestAlgorithm = $algorithmType;

        return $this;
    }

    public function setCanonicalMethod($methodType = self::XML_C14N)
    {
        $this->canonicalMethod = $methodType;

        return $this;
    }

    public function addTransform($transformType)
    {
        $this->transforms[] = $transformType;

        return $this;
    }

    public function sign(DOMNode $data, $appendToNode = NULL)
    {
        if (null === $this->privateKey) {
            throw new RuntimeException(
                'Missing private key. Use setPrivateKey or setCertificate to set one.'
            );
        }

        if( null === $appendToNode ){
            if( $data instanceof DOMDocument ){
                $appendToNode = $data->documentElement;
            } else {
                $appendToNode = $data->ownerDocument->documentElement;
            }
        }

        $objKey = new XMLSecurityKey(
            $this->keyAlgorithm,
            array(
                 'type' => 'private',
            )
        );
        $objKey->loadKey($this->privateKey);

        $objXMLSecDSig = new XMLSecurityDSig();
        $objXMLSecDSig->setCanonicalMethod($this->canonicalMethod);
        $objXMLSecDSig->addReference($data, $this->digestAlgorithm, $this->transforms, array('force_uri' => true, 'overwrite' => false));
        $objXMLSecDSig->sign($objKey, $appendToNode);

        /* Add associated public key */
        if ($this->getPublicKey()) {
            $objXMLSecDSig->add509Cert($this->getPublicKey());
        }
    }

    public function verify(DOMNode $data)
    {

        // clones $data to avoid losing the signature node
        $clonedData = clone $data;

        $objKey        = null;
        $objXMLSecDSig = new XMLSecurityDSig();
        $objDSig       = $objXMLSecDSig->locateSignature($clonedData);
        if (!$objDSig) {
            throw new UnexpectedValueException('Signature DOM element not found.');
        }
        $objXMLSecDSig->canonicalizeSignedInfo();

        if (!$this->getPublicKey()) {
            // try to get the public key from the certificate
            $objKey = $objXMLSecDSig->locateKey();
            if (!$objKey) {
                throw new RuntimeException(
                    'There is no set either private key or public key for signature verification.'
                );
            }

            XMLSecEnc::staticLocateKeyInfo($objKey, $objDSig);
            $this->publicKey    = $objKey->getX509Certificate();
            $this->keyAlgorithm = $objKey->getAlgorith();
        }

        if (!$objKey) {
            $objKey = new XMLSecurityKey(
                $this->keyAlgorithm,
                array(
                     'type' => 'public',
                )
            );
            $objKey->loadKey($this->getPublicKey());
        }

        // Check signature
        if (1 !== $objXMLSecDSig->verify($objKey)) {
            return false;
        }

        // Check references (data)
        try {
            $objXMLSecDSig->validateReference();
        } catch(\Exception $e) {
            return false;
        }

        return true;
    }

    /**
     * Try to extract the public key from DOM node
     *
     * Sets publicKey and keyAlgorithm properties if success.
     *
     * @see publicKey
     * @see keyAlgorithm
     * @param DOMNode $dom
     * @return bool `true` If public key was extracted or `false` if cannot be possible
     */
    protected function setPublicKeyFromNode(DOMNode $dom)
    {
        // try to get the public key from the certificate
        $objXMLSecDSig = new XMLSecurityDSig();
        $objDSig       = $objXMLSecDSig->locateSignature($dom);
        if (!$objDSig) {
            return false;
        }

        $objKey = $objXMLSecDSig->locateKey();
        if (!$objKey) {
            return false;
        }

        XMLSecEnc::staticLocateKeyInfo($objKey, $objDSig);
        $this->publicKey    = $objKey->getX509Certificate();
        $this->keyAlgorithm = $objKey->getAlgorith();

        return true;
    }

    /**
     * Try to extract the public key from private key
     *
     * @see publicKey
     * @param string $privateKey
     * @return bool `true` If public key was extracted or `false` if cannot be possible
     */
    protected function setPublicKeyFromPrivateKey($privateKey)
    {
        return openssl_pkey_export(
            openssl_pkey_get_public($privateKey),
            $this->publicKey
        );
    }

    /**
     * Sets both private and public key from a P12 (PFX) or PEM encoded certificate
     * 
     * @param String $cert Path to certificate file or String
     * @param String $password Optional password for certificate opening
     */
    public function setCertificate($cert, $password = null){

        // if $cert is a file load it
        if( strlen($cert) < 1024 && is_file($cert) ){
            $cert = file_get_contents($cert);
        }

        if(!strlen($cert)){
            throw new RuntimeException(
                __METHOD__ . ' - the Certificate is invalid. Please check the file or the string provided.'
            );
        }

        // private key resource
        $privateKey = null;
        $publicKey = null;

        // tries to load the cert as X509
        if( stripos($cert, "BEGIN CERTIFICATE") !== false ){
            
            $x509 = openssl_x509_parse( $cert );

            if($x509 === false){
                throw new RuntimeException(
                    __METHOD__ . ' - the certificate appears to be in X509 format but openssl_x509_parse was unable to load it. Please check the certificate provided.'
                );
            }

            $privateKey = openssl_get_privatekey($cert, $password);
            openssl_x509_export($cert, $publicKey);

        }
        // tries to load as PFX
        else {
            
            $pfx = array();
            $pkcs12 = openssl_pkcs12_read($cert, $pfx, $password);
            
            if($pkcs12 !== true){
                throw new RuntimeException(
                    __METHOD__ . ' - Unable to load certificate as PKCS12 file. Please check the certificate and password provided.'
                );
            }

            $privateKey = $pfx['pkey'];
            $publicKey = $pfx['cert'];

        }

        if($privateKey === false){
            throw new RuntimeException(
                __METHOD__ . ' - unable to load private key from certificate.'
            );
        }

        if($publicKey === false){
            throw new RuntimeException(
                __METHOD__ . ' - unable to load public key from certificate.'
            );
        }

        openssl_pkey_export($privateKey, $this->privateKey);
        $this->publicKey = $publicKey;
        
        if( !$this->privateKey || !$this->publicKey ){
            throw new RuntimeException(
                __METHOD__ . ' - unable to set private/public keys from cert.'
            );
        }
        
        return $this;
    }

}








