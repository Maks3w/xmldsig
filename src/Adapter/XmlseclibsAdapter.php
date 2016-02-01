<?php

namespace FR3D\XmlDSig\Adapter;

use DOMDocument;
use DOMNode;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use RuntimeException;
use UnexpectedValueException;

/**
 * XmlDSig adapter based on "xmlseclibs" library.
 *
 * http://code.google.com/p/xmlseclibs/
 */
class XmlseclibsAdapter implements AdapterInterface
{
    /**
     * Private key.
     *
     * @var string
     */
    protected $privateKey;

    /**
     * Public key.
     *
     * @var string
     */
    protected $publicKey;

    /**
     * Signature algorithm URI. By default RSA with SHA1.
     *
     * @var string
     */
    protected $keyAlgorithm = self::RSA_SHA1;

    /**
     * Digest algorithm URI. By default SHA1.
     *
     * @var string
     *
     * @see AdapterInterface::SHA1
     */
    protected $digestAlgorithm = self::SHA1;

    /**
     * Canonical algorithm URI. By default C14N.
     *
     * @var string
     *
     * @see AdapterInterface::XML_C14N
     */
    protected $canonicalMethod = self::XML_C14N;

    /**
     * Transforms list.
     *
     * @var array
     *
     * @see AdapterInterface::ENVELOPED
     */
    protected $transforms = [];

    public function setPrivateKey($privateKey, $algorithmType = self::RSA_SHA1)
    {
        $this->privateKey = $privateKey;
        $this->keyAlgorithm = $algorithmType;
    }

    public function setPublicKey($publicKey)
    {
        $this->publicKey = $publicKey;
    }

    public function getPublicKey(DOMNode $dom = null)
    {
        if ($dom) {
            $this->setPublicKeyFromNode($dom);
        }

        return $this->publicKey;
    }

    public function getKeyAlgorithm()
    {
        return $this->keyAlgorithm;
    }

    public function setDigestAlgorithm($algorithmType = self::SHA1)
    {
        $this->digestAlgorithm = $algorithmType;
    }

    public function setCanonicalMethod($methodType = self::XML_C14N)
    {
        $this->canonicalMethod = $methodType;
    }

    public function addTransform($transformType)
    {
        $this->transforms[] = $transformType;
    }

    public function sign(DOMDocument $data)
    {
        if (null === $this->privateKey) {
            throw new RuntimeException(
                'Missing private key. Use setPrivateKey to set one.'
            );
        }

        $objKey = new XMLSecurityKey(
            $this->keyAlgorithm,
            [
                 'type' => 'private',
            ]
        );
        $objKey->loadKey($this->privateKey);

        $objXMLSecDSig = $this->createXmlSecurityDSig();
        $objXMLSecDSig->setCanonicalMethod($this->canonicalMethod);
        $objXMLSecDSig->addReference($data, $this->digestAlgorithm, $this->transforms, ['force_uri' => true]);
        $objXMLSecDSig->sign($objKey, $data->documentElement);

        /* Add associated public key */
        if ($this->getPublicKey()) {
            $objXMLSecDSig->add509Cert($this->getPublicKey());
        }
    }

    public function verify(DOMDocument $data)
    {
        $objKey = null;
        $objXMLSecDSig = $this->createXmlSecurityDSig();
        $objDSig = $objXMLSecDSig->locateSignature($data);
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
            $this->publicKey = $objKey->getX509Certificate();
            $this->keyAlgorithm = $objKey->getAlgorith();
        }

        if (!$objKey) {
            $objKey = new XMLSecurityKey(
                $this->keyAlgorithm,
                [
                     'type' => 'public',
                ]
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
        } catch (\Exception $e) {
            return false;
        }

        return true;
    }

    /**
     * Create the XMLSecurityDSig class.
     *
     * @return XMLSecurityDSig
     */
    protected function createXmlSecurityDSig()
    {
        return new XMLSecurityDSig();
    }

    /**
     * Try to extract the public key from DOM node.
     *
     * Sets publicKey and keyAlgorithm properties if success.
     *
     * @see publicKey
     * @see keyAlgorithm
     *
     * @param DOMNode $dom
     *
     * @return bool `true` If public key was extracted or `false` if cannot be possible
     */
    protected function setPublicKeyFromNode(DOMNode $dom)
    {
        // try to get the public key from the certificate
        $objXMLSecDSig = $this->createXmlSecurityDSig();
        $objDSig = $objXMLSecDSig->locateSignature($dom);
        if (!$objDSig) {
            return false;
        }

        $objKey = $objXMLSecDSig->locateKey();
        if (!$objKey) {
            return false;
        }

        XMLSecEnc::staticLocateKeyInfo($objKey, $objDSig);
        $this->publicKey = $objKey->getX509Certificate();
        $this->keyAlgorithm = $objKey->getAlgorith();

        return true;
    }
}
