<?php

namespace FR3D\XmlDSigTest\Adapter;

use DOMDocument;
use DOMXPath;
use FR3D\XmlDSig\Adapter\AdapterInterface;

/**
 * Common test for all XmlDSig adapters
 */
class CommonTestCase extends \PHPUnit_Framework_TestCase
{
    /**
     * @var AdapterInterface
     */
    protected $adapter;

    /**
     * @var string Path to private key
     */
    protected $privateKey = '../_files/privkey.pem';

    /**
     * @var string Path to public key
     */
    protected $publicKey = '../_files/pubkey.pem';

    public function testGetPublicKeyFromSetter()
    {
        $publicKey = $this->getPublicKey();
        $this->assertNotEquals($publicKey, $this->adapter->getPublicKey());

        $this->adapter->setPublicKey($publicKey);
        $this->assertEquals($publicKey, $this->adapter->getPublicKey());
    }

    public function testGetPublicKeyFromPrivateKey()
    {
        $publicKey = $this->getPublicKey();
        $this->assertNotEquals($publicKey, $this->adapter->getPublicKey());

        $this->adapter->setPrivateKey($this->getPrivateKey());
        $this->assertEquals($publicKey, $this->adapter->getPublicKey());
    }

    public function testGetPublicKeyFromNode()
    {
        $publicKey = $this->getPublicKey();
        $this->assertNotEquals($publicKey, $this->adapter->getPublicKey());

        $data = new DOMDocument();
        $data->load(__DIR__ . '/_files/basic-doc-signed.xml');
        $this->assertEquals($publicKey, $this->adapter->getPublicKey($data));
    }

    public function testSignWithoutPrivateKeys()
    {
        $this->setExpectedException(
            'RuntimeException',
            'Missing private key. Use setPrivateKey to set one.'
        );
        $this->adapter->sign(new DOMDocument());
    }

    public function testSign()
    {
        $data = new DOMDocument();
        $data->load(__DIR__ . '/_files/basic-doc.xml');

        $this->adapter
            ->setPrivateKey($this->getPrivateKey())
            ->setPublicKey($this->getPublicKey())
            ->addTransform(AdapterInterface::ENVELOPED)
            ->setCanonicalMethod('http://www.w3.org/2001/10/xml-exc-c14n#')
            ->sign($data);

        $this->assertXmlStringEqualsXmlFile(
            __DIR__ . '/_files/basic-doc-signed.xml',
            $data->saveXML()
        );
    }

    public function testVerify()
    {
        $data = new DOMDocument();
        $data->load(__DIR__ . '/_files/basic-doc-signed.xml');

        $this->assertTrue($this->adapter->verify($data));
    }

    public function testManipulatedData()
    {
        $data = new DOMDocument();
        $data->load(__DIR__ . '/_files/basic-doc-signed.xml');

        $xpath = new DOMXPath($data);
        $xpath->registerNamespace('s', 'urn:envelope');
        $xpath->query('//s:Value')->item(0)->nodeValue = 'wrong test';

        $this->assertFalse($this->adapter->verify($data));
    }

    public function testManipulatedSignature()
    {
        $data = new DOMDocument();
        $data->load(__DIR__ . '/_files/basic-doc-signed.xml');

        $xpath = new DOMXPath($data);
        $xpath->registerNamespace('s', 'urn:envelope');
        $xpath->query('//s:Value')->item(0)->nodeValue = 'wrong test';

        $this->assertFalse($this->adapter->verify($data));
    }

    protected function getPrivateKey()
    {
        return file_get_contents(__DIR__ . DIRECTORY_SEPARATOR . $this->privateKey);
    }

    protected function getPublicKey()
    {
        return file_get_contents(__DIR__ . DIRECTORY_SEPARATOR . $this->publicKey);
    }
}
