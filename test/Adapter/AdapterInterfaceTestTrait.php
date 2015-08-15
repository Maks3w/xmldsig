<?php

namespace FR3D\XmlDSigTest\Adapter;

use DOMDocument;
use DOMXPath;
use FR3D\XmlDSig\Adapter\AdapterInterface;
use PHPUnit_Framework_Assert as Assert;
use RuntimeException;

/**
 * Common test for all XmlDSig adapters.
 */
trait AdapterInterfaceTestTrait
{
    public function testGetPublicKeyFromSetter()
    {
        $adapter = $this->getAdapter();
        $publicKey = $this->getPublicKey();
        Assert::assertNotEquals($publicKey, $adapter->getPublicKey());

        $adapter->setPublicKey($publicKey);
        Assert::assertEquals($publicKey, $adapter->getPublicKey());
    }

    public function testGetPublicKeyFromNode()
    {
        $adapter = $this->getAdapter();
        $publicKey = $this->getPublicKey();
        Assert::assertNotEquals($publicKey, $adapter->getPublicKey());

        $data = new DOMDocument();
        $data->load(__DIR__ . '/_files/basic-doc-signed.xml');
        Assert::assertEquals($publicKey, $adapter->getPublicKey($data));
    }

    public function testSignWithoutPrivateKeys()
    {
        $adapter = $this->getAdapter();
        try {
            $adapter->sign(new DOMDocument());
        } catch (RuntimeException $e) {
            Assert::assertEquals('Missing private key. Use setPrivateKey to set one.', $e->getMessage());
        }
    }

    public function testSign()
    {
        $adapter = $this->getAdapter();
        $data = new DOMDocument();
        $data->load(__DIR__ . '/_files/basic-doc.xml');

        $adapter->setPrivateKey($this->getPrivateKey());
        $adapter->setPublicKey($this->getPublicKey());
        $adapter->addTransform(AdapterInterface::ENVELOPED);
        $adapter->setCanonicalMethod('http://www.w3.org/2001/10/xml-exc-c14n#');
        $adapter->sign($data);

        Assert::assertXmlStringEqualsXmlFile(
            __DIR__ . '/_files/basic-doc-signed.xml',
            $data->saveXML()
        );
    }

    public function testVerify()
    {
        $adapter = $this->getAdapter();
        $data = new DOMDocument();
        $data->load(__DIR__ . '/_files/basic-doc-signed.xml');

        Assert::assertTrue($adapter->verify($data));
    }

    public function testManipulatedData()
    {
        $adapter = $this->getAdapter();
        $data = new DOMDocument();
        $data->load(__DIR__ . '/_files/basic-doc-signed.xml');

        $xpath = new DOMXPath($data);
        $xpath->registerNamespace('s', 'urn:envelope');
        $xpath->query('//s:Value')->item(0)->nodeValue = 'wrong test';

        Assert::assertFalse($adapter->verify($data));
    }

    public function testManipulatedSignature()
    {
        $adapter = $this->getAdapter();
        $data = new DOMDocument();
        $data->load(__DIR__ . '/_files/basic-doc-signed.xml');

        $xpath = new DOMXPath($data);
        $xpath->registerNamespace('s', 'urn:envelope');
        $xpath->query('//s:Value')->item(0)->nodeValue = 'wrong test';

        Assert::assertFalse($adapter->verify($data));
    }

    /**
     * @return AdapterInterface
     */
    abstract protected function getAdapter();

    /**
     * @return string
     */
    protected function getPrivateKey()
    {
        return file_get_contents(__DIR__ . '/../_files/privkey.pem');
    }

    /**
     * @return string
     */
    protected function getPublicKey()
    {
        return file_get_contents(__DIR__ . '/../_files/pubkey.pem');
    }
}
