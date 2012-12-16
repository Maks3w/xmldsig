<?php

namespace FR3D\XmlDSigTest\Adapter;

use DOMDocument;
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
            ->setPrivateKey(file_get_contents(__DIR__ . '/' . $this->privateKey))
            ->setPublicKey(file_get_contents(__DIR__ . '/' . $this->publicKey))
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
}
