<?php

namespace FR3D\XmlDSigTest\Adapter;

use DOMDocument;
use DOMXPath;
use XMLSecurityDSig;
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
            'Missing private key. Use setPrivateKey or setCertificate to set one.'
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

    public function testVerifyNotMessingWithDOMDocument(){

        $data = new DOMDocument();
        $data->loadXML('<?xml version="1.0" encoding="UTF-8"?><root><node>hello world!</node></root>');

        $this->adapter
            ->setPrivateKey($this->getPrivateKey())
            ->setPublicKey($this->getPublicKey())
            ->addTransform(AdapterInterface::ENVELOPED)
            ->setCanonicalMethod(AdapterInterface::XML_C14N)
            ->sign( $data );

        $this->adapter->verify( $data );

        $xpath = new DOMXPath($data);
        $xpath->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);
        $this->assertEquals( 1, $xpath->query('//ds:SignedInfo')->length );
    }

    public function testNodeSigningWithoutId(){

        $data = new DOMDocument();
        $data->loadXML('<?xml version="1.0" encoding="UTF-8"?><root><node>hello world!</node></root>');

        $xpath = new DOMXPath($data);

        $this->assertEquals( 0, $xpath->query('//node[@Id]')->length );

        $this->adapter
            ->setPrivateKey($this->getPrivateKey())
            ->setPublicKey($this->getPublicKey())
            ->addTransform(AdapterInterface::ENVELOPED)
            ->setCanonicalMethod(AdapterInterface::XML_C14N)
            ->sign( $xpath->query('//node')->item(0) );

        $this->assertEquals( 1, $xpath->query('//node[@Id]')->length );

    }

    public function testNodeSigningWithId(){

        $data = new DOMDocument();
        $data->loadXML('<?xml version="1.0" encoding="UTF-8"?><root><node Id="thisismyidthatshouldnotbechanged">hello world!</node></root>');

        $xpath = new DOMXPath($data);

        $this->assertEquals( 'thisismyidthatshouldnotbechanged', $xpath->query('//node[@Id]')->item(0)->getAttribute('Id') );

        $this->adapter
            ->setPrivateKey($this->getPrivateKey())
            ->setPublicKey($this->getPublicKey())
            ->addTransform(AdapterInterface::ENVELOPED)
            ->setCanonicalMethod(AdapterInterface::XML_C14N)
            ->sign( $xpath->query('//node')->item(0) );

        $this->assertEquals( 'thisismyidthatshouldnotbechanged', $xpath->query('//node[@Id]')->item(0)->getAttribute('Id') );

        $this->assertTrue( $this->adapter->verify( $data ) );
    }

    public function testSetCertificatePem(){

        $this->adapter->setCertificate( __DIR__ . '/../_files/cert.pem' );

        $this->assertEquals( $this->adapter->getPublicKey(), file_get_contents( __DIR__ . '/../_files/cert-pubkey.pem' ) );
        $this->assertEquals( $this->adapter->getPrivateKey(), file_get_contents( __DIR__ . '/../_files/cert-privkey.pem' ) );
    }

    public function testSetCertificatePemFromString(){

        $this->adapter->setCertificate( file_get_contents( __DIR__ . '/../_files/cert.pem' ) );

        $this->assertEquals( $this->adapter->getPublicKey(), file_get_contents( __DIR__ . '/../_files/cert-pubkey.pem' ) );
        $this->assertEquals( $this->adapter->getPrivateKey(), file_get_contents( __DIR__ . '/../_files/cert-privkey.pem' ) );
    }

    public function testSetCertificatePfx(){

        $this->adapter->setCertificate( __DIR__ . '/../_files/cert.pfx', "1234" );

        $this->assertEquals( $this->adapter->getPublicKey(), file_get_contents( __DIR__ . '/../_files/cert-pubkey.pem' ) );
        $this->assertEquals( $this->adapter->getPrivateKey(), file_get_contents( __DIR__ . '/../_files/cert-privkey.pem' ) );
    }

    public function testSetCertificatePfxFromString(){

        $this->adapter->setCertificate( file_get_contents( __DIR__ . '/../_files/cert.pfx' ), "1234" );

        $this->assertEquals( $this->adapter->getPublicKey(), file_get_contents( __DIR__ . '/../_files/cert-pubkey.pem' ) );
        $this->assertEquals( $this->adapter->getPrivateKey(), file_get_contents( __DIR__ . '/../_files/cert-privkey.pem' ) );
    }

    public function testSetCertificatePfxNoPassoword(){

        $this->setExpectedException(
            'RuntimeException',
            'Unable to load certificate as PKCS12 file. Please check the certificate and password provided'
        );

        $this->adapter->setCertificate( __DIR__ . '/../_files/cert.pfx');

    }

    public function testSetCertificatePfxIncorrectPassoword(){

        $this->setExpectedException(
            'RuntimeException',
            'Unable to load certificate as PKCS12 file. Please check the certificate and password provided'
        );

        $this->adapter->setCertificate( file_get_contents(__DIR__ . '/../_files/cert.pfx') , 'abceded');

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
