<?php

namespace FR3D\XmlDSigTest\Soap;

use DOMDocument;
use FR3D\XmlDSig\Adapter\XmlseclibsAdapter;
use FR3D\XmlDSig\Soap\SoapClient;
use PHPUnit_Framework_TestCase as TestCase;

/**
 * Test suite for SoapClient.
 *
 * @requires extension soap
 */
class SoapClientTest extends TestCase
{
    /** @var SoapClient */
    protected $client;

    /** @var XmlseclibsAdapter */
    protected $xmlDSigAdapter;

    protected function setUp()
    {
        $this->xmlDSigAdapter = new XmlseclibsAdapter();
        $this->xmlDSigAdapter->setPrivateKey(file_get_contents(__DIR__ . '/../_files/privkey.pem'));
        $this->xmlDSigAdapter->setPublicKey(file_get_contents(__DIR__ . '/../_files/pubkey.pem'));
        $this->xmlDSigAdapter->addTransform(XmlseclibsAdapter::ENVELOPED);

        $this->client = new SoapClient(
            __DIR__ . '/_files/HelloWorld.wsdl',
            [
                'trace' => true,
                'exceptions' => false,
            ]
        );
        $this->client
            ->setDebugMode(true)
            ->setXmlDSigAdapter($this->xmlDSigAdapter);
    }

    public function testNormalSoapMessage()
    {
        $expected = '<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="urn:hello-world:1.0"><SOAP-ENV:Body><ns1:sayHello/></SOAP-ENV:Body></SOAP-ENV:Envelope>
';
        $this->client->setXmlDSigAdapter(null);
        try {
            $this->client->__call('sayHello', []);
        } catch (\Exception $e) {
            // Ignore
        }

        TestCase::assertEquals($expected, $this->client->__getLastRequest());
    }

    public function testSignSoapMessage()
    {
        $expected = '<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wns1="urn:hello-world:1.0"><SOAP-ENV:Body><wns1:sayHello xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wns1="urn:hello-world:1.0"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"></ds:CanonicalizationMethod>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></ds:SignatureMethod>
  <ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod><ds:DigestValue>QG06QpnB5HBcTxoj9sP4lwgr5fs=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>KbCRtraU6vpqojaPm2ArAsWR/2xBqP0J7nplkXUmQpQkoFWiawnIW8pHVp0RWddlyP9TYBT0f10hN75oxkTvtmHQrxwAC6rjngr+872cHLKnpSZlfUVzAd2QSYR6Gbgk/lSKzZInwe9IEhexQjQ1qDldqu62D8imAyllCtg8bCXLfyHFjixLk19IkJoDjDula1PMLPLpEDuSy934jHSiy3PdA1HwNdlw/1oAqnlcrIA152ywAuPdaFMGgV5JqRPBH5y/wHQ0+4g1VlF7pttigFQcrXLEEZUrz2hdkVb71mZNZFlKIZ70Mdh9WjdgmsMpf1d41w9oOKtrzv46roMmIA==</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIEVDCCAzygAwIBAgIJAPTrkMJbCOr1MA0GCSqGSIb3DQEBBQUAMHkxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIEwVNYWluZTESMBAGA1UEBxMJTGltaW5ndG9uMR8wHQYDVQQKExZ4bWxzZWNsaWJzLnBocCBMaWJyYXJ5MSUwIwYDVQQDExx4bWxzZWNsaWJzL3d3dy5jZGF0YXpvbmUub3JnMB4XDTA4MDcwNzIwMjIzMVoXDTE4MDcwNTIwMjIzMVoweTELMAkGA1UEBhMCVVMxDjAMBgNVBAgTBU1haW5lMRIwEAYDVQQHEwlMaW1pbmd0b24xHzAdBgNVBAoTFnhtbHNlY2xpYnMucGhwIExpYnJhcnkxJTAjBgNVBAMTHHhtbHNlY2xpYnMvd3d3LmNkYXRhem9uZS5vcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDttdMyM5ISVD1Uz+BHAPrxVJ6N1eZonfg3DMvZVT0Zy64+qcXj8zuHC6lolDsfGnD8LUttraQ7qCL+bHKps+hjAhCRdx5Wcn4iDrlFpxFL7INnr6vekzsCQ45BPUrvksF9FKa7yX4iSDButmPfoT14gPnIuSe8Y5UeGe6Lk6sF0WgHyL+JmxOu377Kuhah2pXZ1+z7V4JIlNgemJtKlqrvgGeuE9TagfGHUL9BuZK5fUx/RSDUjqxUeKU3fft9fGIAZl0dduitC2Otv4dr1gxLrUmI+ZZ75FmtfKQT7SmS92QVI2B5WAPlL1bnbvhkZiyw7nFE+Q/wGJ2myE4RIFjdAgMBAAGjgd4wgdswHQYDVR0OBBYEFEC5iG0uGXLpQG/zMj/4TuDWfTpHMIGrBgNVHSMEgaMwgaCAFEC5iG0uGXLpQG/zMj/4TuDWfTpHoX2kezB5MQswCQYDVQQGEwJVUzEOMAwGA1UECBMFTWFpbmUxEjAQBgNVBAcTCUxpbWluZ3RvbjEfMB0GA1UEChMWeG1sc2VjbGlicy5waHAgTGlicmFyeTElMCMGA1UEAxMceG1sc2VjbGlicy93d3cuY2RhdGF6b25lLm9yZ4IJAPTrkMJbCOr1MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBACmSKrte07VrGB8dtrN5mrt28ILickQjguu46h6vChgQ4YfIAoA1KWNsZJUuuIzTDjE5xz2hsW37CI0yrNesv2ho2hhP+fIaxCGmcwLYXL80UaPRglYk5+wPWFOt3QFAVoEgwjLX9+y+c2Gu7xLgHAFZVRjQ5hhKT0Nj3vhnt0k8LcognNl1wKuWda7VL4tODp/2IOXr5o5v/OL3UesGfeWfvr8LVmMc5f7/vLAu1+2Yk+/C9/EZyf3BDZQ4z8ae/iwqprCTUIEjhUDcq4+0YN2EIw6suGE2FtWlsIywNErmoOhdrmntU61n3nFCQBi7QDUnZrAFrl4/bmk3eRJ00nE=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></wns1:sayHello></SOAP-ENV:Body></SOAP-ENV:Envelope>
';
        try {
            $this->client->__call('sayHello', []);
        } catch (\Exception $e) {
            // Ignore
        }

        $lastRequest = $this->client->__getLastRequest();
        TestCase::assertEquals($expected, $lastRequest);

        $dom = new DOMDocument();
        $dom->loadXML($lastRequest);

        $body = $dom
            ->getElementsByTagNameNS($dom->documentElement->namespaceURI, 'Body')
            ->item(0);
        $firstElement = $body->firstChild;

        // Check Signature
        $xmlDSigAdapter = $this->client->getXmlDSigAdapter();
        $newData = new DOMDocument();
        $newData->loadXML($firstElement->C14N());
        TestCase::assertTrue($xmlDSigAdapter->verify($newData));
    }
}
