<?php

namespace FR3D\XmlDSigTest\Adapter;

use FR3D\XmlDSig\Adapter\XmlseclibsAdapter;

/**
 * Test suite for Xmlseclibs adapter.
 *
 * @requires extension openssl
 */
class XmlseclibsAdapterTest extends CommonTestCase
{
    protected function setUp()
    {
        $this->adapter = new XmlseclibsAdapter();
    }

    public function testGetPublicKeyFromPrivateKey()
    {
        $this->markTestIncomplete('PHP OpenSSL extension does not extract public key from private key');
    }
}
