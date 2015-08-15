<?php

namespace FR3D\XmlDSigTest\Adapter;

use FR3D\XmlDSig\Adapter\XmlseclibsAdapter;
use PHPUnit_Framework_TestCase as TestCase;

/**
 * Test suite for Xmlseclibs adapter.
 *
 * @requires extension openssl
 */
class XmlseclibsAdapterTest extends TestCase
{
    use AdapterInterfaceTestTrait;

    protected function getAdapter()
    {
        return new XmlseclibsAdapter();
    }
}
