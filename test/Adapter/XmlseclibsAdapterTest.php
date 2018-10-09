<?php

declare(strict_types=1);

namespace FR3D\XmlDSig\Adapter;

use PHPUnit\Framework\TestCase;

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
