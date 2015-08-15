<?php

namespace FR3D\XmlDSig\Soap;

use DOMDocument;
use FR3D\XmlDSig\Adapter\AdapterInterface;

/**
 * SOAP client with XmlDSig support.
 *
 * If not XmlDSig adapter is set then works like the standard SoapClient
 */
class SoapClient extends \SoapClient
{
    /** @var bool */
    protected $debugMode = false;

    /** @var string */
    protected $lastRequest;

    /** @var AdapterInterface|null */
    protected $xmlDSigAdapter;

    /**
     * @param bool $enable
     *
     * @return self provides a fluent interface
     */
    public function setDebugMode($enable)
    {
        $this->debugMode = $enable;

        return $this;
    }

    /**
     * @return string|null
     */
    public function __getLastRequest()
    {
        if (!$this->xmlDSigAdapter || !$this->debugMode) {
            return parent::__getLastRequest();
        }

        return $this->lastRequest;
    }

    /**
     * @param AdapterInterface|null $xmlDSigAdapter XmlDSig adapter or null for
     *                                              disable it
     *
     * @return self provides a fluent interface
     */
    public function setXmlDSigAdapter(AdapterInterface $xmlDSigAdapter = null)
    {
        $this->xmlDSigAdapter = $xmlDSigAdapter;

        return $this;
    }

    /**
     * @return AdapterInterface|null
     */
    public function getXmlDSigAdapter()
    {
        return $this->xmlDSigAdapter;
    }

    public function __doRequest($request, $location, $action, $version, $one_way = 0)
    {
        if (!$this->xmlDSigAdapter) {
            return parent::__doRequest($request, $location, $action, $version, $one_way);
        }

        // Some WS providers use NS1 for his own use and conflicts with the signature calc
        $request = str_replace([':ns1', 'ns1:'], [':wns1', 'wns1:'], $request);

        $dom = new DOMDocument();
        $dom->loadXML($request);

        $body = $dom
            ->getElementsByTagNameNS($dom->documentElement->namespaceURI, 'Body')
            ->item(0);

        $firstElement = $body->firstChild;
        /* Not necessary since ext/Soap don't add Text nodes between Elements
        foreach($body->childNodes as $node){
            if ($node->nodeType === XML_ELEMENT_NODE) {
                $firstElement = $node;
                break;
            }
        }
        */

        $newData = new DOMDocument();
        $newData->loadXML($firstElement->C14N());

        $this->xmlDSigAdapter->sign($newData);

        /* DOM mode for add the signed node
        $firstElement->appendChild($dom->importNode($newData->firstChild->lastChild, true));
        $request = $dom->saveXML();
        */

        /* Compatibility mode for add signed node without lost namespaces declaration */
        $newBody = '<SOAP-ENV:Body>' . $newData->C14N() . '</SOAP-ENV:Body>';
        $request = preg_replace('#<SOAP-ENV:Body>.*</SOAP-ENV:Body>#', $newBody, $request);

        if ($this->debugMode) {
            $this->lastRequest = $request;
        }

        return parent::__doRequest($request, $location, $action, $version, $one_way);
    }
}
