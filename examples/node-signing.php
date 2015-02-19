<?php

require '../vendor/autoload.php';

use FR3D\XmlDSig\Adapter\AdapterInterface;
use FR3D\XmlDSig\Adapter\XmlseclibsAdapter;
use \DOMDocument;

$data = new DOMDocument();
$data->loadXML('<?xml version="1.0" encoding="UTF-8"?><root><node Id="NFe531502">hello world!</node><node Id="NFe531503">Other hello world!</node></root>');

$xpath = new DOMXPath($data);

$adapter = new XmlseclibsAdapter();

$adapter
    ->setCertificate( __DIR__.'/../test/FR3D/XmlDSigTest/_files/cert.pem' )
    ->addTransform( AdapterInterface::ENVELOPED )
    ->addTransform( AdapterInterface::XML_C14N )
    ->setCanonicalMethod( AdapterInterface::XML_C14N );

$adapter->sign( $xpath->query('//node[@Id="NFe531502"]')->item(0) );
$adapter->sign( $xpath->query('//node[@Id="NFe531503"]')->item(0) );

if( !$adapter->verify($data) ){
    throw new Exception("Impossible to verify signature!");
}

header("Content-Type: application/xml");
die($data->saveXML());