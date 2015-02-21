<?php

require '../vendor/autoload.php';

use FR3D\XmlDSig\Adapter\AdapterInterface;
use FR3D\XmlDSig\Adapter\XmlseclibsAdapter;
use \DOMDocument;

$data = new DOMDocument();
$data->loadXML('<?xml version="1.0" encoding="UTF-8"?><root><node>hello world!</node></root>');

$adapter = new XmlseclibsAdapter();

$adapter
    ->setCertificate( __DIR__.'/../test/FR3D/XmlDSigTest/_files/cert.pem' )
    // ->setCertificate( __DIR__.'/../test/FR3D/XmlDSigTest/_files/cert.pfx', '1234' ) // or this
    ->addTransform( AdapterInterface::ENVELOPED )
    ->addTransform( AdapterInterface::XML_C14N )
    ->setCanonicalMethod( AdapterInterface::XML_C14N )
    ->sign( $data );

if( !$adapter->verify($data) ){
    throw new Exception("Impossible to verify signature!");
}

header("Content-Type: application/xml");
die($data->saveXML());