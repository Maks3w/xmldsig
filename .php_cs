<?php

return Symfony\CS\Config\Config::create()
    ->fixers(
        array(
            '-phpdoc_no_empty_return',
            'concat_with_spaces',
            'ereg_to_preg',
            'multiline_spaces_before_semicolon',
            'ordered_use',
            'strict',
            'strict_param',
        )
    )
    ->finder(
        Symfony\CS\Finder\DefaultFinder::create()
            ->notPath('_files')
            ->in(__DIR__)
    )
    ;
