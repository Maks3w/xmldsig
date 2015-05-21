<?php

return Symfony\CS\Config\Config::create()
    ->fixers(
        array(
            '-concat_without_spaces',
            '-empty_return',
            '-phpdoc_no_empty_return',
            '-phpdoc_params',
            '-phpdoc_to_comment',
            '-single_array_no_trailing_comma',
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
            ->in('src')
            ->in('test')
    )
    ;
