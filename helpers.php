<?php

use \Illuminate\Container\Container;

if (! function_exists('app')) {
    /**
     * Get the available container instance.
     *
     * @param  string  $make
     * @param  array   $parameters
     * @return mixed|\Illuminate\Foundation\Application
     */
    function app($make = null, $parameters = [])
    {
        if (is_null($make)) {
            return Container::getInstance();
        }

        return Container::getInstance()->make($make, $parameters);
    }
}


if (!function_exists('dd')) {
    /**
     * @param mixed ...$args
     */
    function dd(...$args)
    {
        foreach ($args as $v) {
            var_dump($v);
        }
        die;
    }
}